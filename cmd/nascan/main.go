package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/greemty/nascan/internal/ebpf"
	"github.com/greemty/nascan/internal/metrics"
	"github.com/greemty/nascan/internal/quarantine"
	"github.com/greemty/nascan/internal/rules"
	"github.com/greemty/nascan/internal/scanner"
	"github.com/greemty/nascan/internal/threatintel"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const usage = `nascan - NAS security scanner

Usage:
  nascan [flags]        Start the daemon
  nascan update-rules   Download/update YARA-Forge rules and exit

Flags:
`

func main() {
	fs := flag.NewFlagSet("nascan", flag.ExitOnError)
	watchPath := fs.String("watch", "/mnt/nas", "Path to watch (e.g. NFS mount point)")
	bundle := fs.String("bundle", "core", "YARA-Forge bundle: core | extended | full")
	rulesDir := fs.String("rules-dir", "./rules-data", "Directory where YARA rules are stored")
	metricsAddr := fs.String("metrics", ":9100", "Prometheus metrics endpoint (empty to disable)")
	forceUpdate := fs.Bool("force-update", false, "Re-download rules even if already present")
	scanExisting := fs.Bool("scan-existing", false, "Scanner les fichiers déjà présents au démarrage")
	quarantineDir := fs.String("quarantine", "", "Dossier de quarantaine (vide = désactivé)")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}

	if len(os.Args) > 1 && os.Args[1] == "update-rules" {
		runUpdateRules(*rulesDir, *bundle)
		return
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, logger, &config{
		watchPath:     *watchPath,
		rulesDir:      *rulesDir,
		bundle:        *bundle,
		metricsAddr:   *metricsAddr,
		forceUpdate:   *forceUpdate,
		scanExisting:  *scanExisting,
		quarantineDir: *quarantineDir,
	}); err != nil {
		logger.Fatal("fatal error", zap.Error(err))
	}
}

type config struct {
	watchPath     string
	rulesDir      string
	bundle        string
	metricsAddr   string
	forceUpdate   bool
	scanExisting  bool
	quarantineDir string
}

func run(ctx context.Context, logger *zap.Logger, cfg *config) error {
	logger.Info("nascan starting",
		zap.String("watch", cfg.watchPath),
		zap.String("bundle", cfg.bundle),
		zap.String("metrics", cfg.metricsAddr),
	)

	// Rules
	updater := rules.NewUpdater(cfg.rulesDir, cfg.bundle, logger)
	if err := updater.EnsureRules(ctx, cfg.forceUpdate); err != nil {
		return fmt.Errorf("ensuring rules: %w", err)
	}

	// Threat intel — liste d'IPs C2 connues (Feodo Tracker)
	feed := threatintel.NewFeed(logger)
	if err := feed.Start(ctx); err != nil {
		return fmt.Errorf("threat intel: %w", err)
	}

	// Prometheus
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	// Scanner
	alerts := make(chan scanner.Alert, 256)
	sc, err := scanner.New(cfg.watchPath, updater.RulesPath(), alerts, logger, reg)
	if err != nil {
		return fmt.Errorf("init scanner: %w", err)
	}

	// eBPF
	netEvents := make(chan ebpf.NetworkEvent, 256)
	execEvents := make(chan ebpf.ExecEvent, 256)
	correlator := ebpf.NewCorrelator(logger, feed)
	probe := ebpf.NewProbe(netEvents, execEvents, logger)

	// Quarantaine
	var q *quarantine.Quarantine
	if cfg.quarantineDir != "" {
		q, err = quarantine.New(cfg.quarantineDir, logger)
		if err != nil {
			return fmt.Errorf("init quarantine: %w", err)
		}
	}

	// Consommateur d'alertes YARA — unique
	go func() {
		for alert := range alerts {
			logger.Warn("alerte",
				zap.String("file", alert.Path),
				zap.String("rule", alert.RuleName),
				zap.Strings("tags", alert.Tags),
			)
			correlator.AddAlert(alert)

			if q != nil {
				if err := q.Move(alert); err != nil {
					logger.Error("quarantine failed", zap.String("file", alert.Path), zap.Error(err))
				}
			}
		}
	}()

	// Correlator écoute les events réseau eBPF
	go func() {
		for ev := range netEvents {
			correlator.OnNetworkEvent(ev)
		}
	}()

	// Scanner (scan existants puis watch)
	go func() {
		if cfg.scanExisting {
			if err := sc.ScanExisting(ctx); err != nil {
				logger.Warn("scan existants interrompu", zap.Error(err))
			}
		}
		if err := sc.Run(ctx); err != nil {
			logger.Error("scanner error", zap.Error(err))
		}
	}()

	// Probe eBPF
	go func() {
		if err := probe.Run(ctx); err != nil {
			logger.Error("eBPF probe error", zap.Error(err))
		}
	}()

	// Metrics server
	if cfg.metricsAddr != "" {
		go func() {
			if err := metrics.Serve(ctx, cfg.metricsAddr, reg, logger); err != nil {
				logger.Error("metrics server error", zap.Error(err))
			}
		}()
	}

	<-ctx.Done()
	logger.Info("nascan stopped")
	return nil
}

func runUpdateRules(rulesDir, bundle string) {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	updater := rules.NewUpdater(rulesDir, bundle, logger)
	if err := updater.EnsureRules(context.Background(), true); err != nil {
		logger.Fatal("update-rules failed", zap.Error(err))
	}
}
