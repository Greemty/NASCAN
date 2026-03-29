package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	yara "github.com/hillu/go-yara/v4"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type Alert struct {
	Path      string
	RuleName  string
	Namespace string
	Tags      []string
	Timestamp time.Time
}

type Scanner struct {
	watchPath string
	rules     *yara.Rules
	alerts    chan<- Alert
	logger    *zap.Logger

	filesScanned prometheus.Counter
	yaraHits     *prometheus.CounterVec
	scanDuration prometheus.Histogram
}

func New(watchPath, rulesPath string, alerts chan<- Alert, logger *zap.Logger, reg prometheus.Registerer) (*Scanner, error) {
	rules, err := compileRules(rulesPath)
	if err != nil {
		return nil, err
	}

	filesScanned := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nascan_files_scanned_total",
		Help: "Nombre total de fichiers scannés",
	})
	yaraHits := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nascan_yara_hits_total",
		Help: "Nombre de matches YARA par règle et namespace",
	}, []string{"rule", "namespace"})
	scanDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "nascan_scan_duration_seconds",
		Help:    "Durée de scan d'un fichier",
		Buckets: prometheus.DefBuckets,
	})

	reg.MustRegister(filesScanned, yaraHits, scanDuration)

	return &Scanner{
		watchPath:    watchPath,
		rules:        rules,
		alerts:       alerts,
		logger:       logger,
		filesScanned: filesScanned,
		yaraHits:     yaraHits,
		scanDuration: scanDuration,
	}, nil
}

func (s *Scanner) Run(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	if err := s.watchRecursive(watcher, s.watchPath); err != nil {
		return err
	}

	s.logger.Info("scanner démarré", zap.String("path", s.watchPath))

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			s.handleEvent(watcher, event)
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			s.logger.Warn("erreur watcher", zap.Error(err))
		}
	}
}

func (s *Scanner) ScanExisting(ctx context.Context) error {
	s.logger.Info("scan des fichiers existants", zap.String("path", s.watchPath))

	return filepath.WalkDir(s.watchPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			s.logger.Warn("erreur walk", zap.String("path", path), zap.Error(err))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("scan interrompu")
		default:
			go s.scanFile(path)
		}
		return nil
	})
}

func (s *Scanner) handleEvent(watcher *fsnotify.Watcher, event fsnotify.Event) {
	if event.Has(fsnotify.Create) {
		info, err := os.Stat(event.Name)
		if err == nil && info.IsDir() {
			_ = s.watchRecursive(watcher, event.Name)
			return
		}
	}
	if event.Has(fsnotify.Create) {
		go s.scanFile(event.Name)
	}
}

func (s *Scanner) scanFile(path string) {
	start := time.Now()
	defer func() {
		s.scanDuration.Observe(time.Since(start).Seconds())
		s.filesScanned.Inc()
	}()

	var matches yara.MatchRules
	if err := s.rules.ScanFile(path, 0, 30*time.Second, &matches); err != nil {
		s.logger.Debug("erreur scan", zap.String("file", path), zap.Error(err))
		return
	}

	for _, m := range matches {
		s.logger.Warn("match YARA",
			zap.String("file", path),
			zap.String("rule", m.Rule),
			zap.String("namespace", m.Namespace),
			zap.Strings("tags", m.Tags),
		)
		s.yaraHits.WithLabelValues(m.Rule, m.Namespace).Inc()
		s.alerts <- Alert{
			Path:      path,
			RuleName:  m.Rule,
			Namespace: m.Namespace,
			Tags:      m.Tags,
			Timestamp: time.Now(),
		}
	}
}

func (s *Scanner) watchRecursive(watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			s.logger.Warn("impossible de surveiller", zap.String("path", path), zap.Error(err))
			return nil
		}
		if d.IsDir() {
			if err := watcher.Add(path); err != nil {
				s.logger.Warn("watcher.Add échoué", zap.String("path", path), zap.Error(err))
			}
		}
		return nil
	})
}

func compileRules(rulesPath string) (*yara.Rules, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(rulesPath)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return addFile(compiler, rulesPath)
	}

	entries, err := os.ReadDir(rulesPath)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yar" {
			continue
		}
		if _, err := addFile(compiler, filepath.Join(rulesPath, entry.Name())); err != nil {
			return nil, err
		}
	}

	return compiler.GetRules()
}

func addFile(compiler *yara.Compiler, path string) (*yara.Rules, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := compiler.AddFile(f, filepath.Base(path)); err != nil {
		return nil, err
	}
	return compiler.GetRules()
}
