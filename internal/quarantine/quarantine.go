package quarantine

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/greemty/nascan/internal/scanner"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type Quarantine struct {
	dir    string
	logger *zap.Logger
	total  *prometheus.CounterVec
}

func New(dir string, logger *zap.Logger, reg prometheus.Registerer) (*Quarantine, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating quarantine dir: %w", err)
	}

	total := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nascan_quarantine_total",
		Help: "Fichiers mis en quarantaine par règle YARA",
	}, []string{"rule"})
	reg.MustRegister(total)

	return &Quarantine{dir: dir, logger: logger, total: total}, nil
}

func (q *Quarantine) Move(alert scanner.Alert) error {
	filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(alert.Path))
	dest := filepath.Join(q.dir, filename)

	if err := os.Rename(alert.Path, dest); err != nil {
		return fmt.Errorf("moving to quarantine: %w", err)
	}

	if err := os.Chmod(dest, 0o000); err != nil {
		q.logger.Warn("chmod quarantine failed", zap.String("file", dest), zap.Error(err))
	}

	q.total.WithLabelValues(alert.RuleName).Inc()

	q.logger.Warn("fichier mis en quarantaine",
		zap.String("original", alert.Path),
		zap.String("quarantine", dest),
		zap.String("rule", alert.RuleName),
	)

	return nil
}
