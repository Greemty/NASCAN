package quarantine

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/greemty/nascan/internal/scanner"
	"go.uber.org/zap"
)

type Quarantine struct {
	dir    string
	logger *zap.Logger
}

func New(dir string, logger *zap.Logger) (*Quarantine, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating quarantine dir: %w", err)
	}
	return &Quarantine{dir: dir, logger: logger}, nil
}

// Move déplace un fichier en quarantaine
func (q *Quarantine) Move(alert scanner.Alert) error {
	// Nom unique : timestamp + nom original
	filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(alert.Path))
	dest := filepath.Join(q.dir, filename)

	if err := os.Rename(alert.Path, dest); err != nil {
		return fmt.Errorf("moving to quarantine: %w", err)
	}

	// Permissions restrictives — plus personne ne peut lire le fichier
	if err := os.Chmod(dest, 0o000); err != nil {
		q.logger.Warn("chmod quarantine failed", zap.String("file", dest), zap.Error(err))
	}

	q.logger.Warn("fichier mis en quarantaine",
		zap.String("original", alert.Path),
		zap.String("quarantine", dest),
		zap.String("rule", alert.RuleName),
	)

	return nil
}
