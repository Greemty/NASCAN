package quarantine

import (
	"os"
	"path/filepath"
	"testing"

	"time"

	"github.com/greemty/nascan/internal/scanner"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func newTestQuarantine(t *testing.T) (*Quarantine, string) {
	t.Helper()
	dir := t.TempDir()
	logger, _ := zap.NewDevelopment()
	reg := prometheus.NewRegistry()
	q, err := New(dir, logger, reg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return q, dir
}

func TestQuarantine_FileIsMoved(t *testing.T) {
	q, qDir := newTestQuarantine(t)

	// Crée un fichier source temporaire
	src := filepath.Join(t.TempDir(), "malware.exe")
	if err := os.WriteFile(src, []byte("malicious content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	alert := scanner.Alert{
		Path:      src,
		RuleName:  "Test_Rule",
		Timestamp: time.Now(),
	}

	if err := q.Move(alert); err != nil {
		t.Fatalf("Move: %v", err)
	}

	// Le fichier source ne doit plus exister
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("source file should have been moved")
	}

	// Le fichier doit être en quarantaine
	entries, err := os.ReadDir(qDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 file in quarantine, got %d", len(entries))
	}
}

func TestQuarantine_FilePermissions(t *testing.T) {
	q, qDir := newTestQuarantine(t)

	src := filepath.Join(t.TempDir(), "malware.exe")
	os.WriteFile(src, []byte("evil"), 0o644)

	alert := scanner.Alert{Path: src, RuleName: "Test_Rule", Timestamp: time.Now()}
	q.Move(alert)

	entries, _ := os.ReadDir(qDir)
	if len(entries) == 0 {
		t.Fatal("no file in quarantine")
	}

	info, err := os.Stat(filepath.Join(qDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	if info.Mode().Perm() != 0o000 {
		t.Errorf("expected permissions 0000, got %o", info.Mode().Perm())
	}
}

func TestQuarantine_DirCreatedIfMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does", "not", "exist")
	logger, _ := zap.NewDevelopment()
	reg := prometheus.NewRegistry()

	_, err := New(dir, logger, reg)
	if err != nil {
		t.Errorf("expected dir to be created, got error: %v", err)
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("quarantine dir was not created")
	}
}
