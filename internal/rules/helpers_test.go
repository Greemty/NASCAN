package rules

import (
	"testing"

	"go.uber.org/zap"
)

func newTestLogger(t *testing.T) *zap.Logger {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return logger
}
