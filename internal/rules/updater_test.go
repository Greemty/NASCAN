package rules

import (
	"testing"
)

func TestBundleAssetName(t *testing.T) {
	tests := []struct {
		bundle   Bundle
		expected string
	}{
		{BundleCore, "yara-forge-rules-core.zip"},
		{BundleExtended, "yara-forge-rules-extended.zip"},
		{BundleFull, "yara-forge-rules-full.zip"},
	}

	for _, tt := range tests {
		t.Run(string(tt.bundle), func(t *testing.T) {
			if got := tt.bundle.assetName(); got != tt.expected {
				t.Errorf("assetName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestBundleYarName(t *testing.T) {
	tests := []struct {
		bundle   Bundle
		expected string
	}{
		{BundleCore, "yara-rules-core.yar"},
		{BundleExtended, "yara-rules-extended.yar"},
		{BundleFull, "yara-rules-full.yar"},
	}

	for _, tt := range tests {
		t.Run(string(tt.bundle), func(t *testing.T) {
			if got := tt.bundle.yarName(); got != tt.expected {
				t.Errorf("yarName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestNewUpdater_UnknownBundleFallback(t *testing.T) {
	logger := newTestLogger(t)
	u := NewUpdater("/tmp", "invalid-bundle", logger)
	if u.bundle != BundleCore {
		t.Errorf("expected fallback to BundleCore, got %q", u.bundle)
	}
}

func TestNewUpdater_ValidBundle(t *testing.T) {
	logger := newTestLogger(t)
	u := NewUpdater("/tmp", "extended", logger)
	if u.bundle != BundleExtended {
		t.Errorf("expected BundleExtended, got %q", u.bundle)
	}
}

func TestRulesPath(t *testing.T) {
	logger := newTestLogger(t)
	u := NewUpdater("/var/lib/nascan/rules", "core", logger)
	expected := "/var/lib/nascan/rules/yara-rules-core.yar"
	if got := u.RulesPath(); got != expected {
		t.Errorf("RulesPath() = %q, want %q", got, expected)
	}
}
