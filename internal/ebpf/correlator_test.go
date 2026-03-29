package ebpf

import (
	"net"
	"testing"
	"time"

	"github.com/greemty/nascan/internal/scanner"
	"github.com/greemty/nascan/internal/threatintel"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func newTestCorrelator(t *testing.T, maliciousIPs ...string) *Correlator {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	feed := threatintel.NewFeed(logger)
	for _, ip := range maliciousIPs {
		feed.AddIP(ip)
	}
	reg := prometheus.NewRegistry()
	return NewCorrelator(logger, feed, reg)
}

func testAlert(path, rule string) scanner.Alert {
	return scanner.Alert{
		Path:      path,
		RuleName:  rule,
		Namespace: "test",
		Timestamp: time.Now(),
	}
}

func testNetEvent(ip string, port uint16) NetworkEvent {
	return NetworkEvent{
		PID:   1234,
		Comm:  "curl",
		DAddr: net.ParseIP(ip),
		DPort: port,
		Time:  time.Now(),
	}
}

func TestCorrelator_NoAlertNoMalicious(t *testing.T) {
	c := newTestCorrelator(t)
	// Pas d'alerte YARA, IP non malveillante — rien ne doit se passer
	c.OnNetworkEvent(testNetEvent("1.2.3.4", 443))
}

func TestCorrelator_YaraOnly(t *testing.T) {
	c := newTestCorrelator(t)
	c.AddAlert(testAlert("/tmp/malware.exe", "Test_Rule"))
	if len(c.alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(c.alerts))
	}
}

func TestCorrelator_C2Only(t *testing.T) {
	c := newTestCorrelator(t, "1.2.3.4")
	// Pas d'alerte YARA mais IP malveillante
	c.OnNetworkEvent(testNetEvent("1.2.3.4", 443))
}

func TestCorrelator_YaraC2(t *testing.T) {
	c := newTestCorrelator(t, "1.2.3.4")
	c.AddAlert(testAlert("/tmp/malware.exe", "Test_Rule"))
	c.OnNetworkEvent(testNetEvent("1.2.3.4", 443))
}

func TestCorrelator_GC(t *testing.T) {
	c := newTestCorrelator(t)
	// Ajoute une alerte expirée manuellement
	c.alerts = append(c.alerts, timedAlert{
		alert: testAlert("/tmp/old.exe", "Old_Rule"),
		at:    time.Now().Add(-2 * correlationWindow),
	})
	c.alerts = append(c.alerts, timedAlert{
		alert: testAlert("/tmp/new.exe", "New_Rule"),
		at:    time.Now(),
	})

	c.gc()

	if len(c.alerts) != 1 {
		t.Errorf("expected 1 alert after gc, got %d", len(c.alerts))
	}
	if c.alerts[0].alert.RuleName != "New_Rule" {
		t.Errorf("expected New_Rule to survive gc, got %s", c.alerts[0].alert.RuleName)
	}
}
