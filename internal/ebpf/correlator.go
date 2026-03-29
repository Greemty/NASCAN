package ebpf

import (
	"sync"
	"time"

	"github.com/greemty/nascan/internal/scanner"
	"github.com/greemty/nascan/internal/threatintel"
	"go.uber.org/zap"
)

const correlationWindow = 60 * time.Second

type Correlator struct {
	mu     sync.Mutex
	alerts []timedAlert
	logger *zap.Logger
	feed   *threatintel.Feed
}

type timedAlert struct {
	alert scanner.Alert
	at    time.Time
}

func NewCorrelator(logger *zap.Logger, feed *threatintel.Feed) *Correlator {
	return &Correlator{logger: logger, feed: feed}
}

// AddAlert enregistre une alerte YARA pour corrélation future
func (c *Correlator) AddAlert(alert scanner.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, timedAlert{alert: alert, at: time.Now()})
	c.gc()
}

// OnNetworkEvent vérifie si une connexion sortante est suspecte
func (c *Correlator) OnNetworkEvent(ev NetworkEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gc()

	ip := ev.DAddr.String()
	isMalicious := c.feed.IsMalicious(ip)

	// Rien à signaler : pas d'alerte YARA active ET IP non malveillante
	if len(c.alerts) == 0 && !isMalicious {
		return
	}

	// Connexion vers un C2 connu, même sans alerte YARA
	if isMalicious && len(c.alerts) == 0 {
		c.logger.Warn("connexion vers C2 connu",
			zap.String("ip", ip),
			zap.Uint16("port", ev.DPort),
			zap.String("comm", ev.Comm),
			zap.Uint32("pid", ev.PID),
		)
		return
	}

	// Corrélation YARA + réseau
	for _, a := range c.alerts {
		fields := []zap.Field{
			zap.String("yara_file", a.alert.Path),
			zap.String("yara_rule", a.alert.RuleName),
			zap.String("net_comm", ev.Comm),
			zap.Uint32("net_pid", ev.PID),
			zap.String("dst", ip),
			zap.Uint16("dport", ev.DPort),
		}
		if isMalicious {
			c.logger.Warn("corrélation YARA ↔ C2 confirmé", fields...)
		} else {
			c.logger.Warn("corrélation YARA ↔ réseau", fields...)
		}
	}
}

// gc supprime les alertes hors de la fenêtre de corrélation
func (c *Correlator) gc() {
	cutoff := time.Now().Add(-correlationWindow)
	fresh := c.alerts[:0]
	for _, a := range c.alerts {
		if a.at.After(cutoff) {
			fresh = append(fresh, a)
		}
	}
	c.alerts = fresh
}
