package ebpf

import (
	"sync"
	"time"

	"github.com/greemty/nascan/internal/scanner"
	"go.uber.org/zap"
)

const correlationWindow = 60 * time.Second

// Correlator fait le lien entre les alertes YARA et les events réseau eBPF
// Si un fichier est détecté par YARA et qu'une connexion sortante apparaît
// dans la fenêtre de corrélation, on lève une alerte enrichie.
type Correlator struct {
	mu     sync.Mutex
	alerts []timedAlert
	logger *zap.Logger
}

type timedAlert struct {
	alert scanner.Alert
	at    time.Time
}

func NewCorrelator(logger *zap.Logger) *Correlator {
	return &Correlator{logger: logger}
}

// AddAlert enregistre une alerte YARA pour corrélation future
func (c *Correlator) AddAlert(alert scanner.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, timedAlert{alert: alert, at: time.Now()})
	c.gc()
}

// OnNetworkEvent vérifie si une connexion sortante correspond à une alerte YARA récente
func (c *Correlator) OnNetworkEvent(ev NetworkEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gc()

	if len(c.alerts) == 0 {
		return
	}

	// Si des alertes YARA sont actives dans la fenêtre, on corrèle
	for _, a := range c.alerts {
		c.logger.Warn("corrélation YARA ↔ réseau",
			zap.String("yara_file", a.alert.Path),
			zap.String("yara_rule", a.alert.RuleName),
			zap.String("net_comm", ev.Comm),
			zap.Uint32("net_pid", ev.PID),
			zap.String("dst", ev.DAddr.String()),
			zap.Uint16("dport", ev.DPort),
		)
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