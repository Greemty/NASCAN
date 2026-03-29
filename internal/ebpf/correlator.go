package ebpf

import (
	"sync"
	"time"

	"github.com/greemty/nascan/internal/scanner"
	"github.com/greemty/nascan/internal/threatintel"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const correlationWindow = 60 * time.Second

type Correlator struct {
	mu     sync.Mutex
	alerts []timedAlert
	logger *zap.Logger
	feed   *threatintel.Feed

	c2Connections prometheus.Counter
	correlations  *prometheus.CounterVec
}

type timedAlert struct {
	alert scanner.Alert
	at    time.Time
}

func NewCorrelator(logger *zap.Logger, feed *threatintel.Feed, reg prometheus.Registerer) *Correlator {
	c2Connections := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nascan_c2_connections_total",
		Help: "Connexions vers des IPs C2 connues",
	})
	correlations := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nascan_correlations_total",
		Help: "Corrélations YARA ↔ réseau par type",
	}, []string{"type"}) // type: yara_only | c2_only | yara_c2

	reg.MustRegister(c2Connections, correlations)

	return &Correlator{
		logger:        logger,
		feed:          feed,
		c2Connections: c2Connections,
		correlations:  correlations,
	}
}

func (c *Correlator) AddAlert(alert scanner.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, timedAlert{alert: alert, at: time.Now()})
	c.correlations.WithLabelValues("yara_only").Inc()
	c.gc()
}

func (c *Correlator) OnNetworkEvent(ev NetworkEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gc()

	ip := ev.DAddr.String()
	isMalicious := c.feed.IsMalicious(ip)

	if len(c.alerts) == 0 && !isMalicious {
		return
	}

	if isMalicious && len(c.alerts) == 0 {
		c.c2Connections.Inc()
		c.correlations.WithLabelValues("c2_only").Inc()
		c.logger.Warn("connexion vers C2 connu",
			zap.String("ip", ip),
			zap.Uint16("port", ev.DPort),
			zap.String("comm", ev.Comm),
			zap.Uint32("pid", ev.PID),
		)
		return
	}

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
			c.c2Connections.Inc()
			c.correlations.WithLabelValues("yara_c2").Inc()
			c.logger.Warn("corrélation YARA ↔ C2 confirmé", fields...)
		} else {
			c.correlations.WithLabelValues("yara_only").Inc()
			c.logger.Warn("corrélation YARA ↔ réseau", fields...)
		}
	}
}

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
