package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const refreshPeriod = 24 * time.Hour

// sources defines all threat intel feeds
var sources = []struct {
	name    string
	url     string
	comment string // préfixe des lignes à ignorer
}{
	{
		name:    "Feodo Tracker",
		url:     "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		comment: "#",
	},
	{
		name:    "CINS Army",
		url:     "http://cinsscore.com/list/ci-badguys.txt",
		comment: "#",
	},
	{
		name:    "Emerging Threats",
		url:     "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
		comment: "#",
	},
}

type Feed struct {
	mu     sync.RWMutex
	ips    map[string]struct{}
	logger *zap.Logger
	client *http.Client
}

func NewFeed(logger *zap.Logger) *Feed {
	return &Feed{
		ips:    make(map[string]struct{}),
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *Feed) Start(ctx context.Context) error {
	if err := f.refresh(ctx); err != nil {
		return fmt.Errorf("initial threat intel fetch: %w", err)
	}

	go func() {
		ticker := time.NewTicker(refreshPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := f.refresh(ctx); err != nil {
					f.logger.Warn("threat intel refresh failed", zap.Error(err))
				}
			}
		}
	}()

	return nil
}

func (f *Feed) IsMalicious(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.ips[ip]
	return ok
}

func (f *Feed) Count() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.ips)
}

func (f *Feed) refresh(ctx context.Context) error {
	newIPs := make(map[string]struct{})

	for _, src := range sources {
		count, err := f.fetchSource(ctx, src.url, src.comment, newIPs)
		if err != nil {
			// On log l'erreur mais on continue avec les autres sources
			f.logger.Warn("feed fetch failed",
				zap.String("source", src.name),
				zap.Error(err),
			)
			continue
		}
		f.logger.Info("feed loaded",
			zap.String("source", src.name),
			zap.Int("ips", count),
		)
	}

	f.mu.Lock()
	f.ips = newIPs
	f.mu.Unlock()

	f.logger.Info("threat intel updated",
		zap.Int("total_ips", len(newIPs)),
	)
	return nil
}

func (f *Feed) fetchSource(ctx context.Context, url, comment string, dest map[string]struct{}) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	count := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, comment) {
			continue
		}
		// Certaines listes incluent le CIDR ou des métadonnées — on prend juste l'IP
		ip := strings.Fields(line)[0]
		dest[ip] = struct{}{}
		count++
	}

	return count, sc.Err()
}

func (f *Feed) AddIP(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ips[ip] = struct{}{}
}
