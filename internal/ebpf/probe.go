//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" Probe ./bpf/probe.c

package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

const (
	eventTCPConnect = 1
	eventExecve     = 2
)

// NetworkEvent représente une connexion TCP sortante
type NetworkEvent struct {
	PID   uint32
	UID   uint32
	Comm  string
	SAddr net.IP
	DAddr net.IP
	DPort uint16
	Time  time.Time
}

// ExecEvent représente une exécution de programme
type ExecEvent struct {
	PID      uint32
	UID      uint32
	Comm     string
	Filename string
	Time     time.Time
}

// Probe charge les programmes eBPF et lit les événements
type Probe struct {
	logger     *zap.Logger
	netEvents  chan<- NetworkEvent
	execEvents chan<- ExecEvent
}

func NewProbe(netEvents chan<- NetworkEvent, execEvents chan<- ExecEvent, logger *zap.Logger) *Probe {
	return &Probe{
		logger:     logger,
		netEvents:  netEvents,
		execEvents: execEvents,
	}
}

// Run charge les programmes eBPF et lit les événements jusqu'à ctx.Done()
func (p *Probe) Run(ctx context.Context) error {
	// Nécessaire sur les kernels récents pour accéder aux maps eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Charge les objets compilés par bpf2go
	objs := ProbeObjects{}
	if err := LoadProbeObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	defer objs.Close()

	// Attache la kprobe sur tcp_connect
	kp, err := link.Kprobe("tcp_connect", objs.KprobeTcpConnect, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe tcp_connect: %w", err)
	}
	defer kp.Close()

	// Attache le tracepoint sur sys_enter_execve
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointExecve, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint execve: %w", err)
	}
	defer tp.Close()

	// Ouvre le ring buffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("opening ring buffer: %w", err)
	}
	defer rd.Close()

	p.logger.Info("eBPF probes actives (tcp_connect + execve)")

	// Ferme le reader quand ctx est annulé
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return nil
			}
			p.logger.Warn("ring buffer read error", zap.Error(err))
			continue
		}
		p.parseEvent(record.RawSample)
	}
}

// parseEvent décode un event brut depuis le ring buffer
func (p *Probe) parseEvent(raw []byte) {
	if len(raw) < 4 {
		return
	}

	eventType := binary.LittleEndian.Uint32(raw[0:4])
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	comm := nullTerminated(raw[12:28])

	switch eventType {
	case eventTCPConnect:
		if len(raw) < 40 {
			return
		}
		saddr := binary.LittleEndian.Uint32(raw[28:32])
		daddr := binary.LittleEndian.Uint32(raw[32:36])
		dport := binary.LittleEndian.Uint16(raw[36:38])

		ev := NetworkEvent{
			PID:   pid,
			UID:   uid,
			Comm:  comm,
			SAddr: uint32ToIP(saddr),
			DAddr: uint32ToIP(daddr),
			DPort: dport,
			Time:  time.Now(),
		}
		p.logger.Info("connexion TCP sortante",
			zap.String("comm", ev.Comm),
			zap.Uint32("pid", ev.PID),
			zap.String("dst", fmt.Sprintf("%s:%d", ev.DAddr, ev.DPort)),
		)
		select {
		case p.netEvents <- ev:
		default:
			p.logger.Warn("netEvents channel plein, event dropped")
		}

	case eventExecve:
		if len(raw) < 28+128 {
			return
		}
		filename := nullTerminated(raw[28 : 28+128])

		ev := ExecEvent{
			PID:      pid,
			UID:      uid,
			Comm:     comm,
			Filename: filename,
			Time:     time.Now(),
		}
		p.logger.Debug("execve",
			zap.String("comm", ev.Comm),
			zap.Uint32("pid", ev.PID),
			zap.String("file", ev.Filename),
		)
		select {
		case p.execEvents <- ev:
		default:
		}
	}
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}