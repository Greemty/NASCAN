# nascan

A lightweight security daemon for Linux that watches a filesystem in real time, scans files with [YARA-Forge](https://github.com/YARAHQ/yara-forge) rules, correlates detections with network activity using eBPF, and automatically quarantines malicious files.

Built in Go, designed for homelabs and self-hosted infrastructure.

## Why

Most NAS security tools are closed-source, cloud-dependent, or require proprietary hardware. nascan is a simple, auditable daemon you run on your own Linux host — no agents, no cloud, no subscriptions.

## How it works

nascan implements three layers of defense:

```
Layer 1 — Detection (YARA)
  New or modified files are scanned against 5000+ YARA-Forge rules.
  Threat intel from Feodo Tracker, CINS Army, and Emerging Threats
  is loaded at startup and refreshed every 24 hours (~15 000 C2 IPs).
         │
         ▼
Layer 2 — Containment (Quarantine)
  Matched files are immediately moved to an isolated directory
  with chmod 000 — unreadable by any user, including root.
         │
         ▼
Layer 3 — Monitoring (eBPF)
  Kernel probes watch outbound TCP connections and process executions.
  If a matched file is followed by a connection to a known C2 IP
  within 60 seconds, a correlated alert is raised.
```

## Architecture

```
Filesystem (NFS mount, local path, ...)
     │
     ▼
nascan daemon (Go)
  ├── inotify watcher      recursive, real-time file events
  ├── YARA scanner         YARA-Forge rules (auto-downloaded)
  ├── Quarantine           atomic move + chmod 000
  ├── Threat intel         ~15 000 C2 IPs, refreshed every 24h
  ├── eBPF probes          tcp_connect kprobe + execve tracepoint
  ├── Correlator           YARA ↔ network, 60s sliding window
  └── Prometheus /metrics  scraped by your existing stack
```

## Quick start

### 1. Dependencies

```bash
# Debian / Ubuntu
sudo apt install libyara-dev clang llvm libbpf-dev linux-headers-$(uname -r)
```

### 2. Build

```bash
# Generate eBPF objects (Linux only, requires clang)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
go generate ./internal/ebpf/

# Build
go build -o nascan ./cmd/nascan
```

### 3. Download YARA-Forge rules

```bash
./nascan update-rules
```

This fetches the latest `yara-rules-core.yar` bundle from YARA-Forge (~5000 curated rules).
Use `-bundle extended` or `-bundle full` for broader coverage.

### 4. Run

```bash
sudo ./nascan \
  -watch /mnt/nas/downloads \
  -quarantine /var/lib/nascan/quarantine \
  -scan-existing
```

`-scan-existing` triggers a full scan of files already present before switching to watch mode.

## Options

```
-watch          Path to watch (default: /mnt/nas)
-quarantine     Quarantine directory — disabled if empty
-scan-existing  Scan files already present at startup
-bundle         YARA-Forge bundle: core | extended | full (default: core)
-rules-dir      Where YARA rules are stored (default: ./rules-data)
-metrics        Prometheus endpoint (default: :9100, empty to disable)
-force-update   Re-download rules even if already present
```

## Monitoring

nascan exposes `/metrics` on `:9100`. Point your existing Prometheus at it:

```yaml
scrape_configs:
  - job_name: "nascan"
    static_configs:
      - targets: ["<your-host-ip>:9100"]
```

### Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `nascan_files_scanned_total` | — | Total files scanned |
| `nascan_scan_duration_seconds` | — | Scan duration histogram |
| `nascan_yara_hits_total` | `rule`, `namespace` | YARA matches per rule and ruleset |
| `nascan_quarantine_total` | `rule` | Files quarantined per YARA rule |
| `nascan_c2_connections_total` | — | Outbound connections to known C2 IPs |
| `nascan_correlations_total` | `type` | Correlation events: `yara_only`, `c2_only`, `yara_c2` |

The `type` label on `nascan_correlations_total` distinguishes between:
- `yara_only` — YARA match with no C2 connection
- `c2_only` — connection to a known C2 IP with no YARA match (possible undetected malware)
- `yara_c2` — YARA match followed by a C2 connection (highest severity)

## Threat intelligence feeds

nascan aggregates IP blocklists from three sources at startup, refreshed every 24 hours:

| Feed | Coverage |
|------|----------|
| [Feodo Tracker](https://feodotracker.abuse.ch) | Botnet C2 servers |
| [CINS Army](http://cinsscore.com) | ~15 000 malicious IPs |
| [Emerging Threats](https://rules.emergingthreats.net) | Compromised hosts |

All feeds are merged in memory — no database, no persistence. On restart, feeds are re-fetched automatically.

## eBPF probes

nascan attaches two kernel probes at runtime:

- **`kprobe/tcp_connect`** — captures all outbound TCP connections (PID, comm, src/dst IP, port)
- **`tracepoint/syscalls/sys_enter_execve`** — captures process executions

Both probes use a ring buffer to pass events to userspace with minimal overhead. The correlator maintains a 60-second sliding window of active YARA alerts and cross-references every network event against it and the threat intel feed.

Requires Linux kernel 5.8+ with BTF support. Tested on Debian 13 (kernel 6.12).

## Use case: torrent client on Docker + NFS NAS

nascan was designed for this exact setup:

```
Torrent client (Docker)
  └── downloads to NAS share (NFS mounted on Proxmox host)
         └── nascan watches the mount point
               ├── detects malicious files immediately after download
               ├── quarantines them before they can be executed
               └── alerts if a C2 connection follows
```

For an additional layer, mount the NFS share with `noexec` — the kernel will refuse to execute any binary from the mount regardless of permissions:

```
/mnt/nas/downloads  10.0.0.0/24(rw,noexec,nosuid)
```

## License

MIT