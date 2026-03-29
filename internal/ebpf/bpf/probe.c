// +build ignore

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// Types d'événements
#define EVENT_TCP_CONNECT 1
#define EVENT_EXECVE      2

// Struct partagée entre le kernel et le userspace Go
// Doit rester en sync avec probe.go
struct event {
    __u32 type;       // EVENT_TCP_CONNECT ou EVENT_EXECVE
    __u32 pid;
    __u32 uid;
    __u8  comm[16];   // nom du processus

    // TCP connect
    __u32 saddr;      // IP source (IPv4)
    __u32 daddr;      // IP destination (IPv4)
    __u16 dport;      // port destination

    // execve
    __u8  filename[128]; // chemin de l'exécutable
};

// Ring buffer : le kernel y pousse les events, Go les lit
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

// Probe sur tcp_connect — capte toute nouvelle connexion TCP sortante
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    // On ne s'intéresse qu'à IPv4
    __u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type  = EVENT_TCP_CONNECT;
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_probe_read_kernel(&e->saddr, sizeof(e->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&e->daddr, sizeof(e->daddr), &sk->__sk_common.skc_daddr);
    __u16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    e->dport = bpf_ntohs(dport);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Probe sur sys_execve — capte chaque exécution de programme
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_EXECVE;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Lit le chemin de l'exécutable depuis les args du syscall
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";