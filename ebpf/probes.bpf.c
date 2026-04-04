#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "probes.bpf.h"

char LICENSE[] SEC("license") = "GPL";
#ifndef AF_INET
#define AF_INET 2
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} watched_pids SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect") 
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u8 *watched = bpf_map_lookup_elem(&watched_pids, &pid);
    if (!watched)
        return 0;
    

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

    __u16 family;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    if (family != AF_INET)
        return 0;

    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;

    __u32 ip;
    __u16 port;

    bpf_probe_read_user(&ip, sizeof(ip), &addr_in->sin_addr);
    bpf_probe_read_user(&port, sizeof(port), &addr_in->sin_port);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->ip = ip;
    e->port = port;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    return 0;
}