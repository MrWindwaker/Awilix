#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "probes.bpf.h"

char LICENSE[] SEC("license") = "GPL";
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef EPERM
#define EPERM 1
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

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} allowed_ips SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(handle_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u8 *watched = bpf_map_lookup_elem(&watched_pids, &pid);
    if (!watched)
    {
        return 0;
    }

    __u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

    if (family != AF_INET)
    {
        return 0;
    }

    struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
    __u32 ip;
    __u16 port;
    bpf_probe_read_kernel(&ip, sizeof(ip), &addr_in->sin_addr);
    bpf_probe_read_kernel(&port, sizeof(port), &addr_in->sin_port);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return -EPERM;

    e->pid = pid;
    e->ip = ip;
    e->port = port;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u32 ppid;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    e->ppid = ppid;

    __u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &ip);
    if (!allowed)
    {
        e->blocked = 1;
        bpf_ringbuf_submit(e, 0);
        return -EPERM;
    }

    e->blocked = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}