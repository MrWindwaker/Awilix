#ifndef __PROBES_BPF_H
#define __PROBES_BPF_H

#ifndef __BPF_COMPILATION__
#include <linux/types.h>
#endif

struct event
{
    __u32 pid;
    __u32 ip;
    __u16 port;
    __u64 timestamp;
    char comm[16];
    __u8 blocked;
};

#endif