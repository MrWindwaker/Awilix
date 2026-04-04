#ifndef __PROBES_BPF_H
#define __PROBES_BPF_H


struct event
{
    __u32 pid;
    __u32 ip;
    __u16 port;
    __u64 timestamp;
    char comm[16];
};


#endif