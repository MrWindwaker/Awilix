#include "allowlist.h"

bool isAllowed(__u32 ip)
{
    unsigned char *ip_bytes = (unsigned char *)&ip;

    if (ip_bytes[0] == 104 && ip_bytes[1] == 16)
        return true;

    if (ip_bytes[0] == 100 && ip_bytes[1] == 100 && ip_bytes[2] == 100 && ip_bytes[3] == 100)
        return true;

    return false;
}

void populateAllowlist(struct probes_bpf *skel)
{
    __u8 val = 1;

    for (int i = 0; i <= 255; i++)
    {
        __u32 ip = (104) | (16 << 8) | (i << 16) | (34 << 24);
        bpf_map__update_elem(skel->maps.allowed_ips, &ip, sizeof(ip), &val, sizeof(val), BPF_ANY);
    }

    __u32 dns = (100) | (100 << 8) | (100 << 16) | (100 < 24);
    bpf_map__update_elem(skel->maps.allowed_ips, &dns, sizeof(dns), &val, sizeof(val), BPF_ANY);
}