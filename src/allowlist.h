#pragma once
#include <linux/types.h>
#include <bpf/libbpf.h>
#include "ebpf/probes.skel.h"
#include "ebpf/probes.bpf.h"

bool isAllowed(__u32 ip);
void populateAllowlist(struct probes_bpf *skel);