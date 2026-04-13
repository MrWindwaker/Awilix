#pragma once
#include <iostream>
#include "ebpf/probes.skel.h"
#include "ebpf/probes.bpf.h"
#include "allowlist.h"
#include <arpa/inet.h>

int handleEvent(void *ctx, void *data, size_t size);