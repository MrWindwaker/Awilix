# Awilix

A proactive, kernel-level supply chain attack interceptor for developers and system administrators.

## The Problem

On April 1st 2026, the axios npm package was compromised. Before that, xz. Before that, event-stream. The pattern is always the same: discovered too late, damage already done, postmortem published, everyone moves on.

Traditional antivirus reacts to known threats. It loses by design — attackers only need one novel technique, defenders have to anticipate all of them.

Awilix takes a different approach.

## The Insight

Every supply chain attack — regardless of sophistication — must call home. The C2 callout is the invariant. We don't guard the perimeter. We stake out the exit.

## How It Works

When a package manager like npm runs, Awilix:

1. Detects the process instantly via Linux netlink process events
2. Tracks the entire process tree, including postinstall hook children
3. Intercepts every outbound `connect()` syscall via an eBPF LSM hook
4. Checks the destination against a known-good allowlist
5. Blocks unauthorized connections at the kernel level — returning `EPERM` before the connection completes
6. Alerts the developer in their terminal and logs the event to JSON

## Demo
[DETECTED] PID 2540058: node /usr/bin/npm install
[CHILD] PID 2540070 (parent: 2540058)
[BLOCKED] PID 2540070 (node-MainThread) -> 127.0.0.1:4444
[AWILIX] ⚠ Suspicious connection blocked!
[AWILIX] Process: node-MainThread (PID 2540070)
[AWILIX] Attempted to connect to: 127.0.0.1:4444
[AWILIX] This has been logged to logs/awilix.log

## Status

Early prototype. Currently targeting npm on Linux with kernel 5.15+.

## Requirements

- Linux kernel 5.15+ with `CONFIG_BPF_LSM=y`
- `bpf` in active LSM list (`/sys/kernel/security/lsm`)
- clang, libbpf, bpftool

## Build

```bash
make
sudo ./bin/awilix
```

## Why

One developer, one janky server, one too many postmortems.

If no one is going to protect developers from supply chain attacks at the system level, a janky PC in Monterrey is a good place to start.