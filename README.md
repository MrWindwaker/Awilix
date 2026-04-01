# Awilix

A proactive network surveillance tool for developers and system administrators.
Traditional antivirus reacts to known threats. Awilix watches the exit.
Every supply chain attack — regardless of sophistication — must call home. Awilix intercepts that moment by monitoring the network behavior of sensitive processes like package managers, flagging and blocking outbound connections that have no business being made.

## Why

The axios incident. The xz backdoor. Event-stream. The pattern is always the same: discovered too late, damage already done. Awilix is built on the premise that the hole matters as much as the patch.
Status
Early development. Currently targeting package manager network egress via eBPF.


## Goals

* Observe and baseline normal package manager network behavior
* Block unauthorized outbound connections at the syscall level
* Be lightweight enough to run on a janky server
* Be useful to a solo developer, not just an enterprise security team
