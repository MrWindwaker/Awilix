# Development Journal

## *April 3 2026*
Current prototype. 

* Scans /proc for running processes
* Filters only numeric PIDs
* Reads and parses cmdline arguments
* Detects npm install specifically
* Tracks seen PIDs to avoid duplicates
* Cleans up dead PIDs so it can detect the same command again

## *April 4 2026*

### What we built today
- eBPF probe compiled and loaded into the kernel via libbpf skeleton
- Ring buffer established between kernel and userspace
- Child process tracking via /proc/<pid>/stat PPid field
- Connection allowlist (Cloudflare 104.16.x.x, DNS 100.100.100.100)
- Simulated postinstall attack via evil.js — caught and blocked

### Current status
- Detects npm install in real time
- Tracks the full process tree (parent + children)
- Intercepts connect() syscalls via eBPF
- Checks connections against an allowlist
- Blocks unauthorized callouts
- Caught a fake C2 connection to 1.3.3.7:4444 (with 2 second delay)

### Known limitations
- Race condition: scan loop too slow for fast-spawning children
- Port detection inaccurate (shows :0 for HTTPS connections)
- Allowlist hardcoded, not loaded from config
- [BLOCKED] logs but does not yet kill the connection

### Potential improvements (v1)
- Netlink process events for instant child detection
- Hook sys_exit_connect for accurate port numbers
- Load allowlist from config/policy.json
- Actual connection termination on block
- Extend to pip, cargo, pacman

## *April 13 2026*

The prototype is done and online. I feel the adrenaline of what I have built 
and learned from the past two weeks.

Started this because of the axios incident. Angry enough to do something about it.
Didn't know C++. Didn't know eBPF. Didn't know netlink. Learned all of it by hitting
walls and pushing through them.

Awilix now:
- Detects npm install via kernel netlink events
- Tracks child processes via BTF task structs
- Intercepts connect() via eBPF LSM hooks
- Blocks unauthorized connections before they complete
- Alerts the developer in their own terminal
- Logs everything to JSON

The inotify wall. The VM disaster. The Docker afternoon. The seg faults. 
The 2 AM commit. The flu week. All of it led here.

One developer. One janky X230. One too many postmortems.

The exit is staked out.

Next: find partners, extend beyond npm, make it production ready.

Special thanks to Bayaseto and his unnamed friend, the supervisors.