# Development Journal

## *April 3 2026*
Current prototype. 

* Scans /proc for running processes
* Filters only numeric PIDs
* Reads and parses cmdline arguments
* Detects npm install specifically
* Tracks seen PIDs to avoid duplicates
* Cleans up dead PIDs so it can detect the same command again