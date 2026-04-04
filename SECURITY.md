# Security Policy

## Our Promise

Awilix is built on a simple principle: **visibility without violation, protection without possession.**

This document outlines what Awilix does, what it does NOT do, and how we earn and maintain your trust.

---

## What Awilix Does

- Monitors outbound network calls from package managers (npm, pip, yarn, pnpm, gem, etc.)
- Logs **package name** and **destination domain** when an unknown server is contacted
- Warns you immediately with clear, actionable information
- Shows you exactly where logs are stored
- Provides instructions for reporting suspicious activity to ecosystem security teams
- Runs entirely on your machine

---

## What Awilix Does NOT Do

| Does Not | Explanation |
|----------|-------------|
| **Modify traffic** | We log and warn. We do not alter, block, or interfere with network calls |
| **Read file contents** | Only package names are captured. We never read your source code, environment variables, or credentials |
| **Phone home** | Awilix makes no automatic external connections. Reporting is always manual and user-initiated |
| **Auto-update** | Updates require your explicit action. You control what runs on your machine |
| **Persist after uninstall** | Removal is complete. No hidden processes, no leftover config, no background tasks |
| **Collect personal data** | No telemetry. No analytics. No user tracking. No "anonymized" data collection |
| **Require root/administrator** | Runs at user level. Elevated privileges are never required |

---

## Transparency Chain

Every action Awilix takes is visible and auditable:

1. **Source Code** — Fully open source. Read it. Compile it yourself.
2. **Builds** — Reproducible builds. Verify binaries match source.
3. **Behavior** — Documented syscalls and interception methods.
4. **Logs** — Plain text, user-readable, stored in `~/.awilix/logs/`
5. **Warnings** — Clear terminal output. No silent operation.
6. **Uninstall** — `rm -rf ~/.awilix` removes everything.

---

## Consent

Awilix operates only with your explicit consent:

- You install it deliberately
- You run it deliberately
- You can stop it at any time
- You can uninstall it completely at any time

No background daemons. No installation without your knowledge. No persistence you didn't authorize.

---

## Reporting Suspicious Activity

When Awilix detects an unknown outbound call:

1. You see a warning in your terminal
2. The log is written to `~/.awilix/logs/`
3. You decide what happens next

**To report to security teams:**
```bash
cat ~/.awilix/logs/$(date +%Y-%m-%d).log
```

Review the log. If you believe you've found a malicious package, submit to:

npm: npm report [package-name] or security@npmjs.com

General: https://github.com/advisories

Awilix never submits reports automatically. You are in control.

Uninstall
Awilix leaves no trace:

bash
# Stop Awilix if running
pkill awilix

# Remove everything
rm -rf ~/.awilix

# If installed system-wide (requires deliberate user action)
sudo rm -rf /usr/local/bin/awilix
After uninstall, your system returns to its exact pre-Awilix state.

Our Philosophy
"A tool that respects you enough to let you destroy it is a tool you can trust."

Awilix is built to be:

Indispensable, not inescapable

Visible, not invisible

Respectful, not possessive

Protective, not punitive

We want you to keep Awilix because it earns its place, not because it hides from removal.

Vulnerability Reporting
If you discover a security vulnerability in Awilix itself:

Do not open a public issue

Email: mrwindwaker@proton.me

Include detailed steps to reproduce

We take our own security as seriously as we take yours.

Version History
Version	Security Commitment
1.x	Core principles: minimal data, clean uninstall, no telemetry

Questions?
If anything in this document is unclear, if you find behavior that contradicts these promises, or if you simply want to verify what Awilix is doing on your machine:

Read the source code

Run with strace to see every syscall

Build from source yourself

Open an issue (for non-security concerns)

We have nothing to hide. We invite your scrutiny.

Awilix is your tool. Your machine. Your choice. Always.


## Why This Helps Your Mind

| Concern | Addressed By |
|---------|--------------|
| "Am I building something that looks like malware?" | Clear "Does NOT" table draws the line explicitly |
| "What if users don't trust me?" | Transparency chain gives them every tool to verify |
| "What if I accidentally over-collect?" | Documented constraints you must honor |
| "What about uninstall?" | Explicit, tested removal process |
| "What about ethics?" | Philosophy section states your values openly |
