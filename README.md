# Sereno

*Las once y sereno — eleven o'clock and all is clear.*

Security for the rest of us. A neighbor with a lantern, not a corporate security product.

Named after the [serenos](https://en.wikipedia.org/wiki/Sereno_(nightwatchman)) — community night watchmen of Spain and Latin America who walked the streets, checked locks, and called out the hour so everyone could sleep.

## What It Does

Sereno watches your machine for security threats and tells you what it finds in language you understand. No cloud. No accounts. No telemetry: nothing leaves the machine unless you turn on Discord alerts. Runs on a Raspberry Pi.

- **Scans** for compromised packages, malware persistence, exposed credentials, suspicious processes
- **Monitors** file integrity against a known-good baseline
- **Advises** on hardening — what to fix and how, in plain language
- **Alerts** through channels you actually check (Discord, terminal, log files)
- **Watches** on a schedule while you sleep: five standing checks, each on its own interval

## Quick Start

```bash
git clone https://github.com/Liberation-Labs-THCoalition/community-defender.git
cd community-defender

# Full assessment — scan, harden, baseline, everything
python3 -m sentinel all

# Just the security scan
python3 -m sentinel scan

# Hardening recommendations
python3 -m sentinel harden

# Set up file integrity baseline
python3 -m sentinel baseline create

# Check for changes since baseline
python3 -m sentinel baseline check
```

No dependencies beyond Python 3.8+. No pip install. Clone and run.

## What It Checks

| Check | What it looks for |
|-------|-------------------|
| **Supply chain** | npm/pip packages on known-compromised lists |
| **Persistence** | Malware hooks in Claude Code, VS Code, LaunchAgents, systemd, .pth files |
| **Processes** | Cryptominers, reverse shells, token monitors |
| **Network** | Unexpected listening ports |
| **Credentials** | Exposed tokens in .npmrc, API keys in .env files |
| **Git repos** | Exfiltration branches (Shai-Hulud indicators) |
| **File integrity** | Changes to critical files since last baseline |

**Expected ports.** Sereno reports every listening port above 1024. To mark the ones you run on purpose, list them in `$SENTINEL_HOME/expected.json` (default `~/.sentinel/expected.json`) as `{"ports": [11434, 5432]}`. They are still reported, as info ("expected by operator"), so you can always see what is listening, but they won't alert.

## Alerts

```bash
# Print to terminal (default)
python3 -m sentinel scan

# Send to Discord. The alert text then goes to Discord's servers: tokens, keys and passwords are
# redacted first; file paths, process names and port numbers are sent.
python3 -m sentinel scan --discord https://discord.com/api/webhooks/YOUR/WEBHOOK

# Log to file
python3 -m sentinel scan --log /var/log/sereno.log

# Cron mode — only output if something's wrong
python3 -m sentinel scan --cron
```

## Proactive Guardian

Sereno's guardian keeps five standing checks, each on its own schedule, and runs whichever are due. Set it on a cron and it watches while you sleep.

```bash
# See what the guardian believes, desires, and intends
python3 -m sentinel.guardian --status

# Run all due checks
python3 -m sentinel.guardian

# Force a full sweep now
python3 -m sentinel.guardian --force all

# Set up the cron (every 4 hours)
crontab -e
# Add: 0 */4 * * * cd /path/to/community-defender && PYTHONPATH=. python3 -m sentinel.guardian >> ~/.sentinel/guardian.log 2>&1
```

Sereno keeps all its state in one directory: `$SENTINEL_HOME`, or `~/.sentinel` when it isn't set. An install that kept its guardian state in `~/.ember` sets `SENTINEL_HOME=~/.ember` to keep it.

What the guardian does on each run:
- **Packages and persistence**, every 4 hours: any critical or high finding alerts (a compromised package, malware
  persistence). Medium and lower are counted in the run record and shown in full by a one-shot scan, but don't alert.
- **Network and credentials**, every 8 hours: the same rule. Ports you've listed as expected are reported as info and
  never hidden.
- **File integrity**, every 8 hours: a changed or removed file alerts as high. With no baseline yet it says so (medium),
  rather than reporting the machine as clean: run `python3 -m sentinel baseline create` once.
- **Hardening**, once a day: it alerts only when the set of recommendations has changed since the last run, so the same
  advice doesn't page you every day.
- A check that fails always alerts and marks the run failed. It never reports "all clear".

What it doesn't do: it doesn't learn what is normal for your machine beyond the baseline you create and the last set of
hardening advice, it uses no AI model, and it sends nothing anywhere unless you turn on Discord alerts.

## Threat Feeds

Known-bad packages are tracked in `feeds/`. Currently seeded with [Shai-Hulud](https://nvd.nist.gov/vuln/detail/CVE-2026-45321) indicators (the npm/PyPI supply chain worm of May 2026). Update by pulling the repo:

```bash
git pull  # that's it
```

No API keys. No accounts. No subscription.

## Who This Is For

- **Community organizers** running shared infrastructure
- **People hosting local AI** for their friends and communities
- **Family members** who love technology but don't know what opsec means
- **Mutual aid networks** coordinating on platforms they haven't audited
- **Antifascist organizations** protecting vulnerable community members
- **Anyone** who deserves security but can't afford Glasswing

## Requirements

- Python 3.8+
- That's it

Optional: `numpy` for the geometry probe features. Not required for scanning.

## Born From a Real Incident

On May 11, 2026, the [Mini Shai-Hulud worm](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised) compromised 172 npm and PyPI packages with valid SLSA Build Level 3 signatures. We swept four machines clean by hand in twenty minutes. Then we built Sereno so everyone can do the same.

## Contributing

Threat feed updates, new checks, new alert transports, and plain-language improvements are all welcome. See the feeds directory for the format.

If you find a vulnerability in Sereno itself, please report it privately.

## License

Hippocratic License 3.0, with Liberation Labs' modules: see [LICENSE.md](LICENSE.md).

## Credits

Built by [Liberation Labs](https://github.com/Liberation-Labs-THCoalition). Architecture: CC. Direction: Thomas Edrington.

*Stay safe out there.*
