# Sereno

*Las once y sereno — eleven o'clock and all is clear.*

Security for the rest of us. A neighbor with a lantern, not a corporate security product.

Named after the [serenos](https://en.wikipedia.org/wiki/Sereno_(nightwatchman)) — community night watchmen of Spain and Latin America who walked the streets, checked locks, and called out the hour so everyone could sleep.

## What It Does

Sereno looks over your machine for signs of trouble and tells you what it finds in language you understand. No cloud. No accounts. No telemetry: Sereno sends nothing off your machine unless you turn on Discord alerts. Runs on a Raspberry Pi.

- **Scans** for compromised packages, malware persistence, exposed credentials, suspicious processes, open ports, and risky settings in AI coding tools
- **Monitors** file integrity against a known-good baseline
- **Advises** on hardening — what to fix and how, in plain language
- **Alerts** through channels you actually check (Discord, terminal, log files)
- **Watches** on a schedule while you sleep: five standing checks, each on its own interval

## Quick Start

```bash
git clone https://github.com/Liberation-Labs-THCoalition/Project-Sereno.git
cd Project-Sereno

# Full assessment — profile, scan, harden, baseline, everything (makes a baseline if you have none)
python3 -m sentinel all

# Just the security scan
python3 -m sentinel scan

# Hardening recommendations
python3 -m sentinel harden

# Set up file integrity baseline
python3 -m sentinel baseline create

# Check for changes since baseline
python3 -m sentinel baseline check

# You've looked at the changes and they're yours: make them the new baseline
python3 -m sentinel baseline update
```

No dependencies beyond Python 3.8+. No pip install. Clone and run.

The commands say `sentinel`, not `sereno`. That's the name of Sereno's code folder, kept so that older installs and cron lines keep working.

## What It Checks

`python3 -m sentinel scan` runs these nine checks:

| Check | What it looks for |
|-------|-------------------|
| **Supply chain: npm** | Packages in the `node_modules` folders under your home folder that are on Sereno's npm list. How serious a match is depends on how exact the list is. A known-bad version is critical; any other version of a package listed with versions isn't reported. A listed package whose bad versions aren't given is medium, titled "Check the version": the finding names your version and says the list doesn't say which releases are bad, so compare it with the advisory. A package that's only under a listed scope, such as `@tanstack`, is medium: most packages in those scopes are fine, so compare your version with the advisory (see Threat Feeds), and if it's a bad one, follow the steps in the finding. |
| **Supply chain: pip** | Python packages that `pip3 list` shows, checked against Sereno's pip list. That's one Python install: packages in your other virtual environments aren't on it. An exact known-bad version is critical, and other versions of that package aren't reported. A listed package whose bad versions aren't given is medium ("Check the version", naming yours), never a claim that your version is a bad one. |
| **Persistence** | Ways malware makes itself start again: the Shai-Hulud worm's files anywhere in your home folder (its token monitor, also as a systemd service or macOS LaunchAgent, and its payload files; `setup.mjs` and `sysmon.py` are common names, so alone they're a note, and critical only next to the worm's other files or naming them), VS Code tasks that call them, Claude Code hooks, and Python startup files that run code. More below. |
| **Processes** | Running programs with names known from malware: the Shai-Hulud token monitor and payloads, cryptominers such as xmrig, and reverse shells. |
| **Network** | Programs waiting for connections (listening ports), each named where Sereno can tell: "remote desktop (gnome-remote-desktop) on port 3390", not just "port 3390". Every TCP port except 22, 80 and 443: medium if other machines can reach it, info if only this machine can. Remote control that other machines can reach (a remote desktop such as RDP, VNC, NoMachine, RustDesk, AnyDesk or TeamViewer, or SSH on a port other than 22) is high on any TCP port, with how to switch it off. UDP services on ports up to 1024 that other machines can reach, except common ones (DHCP, NTP, NetBIOS), and remote desktops' UDP ports. Tailscale's own listeners on your tailnet addresses are info. |
| **Credentials** | Tokens in `~/.npmrc` (high), and lines that look like API keys, tokens or passwords in files named `.env` under your home folder (medium). |
| **Git repos** | Dune-themed branch names, which the Shai-Hulud worm used to carry stolen data out, in the git repositories under your home folder. |
| **MCP servers** | AI coding tools (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI, and Codex on Python 3.11+) starting MCP servers with no fixed version (`npx -y some-server`, `uvx some-server`): medium, or high if the package is on Sereno's lists. A server pinned to a version that's on the lists (`uvx litellm==1.82.7`): critical; pinned to a package listed without versions: medium, "Check the version". API keys written in plain text in their configs, named, never shown: medium, or high if git tracks the file. Project `.mcp.json`, `.cursor/mcp.json` and `.vscode/mcp.json` files count too. |
| **AI agent safety** | AI coding agents set to skip their own safety prompts: Claude Code's bypass mode, its warning before bypass mode turned off, every project MCP server approved, or every shell command allowed (`Bash`, `Bash(*)`, or a program that runs whatever it's given, such as `Bash(python3:*)` or `Bash(env *)`, from Claude Code's own list); Codex set to never ask with no sandbox; VS Code's global auto-approve; Gemini CLI letting every shell command through; and shell aliases, functions and fish abbreviations that start `claude`, `codex` or `gemini` with their skip flags (also behind a program that starts another, such as `sudo`, `timeout`, `npx`, `op run --`, `mise exec --`, `watch` or `su -c`, and inside `eval` or `sh -c`). In your own settings these are advice (medium): what it means, and how to turn the prompt back on. In a project folder's Claude Code settings they're high, because a repo someone else wrote can switch your prompts off. Agent logins left exposed: a login file other accounts can read (`~/.claude/.credentials.json`, Codex's `auth.json`, Gemini CLI's `oauth_creds.json`), or an agent API key or token (`ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY` and two more) written into a shell startup file or your Claude Code settings: high, named, never shown. |

Two more checks run outside `scan`. Both are part of `all` and of the guardian:

- **File integrity** (`baseline create`, then `baseline check`): files that are new, gone, changed, or have new permissions or a new owner since you made the baseline. The files it watches are listed under [What Sereno reads](#what-sereno-reads-and-what-leaves-your-machine).
- **Hardening** (`harden`): loose permissions on SSH keys and credential files, SSH that accepts passwords, a firewall that's off, automatic updates that aren't set up, services open to the network (Ollama included), and a real email address in your git commits.

**Claude Code hooks.** Claude Code can run commands, called hooks, when things happen. Sereno reads your own Claude Code settings (`~/.claude/settings.json` and `settings.local.json`), managed settings an administrator installed, and the `.claude/settings.json` and `.claude/settings.local.json` in project folders (Claude Code's known projects, and folders up to four levels under your home). A project's settings arrive with the project, so opening the folder can bring hooks with it. Sereno reports:

- a hook that names known malware: critical;
- a hook that downloads and runs code (for example `curl ... | sh`): high;
- a project that sends Claude Code's traffic, and your API key with it, to another address (`ANTHROPIC_BASE_URL`): high. In your own settings it's info, since people run proxies on purpose;
- any other hook in a project's settings: medium, because working in that folder runs it.

A plain hook in your own settings isn't reported: it's yours.

**Python startup files.** Python runs some files every time it starts: a line in a `.pth` file that begins with `import`, and any `sitecustomize.py` or `usercustomize.py`. The malware in litellm 1.107.0 used both. Sereno looks in the `site-packages` and `dist-packages` folders under your home and reports each one as high, except well-known normal ones (virtualenv, setuptools, editable installs, coverage, pytest-cov, namespace packages, coloredlogs). It recognises those by file name and content together, so a file can't pass by borrowing a name.

**AI agent safety prompts and logins.** Claude Code, Codex and Gemini CLI ask before they run a command or change a file, and each can be told not to. That's your call, and in your own settings Sereno treats it as advice: it says what the setting does, how to turn the prompt back on, and how to undo that. But an agent that never asks also acts on a prompt hidden in a file it reads, and the s1ngularity malware (2025) drove installed agents with exactly these skip flags. A project folder's Claude Code settings that switch prompts off are high. Claude Code 2.1.257 and later ignore bypass mode in a project's files, and a project's allow rules wait until you trust the folder; but earlier versions honor bypass mode from a project, and one click on "trust" lets the allow rules through. A project's `.claude/settings.local.json` that git says it doesn't track is treated as yours: that's where Claude Code saves your "don't ask again" answers. One git can't vouch for (the folder isn't a repository, as a download isn't) is treated as the project's. Keys and tokens are named by variable, file and line, never shown, and shell lines aren't quoted. A short value such as `ollama`, which local model servers ask for, or a placeholder such as `your_api_key_here`, is a note, not an issue; so is a key left in a commented-out line, which is still in the file. An agent credential in Sereno's own environment is a note too: that's how people run agents.

Sereno reads a shell line as the shell does and counts a skip flag only where `codex` or `gemini` is the program run, so `pip install gemini -y` or a message that mentions `codex --yolo` isn't mistaken for the agent. Not covered: an agent started through a program that isn't on Sereno's list of programs that start another (for example `docker run`, `ssh`, `nix shell`, `distrobox` or `strace`); an agent named through a variable, another alias or a function (`$AGENT --yolo`, or `alias g=gemini` and then `alias gy='g --yolo'`); a command typed into a terminal with `tmux send-keys`; and Gemini's short options run together (`gemini -sy`). In bash, `>|` writes to a file even when it exists; Sereno reads the `|` as a pipe, as fish does in `2>|`, so `make >| codex --yolo` is reported although bash would only write to a file named codex.

**Files Sereno can't read.** A Claude Code settings file, MCP config, or any file the agent safety check reads that Sereno can't read is reported as "not checked" (info), never as clean.

**Expected ports.** Sereno reports every listening TCP port except 22, 80 and 443, and UDP services on ports up to 1024; a port only this machine can reach (127.0.0.1, ::1) is info. To mark the ones you run on purpose, list them in `$SENTINEL_HOME/expected.json` (default `~/.sentinel/expected.json`) as `{"ports": [11434, 5432]}`. They are still reported, as info ("expected by operator"), so you can always see what is listening, but they won't alert. That holds for a remote desktop you use on purpose too.

**How Sereno names a port, and how sure it is.** Each finding says how it told what the port is:

- **By its program** (and the program's file on disk): a fact. Linux shows Sereno the program only for your own programs unless you run it with sudo.
- **By its systemd unit**, which current Linux systems show for every socket (older `ss` versions don't): used when the program isn't visible. A unit the system made (under `/system.slice`) is a fact, and it outranks the port: Docker's published port 4000 is "Docker", not "likely NoMachine". A unit a user or a container named is shown in the finding, but it can only mark a port as remote control, never as an ordinary service, since anyone can call their own unit `cups.service`. A socket another user holds inside the SSH server's unit isn't the SSH server: the server's own listener is root's.
- **By its port alone** ("Likely remote desktop (VNC) on port 5901"): a guess, used only when neither the program nor a system unit Sereno knows is visible. The finding says "owner not visible without sudo" and how to look: `sudo ss -ltnup 'sport = :5901'`.
- **Tailscale's own listeners** are info when they're bound only to your tailnet addresses and Sereno can tell they're Tailscale's: `tailscale status --json` lists that exact address and port as this machine's peer API, or the socket belongs to root's `tailscaled` (its system unit, or its program when Sereno runs with sudo: without it, Sereno sees only your own programs). A program that only calls itself tailscaled doesn't count, and neither does a program name dressed up to look like the owner's user id.
- **SSH logins' forwarded ports.** The SSH server forks a process for each login (before OpenSSH 9.8 it's still called `sshd`), and that process holds the ports the login forwards with `ssh -R`. Such a port is named "SSH reverse tunnel", medium, not "SSH server", high, when the process's parent is the SSH server running as root and either the process shares its parent's session (a login as any user but root) or the parent is the listening server: it holds one of the listening sockets Sereno found, and isn't a login's process itself. Which sockets the parent holds is read from the links in its `/proc/<pid>/fd` folder; for root's SSH server only root can read them, so a root login's port is told apart only when Sereno runs with sudo. An SSH server someone started themselves, a root login included, stays high.

Not covered by the SSH rule: after the SSH service restarts while a root login stays open (Debian's and Ubuntu's `ssh.service` has `KillMode=process`, and an `openssh-server` upgrade restarts it), or when inetd starts `sshd` for each connection, a root login that both forwards a port with `ssh -R` and starts a second SSH server makes that server read "SSH reverse tunnel", medium, not "SSH server", high: the login's process then holds a listening socket (its forward) and has systemd or inetd for a parent, as the listening server does. The server is still reported. In the same two setups, a root login's own forwarded ports read "SSH server", high, until the login ends.

A port whose program Sereno can't see is still reported, never treated as clean. If Sereno can't list the ports at all, it says "Listening ports not checked" (medium). On macOS, if `netstat` fails but `lsof` works, it says "Listening ports partly checked" (medium): without sudo, `lsof` shows only your own programs.

## Folders Sereno doesn't enter (the skip list)

On a machine you share, someone else's folders under your home aren't yours to search. Several AI agents kept under one account (`~/agents/<name>/`) is the case this was built for: Sereno's findings never carry values, but paths and variable names from someone else's folder, in a log you read, still cross a line. List those folders, and every search Sereno makes through your home (package folders, payload files, VS Code tasks, Python startup files, `.env` files, git repositories, Claude Code and MCP project settings, the file-integrity baseline, and the profile's counts) leaves them out: it doesn't enter them at all, rather than entering and hiding what it found. Nothing inside a listed folder is even looked at: Sereno checks each path against the list before its first look, not after.

A path counts as in a listed folder three ways: by the path as written (a link inside the folder that points elsewhere is still inside it, so a project of theirs that `~/.claude.json` lists, linked out to `/data`, isn't read); by where it really leads (a link of yours into the folder doesn't get around it); and by what the folder is, whatever it's called (a link you listed, a mount of it, or `~/Agents/Nexus` for `~/agents/nexus` on a Mac, whose disk ignores case).

The list is `$SENTINEL_HOME/skip.json` (default `~/.sentinel/skip.json`), a JSON list of paths. `~` means your home; a relative path is taken from your home; `*` and `?` match names (not names starting with a dot); an entry starting with `!` takes a path back off the list. With no file, nothing is skipped.

```json
["~/agents/nexus", "~/agents/lyra"]
```

On a shared home, skip every agent's folder but your own. The `*` picks up an agent who arrives later, too:

```json
["~/agents/*", "!~/agents/ember"]
```

The guardian reads the same file, so set `SENTINEL_HOME` the same way for it and for your own runs (each run names the state folder it used; see below). For one run, add `--skip PATH` (as many as you like) to `scan`, `all`, `profile` or `baseline`; it's added to the file's list, and a relative path is taken from the folder you're in:

```bash
python3 -m sentinel scan --skip ~/agents/nexus --skip ~/agents/lyra
```

A skip is never silent. A scan that skipped anything carries one note, "Not checked: 3 folders on your skip list", naming the listed paths it matched (never anything inside them): that scan says nothing about those folders. Each listed folder counts once, however many paths led into it, and one that isn't there isn't counted. An entry that matches nothing is a note too, once per scan. If `skip.json` can't be read, or isn't a list of paths, Sereno can't promise to stay out of the folders you meant, so it searches none of the folders under your home and says so as a high finding ("Skip list unreadable"); fix or remove the file.

Files Sereno reads at fixed places follow the list too: `~/.bashrc`, `~/.npmrc`, `~/.claude/settings.json`, `~/.claude.json` itself, and the agent folders named by `CLAUDE_CONFIG_DIR` and `CODEX_HOME`. They're yours, so they're read as usual; one you list, or one that's a link into a listed folder, isn't, and the note counts it. In `~/.claude.json`, the MCP servers it keeps for a project in a listed folder aren't reported.

**Which state folder a scan used.** Every scan's report starts with the state folder it read (`expected.json`, `skip.json`), and says when that's the default because `SENTINEL_HOME` isn't set (or is set to nothing: "is empty"); the JSON has `state_folder` and `state_folder_default`. If you set `SENTINEL_HOME` only on a cron line, a scan you run by hand reads `~/.sentinel` instead, and the header shows it.

## What Sereno reads, and what leaves your machine

Sereno reads. It doesn't change your files. It writes only its own files in `$SENTINEL_HOME` (default `~/.sentinel`), plus a log or results file if you ask for one. It runs as you, so it sees what you can see, and it looks mostly in your home folder, outside the folders on your skip list (see above).

| Part | What it reads |
|------|---------------|
| Supply chain | Package folder names in the `node_modules` folders under your home, and the `package.json` of each package that's on the list or under a listed scope. Package names and versions from `pip3 list`. |
| Persistence | File names across your home folder. Claude Code settings files, and the project list in `~/.claude.json`. VS Code `tasks.json` files. `.pth`, `sitecustomize.py` and `usercustomize.py` files under your home. |
| Processes | The process list (`ps aux`), which includes each program's full command line. |
| Network | The listening ports with their program, user and systemd unit (`ss` on Linux, or `/proc/net` and the links in each program's `/proc/<pid>/fd` when `ss` is missing; `lsof` and `netstat` on macOS), the program's file path (`/proc/<pid>/exe` on Linux, `ps` on macOS), and your `expected.json`. For an SSH server's program holding a port, its session and its parent's name and user (`/proc/<pid>/stat`, and the parent's `comm` and `status`), and which sockets that parent holds (the links in its `/proc/<pid>/fd`, which name the files and sockets a program has open: only the sockets are used, and nothing is kept), up through the SSH servers run as root. When a port is on a Tailscale address, `tailscale status --json`, which asks the Tailscale program on your machine, not the network. Never a program's command line, which can hold passwords. |
| Credentials | `~/.npmrc` and `.env` files under your home. |
| Git repos | Branch names in each repository under your home (`git branch -a`). |
| MCP servers | The MCP config files of the tools listed above, and `~/.claude.json`, which holds Claude Code's servers and project list. For a config holding a secret, it asks git whether the file is tracked, with the folder's own git hooks and fsmonitor command switched off, so a folder's git settings can't run a program. |
| AI agent safety | Claude Code settings files (yours in `~/.claude` and `$CLAUDE_CONFIG_DIR`, managed ones, and the project ones the persistence check finds, using the project list in `~/.claude.json`), Codex's `config.toml` (in `~/.codex` and `$CODEX_HOME`), Gemini CLI's `~/.gemini/settings.json`, VS Code's user `settings.json`, and your shell startup files: `.bashrc`, `.bash_profile`, `.bash_login`, `.bash_aliases`, `.profile`, `.zshrc`, `.zprofile`, `.zshenv`, the files in `~/.bashrc.d`, oh-my-zsh's `custom/*.zsh`, and fish's `config.fish`, `conf.d`, `functions` and `fish_variables` (where `set -U` keeps its variables). For a project's `settings.local.json` that switches prompts off, it asks git whether the file is tracked, as the MCP check does. Agent login files are never opened: only their permissions are read. From its own environment, only whether agent credential variables are set, never their values. |
| File integrity | Every file in the watch list, read to fingerprint it: `~/.ssh` (private keys included), `.bashrc`, `.zshrc`, `.profile`, `.gitconfig`, `.npmrc`, `~/.vscode`, your systemd user services, and in `~/.claude` only settings, hooks, commands, agents, skills, `CLAUDE.md`, keybindings and the plugin lists (not transcripts or caches). On Linux also `/etc/crontab`, `/etc/hosts`, `/etc/passwd` and `/etc/sudoers`; on macOS, `~/Library/LaunchAgents`. The baseline stores each file's path, SHA-256 fingerprint, size, time, permissions and owner, never its contents. A file you can't read, like `/etc/sudoers` for most users, is tracked by its permissions and owner only. |
| Hardening | Permissions of SSH keys and credential files, `/etc/ssh/sshd_config`, firewall status, automatic-update settings (`/etc/apt/apt.conf.d/20auto-upgrades`), listening ports, and your global git email. |
| Profile (`profile`, `all`) | Machine name, your user name, system, CPU, memory and disk use; versions of Python, Node, npm and git; counts of packages, SSH keys and `.env` files; Ollama's model list; the names of your Claude Code hook events. |

What leaves your machine:

- **Nothing, unless you turn on Discord.** Findings print in your terminal. `--log` adds them to a file on your machine, in full, with nothing removed: keep that file where only you can read it.
- **Discord, if you add `--discord`.** Each critical or high finding goes to the webhook address you give, through Discord's servers, with a scan's summary or the guardian's notice that a check failed. Before sending, Sereno removes anything shaped like a secret: tokens, API keys, passwords, and logins inside web addresses (`sentinel/redact.py`). What's still sent: file paths (which usually include your user name), program names and command lines with secrets removed, port numbers, and your machine's name.
- **Nothing else.** No telemetry, no account, no update check. The threat lists come with the code, and you update them with `git pull`.
- **One thing that isn't Sereno.** The scan runs `pip3 list`, and `profile` and `all` run `npm list -g`. pip and npm may, on their own, ask PyPI or the npm registry whether a newer pip or npm exists (about once a week). That request carries nothing from Sereno. To turn it off: `export PIP_DISABLE_PIP_VERSION_CHECK=1` and `npm config set update-notifier false`.

## What Sereno is not

- **Not antivirus.** It doesn't scan every file for malware. It looks for specific signs: packages on its lists, known malware file and process names, and settings that run code.
- **Not real-time protection.** It looks when you run it, or when the guardian's schedule comes round. Something that comes and goes between looks can be missed.
- **Not a replacement for updates.** Keep your system and your apps up to date.
- **Not a replacement for your judgment.** A finding is something to look at, not proof of an attack: ordinary software sometimes looks like this. If you're not sure, ask someone you trust before you delete anything.
- **"Nothing found" means nothing found by these checks,** in the places they look. It doesn't mean the machine is clean. If a check itself breaks, the scan says so as a high finding ("Check couldn't run"), and the guardian names the skill that failed instead of saying "All clear".
- **Linux and macOS.** On Windows, run it inside WSL. On Windows itself, the process and network checks can't look, and say nothing.

## Alerts

```bash
# Print to terminal (default)
python3 -m sentinel scan

# Send to Discord: each critical or high finding, and a summary. Secrets are removed first; file paths,
# program names, port numbers and your machine's name are sent (see "What leaves your machine").
python3 -m sentinel scan --discord https://discord.com/api/webhooks/YOUR/WEBHOOK

# Log to file (the full text, nothing removed: keep the file private)
python3 -m sentinel scan --log ~/sereno.log

# Cron mode — only output if something's wrong
python3 -m sentinel scan --cron
```

For scripts:

```bash
# Results as JSON, also saved to a file
python3 -m sentinel scan --json -o results.json

# Only some checks
python3 -m sentinel scan --checks network,mcp_servers
```

Check names for `--checks`: `npm_supply_chain`, `pip_supply_chain`, `persistence`, `processes`, `network`, `credentials`, `git_repos`, `mcp_servers`, `agent_safety`. A misspelled name stops the scan before it starts, with the list of names. A scan exits with 1 when it finds something critical, 2 for a check name it doesn't know, and 0 otherwise.

Findings marked info are notes, not issues: a port only this machine can reach, for example. The report lists them after "No issues found", and `--cron` stays quiet when notes are all there is.

## Proactive Guardian

Sereno's guardian keeps five standing checks, each on its own schedule, and runs whichever are due. Set it on a cron and it watches while you sleep.

```bash
# See what the guardian believes, desires, and intends
python3 -m sentinel.guardian --status

# Run all due checks
python3 -m sentinel.guardian

# Force a full sweep now
python3 -m sentinel.guardian --force all

# Force one check now, by the name --status shows (this one is file integrity)
python3 -m sentinel.guardian --force system_integrity

# Alerts work as they do for scan
python3 -m sentinel.guardian --discord https://discord.com/api/webhooks/YOUR/WEBHOOK --log ~/sereno.log

# Set up the cron (every 4 hours)
crontab -e
# Add: 0 */4 * * * cd /path/to/Project-Sereno && PYTHONPATH=. python3 -m sentinel.guardian >> ~/.sentinel/guardian.log 2>&1
```

Sereno keeps all its state in one directory: `$SENTINEL_HOME`, or `~/.sentinel` when it isn't set. The guardian's last line, `--status`, and each run record in `guardian_runs/` name the folder it used. An install from before 2026-10-17 that kept its guardian state in `~/.ember` had its baseline and profile in `~/.sentinel`: copy `baseline.json` and `profile.json` into `~/.ember` first, then set `SENTINEL_HOME=~/.ember`. Otherwise the guardian keeps its beliefs but reports that no baseline exists.

What the guardian does on each run:
- **Packages and persistence**, every 4 hours (packages includes the MCP server check; persistence includes running
  processes): any critical or high finding alerts (a compromised package, malware persistence). Medium and lower are
  counted in the run record and shown in full by a one-shot scan, but don't alert.
- **Network and credentials**, every 8 hours: the same rule. Ports you've listed as expected are reported as info and
  never hidden.
- **File integrity**, every 8 hours: a changed or removed file alerts as high, and so do a new owner and a newly added
  setuid or setgid bit (a permission that lets a program run with its owner's power). A new file or another permission
  change is counted but doesn't alert. With no baseline yet it says so (medium), rather than reporting the machine as
  clean: run `python3 -m sentinel baseline create` once.
- **Hardening**, once a day: it alerts only when the set of recommendations has changed since the last run, so the same
  advice doesn't page you every day.
- A check that breaks sends an alert saying it failed, and the run record in `$SENTINEL_HOME/guardian_runs/` marks it
  failed. The run's last line says "All clear" only when every skill ran and found nothing that needs action. When a
  skill failed, it names it and the guardian exits with 1; when nothing was due, it says that no skills ran.

What it doesn't do: it doesn't learn what is normal for your machine beyond the baseline you create and the last set of
hardening advice, it uses no AI model, and it sends nothing anywhere unless you turn on Discord alerts.

## Threat Feeds

Known-bad packages are tracked in `feeds/`: the npm and PyPI packages of the [Shai-Hulud](https://nvd.nist.gov/vuln/detail/CVE-2026-45321) supply chain worm of May 2026, and exact bad versions of litellm, telnyx, lightning and pytorch-lightning from OSV's malware records, plus tensorlake on npm. Update by pulling the repo:

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

- Python 3.8+ (3.11+ to check Codex's MCP config)
- Linux or macOS (on Windows, use WSL)
- That's it. Sereno uses tools those systems already have: `ps`, `ss` (Linux) or `lsof` and `netstat` (macOS), and `git`, `pip` and `tailscale` when they're installed.

## Born From a Real Incident

On May 11, 2026, the [Mini Shai-Hulud worm](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised) compromised 172 npm and PyPI packages with valid SLSA Build Level 3 signatures. We swept four machines clean by hand in twenty minutes. Then we built Sereno so everyone can do the same.

## Contributing

Threat feed updates, new checks, new alert transports, and plain-language improvements are all welcome. See the feeds directory for the format. What changed, and when, is in [CHANGELOG.md](CHANGELOG.md).

If you find a vulnerability in Sereno itself, please report it privately.

## License

Hippocratic License 3.0, with Liberation Labs' modules: see [LICENSE.md](LICENSE.md).

## Credits

Built by [Liberation Labs](https://github.com/Liberation-Labs-THCoalition). Architecture: CC. Direction: Thomas Edrington.

The MCP server check follows an idea from [stack-guard](https://github.com/SolanceLab/stack-guard) by SolanceLab (MIT),
which flags unpinned MCP servers for Claude Code users.

*Stay safe out there.*
