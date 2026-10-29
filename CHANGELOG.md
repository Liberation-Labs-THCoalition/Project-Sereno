# Changelog

What changed in Sereno, in plain words. Newest first. To get the changes, run `git pull` in your Project-Sereno folder.

## 2026-10-29

From Ember's guardian install on a shared home (2026-10-26..28); Nexus found the second and third.

- **A skip list for every search under your home.** On a machine where several AI agents keep their folders under one
  account (`~/agents/<name>/`), Sereno's searches walked into the other agents' folders, and their paths and variable
  names landed in the log. List folders in `$SENTINEL_HOME/skip.json` (`["~/agents/*", "!~/agents/yours"]` skips every
  agent's folder but your own), or pass `--skip PATH`, and every search leaves them out, without entering them: package
  folders, payload files, VS Code tasks, Python startup files, `.env` files, git repositories, Claude Code and MCP
  project settings (also those `~/.claude.json` lists), the baseline, and the profile's counts. Links into a listed
  folder are resolved first, so they don't get around it. A scan that skipped anything says so in one note ("Not
  checked: 3 folders on your skip list"); an entry that matches nothing is a note too; a `skip.json` that can't be read
  makes Sereno search none of your folders and say so (high), rather than risk entering the ones you listed. With no
  file, nothing changes.
- **Every scan names its state folder.** The report's header, the JSON (`state_folder`, `state_folder_default`), the
  guardian's last line and its run records say which folder Sereno read, and when it's the default because
  `SENTINEL_HOME` isn't set. Ember's scans by hand read `~/.sentinel` for days, `SENTINEL_HOME` being set only on the
  cron line.
- **A package listed without versions is "check the version", not a high.** Such an entry can't say your version is a
  bad one, so it's now medium, naming your version and saying the list doesn't say which releases are bad. An entry
  with versions matches only those (critical, as before); other versions aren't reported. An MCP server pinned to a
  listed bad version is now reported (critical), and one pinned to a package listed without versions is "check the
  version" (medium). litellm's entry already names its three bad releases (1.82.7, 1.82.8, 1.107.0; OSV MAL-2026-2144),
  so litellm 1.84.0 isn't reported.

## 2026-10-24

- **Network check: every port, named.** Each listening port, TCP and UDP, now shows the program behind it and the
  program's file where Sereno can see them, and known services are named: "remote desktop (gnome-remote-desktop) on
  port 3390" instead of "unexpected listening port 3390". Each finding says how it knew: by the program, by its systemd
  unit, or by the port alone ("likely ..."). A port whose program can't be seen without sudo says so, and is still
  reported. (151d520, 7ba1698, 09d8dd1, 66ec1b7, 8ff2256, f6df868)
  - Remote control that other machines can reach (a remote desktop such as RDP, VNC, NoMachine, RustDesk, AnyDesk or
    TeamViewer, or SSH on a port other than 22) is now high on any TCP port, with the command that switches it off
    and the one that undoes it. SSH on port 22 isn't reported, as before.
  - Tailscale's own listeners on your tailnet addresses are info, recognised when `tailscale status --json` lists them
    as this machine's peer API, or when they belong to root's `tailscaled`.
  - If Sereno can't list the ports at all, it says "Listening ports not checked" (medium) instead of nothing. Without
    `ss`, it reads `/proc/net` directly.
  - On macOS, the system's own listeners are listed too (from `netstat`), and a connected UDP socket is no longer
    mistaken for a listening port.
  - After review: a program can't pass itself off as root's `tailscaled` by naming a helper "uid:0" (Sereno reads
    the owner only from the fields after the program names). Docker's published port 4000 is "Docker", not "likely
    NoMachine": a unit the system made outranks the port. A unit a user named `cups.service` no longer calls their
    port printing. An SSH login's forwarded port (`ssh -R`) is "SSH reverse tunnel", medium, with no advice to stop
    an SSH server. TightVNC, Xvnc4, RealVNC's virtual desktops, xpra, Sunshine and Guacamole are named as remote
    desktops. GNOME's VNC off a 5900 port gets the VNC command, not RDP's. A socket bound to the loopback device is
    this machine only. Run as root, a socket with no program is no longer called "the kernel's" outright. On macOS,
    netstat failing is "partly checked", not silence. One byte that isn't UTF-8 in a command's output, a program's
    name or a program's folder no longer stops the whole check or the printed report. A second SSH server that a root
    login started is "SSH server", high, not a tunnel, and stays high after the SSH service restarts or when inetd
    starts sshd: Sereno now tells the listening SSH server by the sockets it holds, not by its parent's name. A port
    forwarded through a login to a second SSH server is a tunnel, medium, not a server. Run as root, the step for a
    socket a user's own systemd holds names that user.
  - Never read: a program's command line, which can hold passwords.
- **Notes are printed.** A scan with nothing but notes said "7 notes below, for your information:" and then printed
  none of them. They're listed now. (69c4073)
- **New check: AI agent safety (`agent_safety`).** Sereno now reports AI coding agents set to skip their own
  safety prompts: Claude Code's bypass mode, its warning before bypass mode turned off, every project MCP server
  approved, or every shell command allowed (including a rule for a program that runs whatever it's given, such as
  `Bash(python3:*)`); Codex set to never ask with no sandbox; VS Code's global auto-approve; Gemini CLI letting every
  shell command through; and shell aliases, functions and fish abbreviations that start `claude`, `codex` or
  `gemini` with their skip flags, also through programs that start another (`sudo -Hu bob`, `timeout`, `npx`,
  `op run --`, `mise exec --`, `uv tool run`, `watch`, `su -c`, `tmux new` and more) or `$(which codex)`, and with a
  redirection written against a flag (`--yolo>log`). Each shell line is read in one pass, so a file built to slow the
  scan down can't. In your own settings that's advice (medium), with how to turn the prompt back on;
  in a project folder's Claude Code settings it's high. It also reports agent logins left exposed: a login file
  other accounts can read (`chmod 600` fixes it), and an agent API key or token written into a shell startup file,
  fish's universal variables or your Claude Code settings, by name and line, never the value.
- **Fixes in the same checks.** A package.json nested too deep to parse no longer stops the npm check; and when git
  refuses to read a repository (one owned by another account), the MCP check says it couldn't ask git instead of
  calling the file untracked.
- **MCP check: a scanned folder's git settings can't run a program.** To learn whether a config holding a secret is
  in git, Sereno asks git, and git used to run the fsmonitor command named in that folder's own `.git/config`, so a
  downloaded folder could make a read-only scan run a program. Sereno now switches that command and git hooks off
  for the question, as Claude Code does.
- **A settings file nested too deep to parse no longer stops a check.** A JSON file in a project folder nested
  deeper than Python can parse used to stop the persistence, MCP and agent checks, losing their other findings. It's
  now reported as not checked, like any file Sereno can't read.

## 2026-10-23

- **Honest results.** What Sereno says now matches what it checked. (b80e1f2)
  - npm matches are rated by how exact the list is: a known-bad version is critical, a listed package without versions
    is high, and a package that's only under a listed scope is medium, where every `@tanstack` package used to be
    called critical.
  - A check that breaks is reported as a high finding ("Check couldn't run"), where a scan used to end with "No issues
    found".
  - A misspelled `--checks` name stops the scan (exit code 2) instead of running nothing and reporting clean.
  - The guardian's last line says "All clear" only when every skill ran and found nothing; a failed skill is named,
    and the guardian exits with 1.
  - Info notes aren't counted as issues, and `--cron` stays quiet when notes are all there is.
  - `setup.mjs` and `sysmon.py` alone are a note, not critical malware; next to the worm's other files they're still
    critical.
- **New check: MCP servers.** Sereno now reads the configs of AI coding tools (Claude Code, Claude Desktop, Cursor,
  VS Code, Windsurf, Gemini CLI, and Codex on Python 3.11+) and reports MCP servers started with no fixed version
  (`npx -y some-server`, `uvx some-server`), and API keys written in plain text in those configs, by key name, never
  the value. (f99a165)
- **New name on GitHub: Project-Sereno.** The old community-defender address redirects. Commands still say
  `sentinel`, so existing installs and cron lines keep working. (06086ba)
- **File integrity: quieter, and sharper.** The baseline no longer watches Claude Code's transcripts and caches in
  `~/.claude`, which changed all the time and raised an alert on every guardian run. It still watches the parts that
  change how Claude Code behaves: settings, hooks, commands, agents, skills, `CLAUDE.md` and the plugin lists. It now
  sees setuid and setgid bits and changes of owner, and the guardian rates both high. Existing baselines keep
  working. (b40b798)
- **pip check: listed packages are never skipped.** A package on the pip list without its bad versions is now
  reported, as high, instead of passed over. The lists now carry the exact bad versions of litellm, telnyx, lightning
  and pytorch-lightning, so ordinary installs of those aren't flagged, and the npm list adds tensorlake. (e452195)
- **Python startup files.** Any `.pth` line that runs code at Python's start, and any `sitecustomize.py` or
  `usercustomize.py` in `site-packages` under your home, is reported as high. Well-known normal ones are let through,
  recognised by name and content together. The old check missed the litellm 1.107.0 malware, which used both. (3525a41)
- **Network check: more complete.** Every listening TCP port except 22, 80 and 443 is reported, low ports included.
  One only this machine can reach is info. UDP services on low ports that other machines can reach are reported
  too. (0060f82)
- **Claude Code settings in project folders.** Sereno reads the `.claude` settings that come with a project, not just
  your own. It reports hooks that download and run code (high), any hook a project brings (medium), and a project that
  sends Claude Code's traffic, and your API key with it, to another address through `ANTHROPIC_BASE_URL` (high).
  (24c7fea)

## Earlier

Earlier changes aren't listed here. See the git history: `git log`, or the commits page at
https://github.com/Liberation-Labs-THCoalition/Project-Sereno/commits/main
