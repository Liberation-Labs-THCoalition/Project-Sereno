# Changelog

What changed in Sereno, in plain words. Newest first. To get the changes, run `git pull` in your Project-Sereno folder.

## 2026-10-24

- **Network check: every port, named.** Each listening port, TCP and UDP, now shows the program behind it and the
  program's file where Sereno can see them, and known services are named: "remote desktop (gnome-remote-desktop) on
  port 3390" instead of "unexpected listening port 3390". Each finding says how it knew: by the program, by its systemd
  unit, or by the port alone ("likely ..."). A port whose program can't be seen without sudo says so, and is still
  reported. (151d520, 7ba1698, 09d8dd1)
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
    netstat failing is "partly checked", not silence. One byte that isn't UTF-8 in a command's output no longer stops
    the whole check.
  - Never read: a program's command line, which can hold passwords.
- **Notes are printed.** A scan with nothing but notes said "7 notes below, for your information:" and then printed
  none of them. They're listed now. (69c4073)

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
