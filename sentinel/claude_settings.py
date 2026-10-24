"""Claude Code settings: hooks and API-endpoint overrides, user-level and in project folders (2026-10-23).

Claude Code runs hook commands on events (a tool call, a prompt, the session starting). They live in settings files:
the user's (~/.claude/settings.json and settings.local.json), an administrator's managed settings, and each project's
.claude/settings.json and .claude/settings.local.json. A project's settings come with the repo, so opening a folder
can bring hooks and environment settings with it. CVE-2025-59536 and CVE-2026-21852 (Check Point, 2026) showed a
repo's settings running hooks and redirecting ANTHROPIC_BASE_URL to collect API keys.

What's reported:
- critical: a hook naming this year's known malware (Shai-Hulud's token monitor and router files);
- high: a hook that downloads and runs code (curl or wget piped to a shell, base64 decoded into a shell, nc -e),
  or a project that sets ANTHROPIC_BASE_URL (a user-level one is info: people run proxies on purpose);
- medium: any other hook in a project's settings, because opening that folder runs it;
- info: a settings file that couldn't be read, so it wasn't checked.
A plain hook in the user's own settings isn't reported: it's the user's.

Read-only, local, standard library only.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

KNOWN_MALWARE = ("router_init", "tanstack_runner", "token-monitor", "gh-token-monitor", "shai-hulud")
FETCH_AND_RUN = re.compile(
    r"(curl|wget)\b[^|;&]*\|\s*(ba|z|da)?sh\b"          # curl ... | sh
    r"|base64\s+(-d|--decode)[^|;&]*\|\s*(ba|z|da)?sh\b"  # base64 -d ... | bash
    r"|\b(ba|z)?sh\s+-c\s+[\"']?\$\((curl|wget)\b"     # bash -c "$(curl ...)"
    r"|\bnc\b[^|;&]*\s-e\s",                             # nc ... -e
    re.IGNORECASE)
PROJECT_FILES = (Path(".claude") / "settings.json", Path(".claude") / "settings.local.json")
WALK_DEPTH = 4
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".cache", "Library", ".Trash"}


def user_files(home: Path) -> list:
    """(path, scope) for user-level and managed settings files that exist."""
    files = [(home / ".claude" / "settings.json", "user"), (home / ".claude" / "settings.local.json", "user"),
             (Path("/etc/claude-code/managed-settings.json"), "managed"),
             (Path("/Library/Application Support/ClaudeCode/managed-settings.json"), "managed")]
    return [(p, s) for p, s in files if p.is_file()]


def known_projects(home: Path) -> list:
    """The project folders Claude Code lists in ~/.claude.json that still exist; [] when it can't be read."""
    claude = home / ".claude.json"
    if not claude.is_file():
        return []
    try:
        return [p for p in (json.loads(claude.read_text()).get("projects") or {}) if Path(p).is_dir()]
    except (OSError, ValueError, AttributeError):
        return []


def project_files(home: Path, extra_roots=()) -> list:
    """(path, "project") for .claude/settings*.json in Claude Code's known projects and up to WALK_DEPTH folders under
    home. Home itself is the user level, not a project."""
    roots = set(Path(r) for r in extra_roots)
    for root, dirs, _files in os.walk(str(home)):
        if len(Path(root).relative_to(home).parts) >= WALK_DEPTH:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        if any((Path(root) / f).is_file() for f in PROJECT_FILES):
            roots.add(Path(root))
    roots.discard(home)
    return [(r / f, "project") for r in sorted(roots) for f in PROJECT_FILES if (r / f).is_file()]


def hook_commands(data) -> list:
    """(event, command) for every command hook in a settings dict."""
    out = []
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return out
    for event, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            for hook in (group.get("hooks") or []) if isinstance(group, dict) else []:
                if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                    out.append((event, hook["command"]))
    return out


def judge_hook(command: str, scope: str):
    """(severity, why) for one hook command, or (None, "") when it isn't reported."""
    low = command.lower()
    if any(m in low for m in KNOWN_MALWARE):
        return "critical", "names known malware"
    if FETCH_AND_RUN.search(command):
        return "high", "downloads and runs code each time it fires"
    if scope == "project":
        return "medium", "comes with this project folder and runs when Claude Code works in it"
    return None, ""


def check_claude_settings(finding, home: Path = None) -> list:
    """Findings for Claude Code settings files; `finding(severity, title, description, remediation, details)`."""
    home = home or Path.home()
    out, seen = [], set()
    for path, scope in user_files(home) + project_files(home, known_projects(home)):
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        try:
            data = json.loads(path.read_text(errors="replace"))
        except (OSError, ValueError) as e:
            out.append(finding("info", "Claude Code settings not checked: %s" % path,
                               "Sereno couldn't read it (%s), so its hooks weren't checked." % type(e).__name__,
                               "Check that the file is valid JSON.", {"path": str(path)}))
            continue
        for event, command in hook_commands(data):
            severity, why = judge_hook(command, scope)
            if severity:
                out.append(finding(
                    severity, "Claude Code hook (%s, %s): %s" % (scope, event, why),
                    "%s has a %s hook that %s. Command: %s" % (path, event, why, command[:160]),
                    ("Remove the hook from %s unless you put it there on purpose." % path if severity != "medium"
                     else "Read the command before you work in this folder with Claude Code, and remove the hook "
                          "if you don't recognise it."),
                    {"path": str(path), "scope": scope, "event": event, "command": command}))
        env = data.get("env") if isinstance(data, dict) and isinstance(data.get("env"), dict) else {}
        base = env.get("ANTHROPIC_BASE_URL")
        if isinstance(base, str) and base:
            project = scope == "project"
            out.append(finding(
                "high" if project else "info",
                "Claude Code sends its API traffic elsewhere (%s settings)" % scope,
                ("%s sets ANTHROPIC_BASE_URL to %s, so Claude Code's requests, and your API key with them, go "
                 "there.%s" % (path, base, " It comes with this project folder: that's how CVE-2026-21852 "
                                           "collected keys." if project else "")),
                ("Remove it from %s unless you chose that endpoint yourself." % path),
                {"path": str(path), "scope": scope, "base_url": base}))
    return out
