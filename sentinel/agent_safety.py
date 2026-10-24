"""AI coding agents set to skip their own safety prompts, and agent logins left exposed (2026-10-24).

Claude Code, Codex and Gemini CLI ask before they run a command or change a file. Each can be told not to ask, in a
settings file, a shell alias or a launch flag. People do that on purpose, and it's their call. But an agent that never
asks will also act on a prompt hidden in a file it reads, and the s1ngularity/Nx malware (2025-08-26) drove installed
agents with exactly these skip flags. A project folder can also carry settings that switch prompts off for whoever
works in it. And the agents' logins are worth stealing: a CLAUDE_CODE_OAUTH_TOKEN stays valid for a year.

What's reported:
- medium (advice): prompts turned off in your own settings or shell files, with what that means and how to turn the
  prompt back on. An administrator's managed settings count as advice too, and so does a project's
  .claude/settings.local.json that git doesn't track, because Claude Code treats that file as yours.
- high: a project folder's Claude Code settings that switch prompts off (a repo someone else wrote can do this); an
  agent login file that other accounts can read; an agent API key or token written into a shell startup file or into
  your Claude Code settings.
- info: an agent credential set in the environment Sereno runs in (that's how people run agents); a short value that
  looks like a placeholder; a file Sereno couldn't read, so it wasn't checked.

A secret's value never goes into a finding: variables are named, never shown, and shell lines aren't quoted. Login
files are never opened; only their permissions are read. Read-only, local, standard library only.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from .claude_settings import known_projects, project_files
from .mcp import _git_tracked, strip_jsonc
from .redact import redact

# Agent credentials people put in shell files. Claude Code reads the first three (the OAuth token that
# `claude setup-token` prints is valid for a year), Codex the fourth, Gemini CLI the fifth.
CRED_VARS = ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GEMINI_API_KEY")
SHELL_FILES = (".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".profile", ".zshrc", ".zprofile", ".zshenv",
               ".config/fish/config.fish")
# fish keeps more config in conf.d, and its `alias --save` and `funcsave` write to functions/
FISH_DIRS = (".config/fish/conf.d", ".config/fish/functions")
MANAGED_FILES = (Path("/etc/claude-code/managed-settings.json"),
                 Path("/Library/Application Support/ClaudeCode/managed-settings.json"))
VSCODE_FILES = (Path(".config") / "Code" / "User" / "settings.json",
                Path("Library") / "Application Support" / "Code" / "User" / "settings.json")
# VS Code's switch that approves every agent tool call; chat.tools.autoApprove is its older name.
VSCODE_AUTO_APPROVE = ("chat.tools.global.autoApprove", "chat.tools.autoApprove")
# Gemini CLI can't be put in YOLO mode from a settings file: its code ignores general.defaultApprovalMode = "yolo", and
# only --yolo, -y or --approval-mode=yolo turn it on (packages/cli/src/config/config.ts, read 2026-10-24).
# tools.autoAccept covers read-only tools only. What settings can do is let shell commands skip the confirmation
# through tools.allowed, where a bare tool name, or its class name ShellTool, matches every command
# (doesToolInvocationMatch in packages/core/src/utils/tool-utils.ts). Narrow on purpose: an entry naming a command is
# someone's chosen list.
GEMINI_SHELL_TOOLS = ("run_shell_command", "ShellTool")
# A Claude Code permissions.allow rule that lets every shell command through: a bare tool name or a lone wildcard. The
# docs say `Bash(*)` equals `Bash`, `:*` is a trailing wildcard, and PowerShell rules work the same way; "Shell" is in
# the settings reference's own example. A rule naming a command isn't reported.
BROAD_SHELL_RULE = re.compile(r"^\s*(?:Bash|Shell|PowerShell)\s*(?:\(\s*:?\*\s*\)|\s\*)?\s*$")
# Launch flags that switch an agent's prompts off. The Claude and Codex long flags are their own; --yolo, -y and the
# mode flags count only after the agent's name, in the same command.
AGENT_FLAGS = (
    ("claude", "--dangerously-skip-permissions", re.compile(r"(?<![\w-])--dangerously-skip-permissions(?![\w-])")),
    ("claude", "--permission-mode bypassPermissions",
     re.compile(r"(?<![\w-])--(?:permission-)?mode(?:=|\s+)[\"']?bypassPermissions\b")),
    ("codex", "--dangerously-bypass-approvals-and-sandbox",
     re.compile(r"(?<![\w-])--dangerously-bypass-approvals-and-sandbox(?![\w-])")),
    ("codex", "--yolo", re.compile(r"\bcodex\b[^;&|]*?(?<![\w-])--yolo(?![\w-])")),
    ("gemini", "--yolo", re.compile(r"\bgemini\b[^;&|]*?(?<![\w-])--yolo(?![\w-])")),
    ("gemini", "-y", re.compile(r"\bgemini\b[^;&|]*?(?<![\w-])-y(?![\w-])")),
    ("gemini", "--approval-mode yolo", re.compile(r"\bgemini\b[^;&|]*?(?<![\w-])--approval-mode(?:=|\s+)[\"']?yolo\b")),
)
# Codex never asking AND running without a sandbox, given as two flags (either alone keeps a safeguard)
CODEX_NEVER = re.compile(r"\bcodex\b[^;&|]*?(?<![\w-])(?:-a|--ask-for-approval)(?:=|\s+)[\"']?never\b")
CODEX_NO_SANDBOX = re.compile(r"\bcodex\b[^;&|]*?(?<![\w-])(?:-s|--sandbox)(?:=|\s+)[\"']?danger-full-access\b")
ALIAS_NAME = re.compile(r"^\s*(?:alias\s+(?:-\w+\s+)*([\w.:+-]+)|function\s+([\w.:+-]+)|([\w.:+-]+)\s*\(\s*\))")


# ── Reading files ──

def _read(path: Path):
    """The file's text, or None when it isn't there. Raises OSError when it's there but can't be read."""
    try:
        return path.read_text(errors="replace")
    except (FileNotFoundError, NotADirectoryError):
        return None


def _not_checked(finding, path: Path, error: Exception, what: str):
    return finding("info", "Couldn't read %s, so it wasn't checked" % path,
                   "Sereno couldn't read it (%s), so %s weren't checked. That's not the same as clean."
                   % (type(error).__name__, what),
                   "Check that the file is valid and that you can read it.", {"path": str(path)})


def _config_dirs(default: Path, override) -> list:
    """The agent's config folder, plus the one its environment variable points to (CLAUDE_CONFIG_DIR, CODEX_HOME)."""
    return [default] + ([Path(override).expanduser()] if override else [])


# ── Claude Code settings ──

def claude_prompts_off(data, scope: str) -> list:
    """(setting, what it does, how to turn the prompt back on) for each setting in a Claude Code settings dict that
    turns a safety prompt off. scope is "user", "managed", "project" (a shared .claude/settings.json) or "local" (a
    project's .claude/settings.local.json)."""
    if not isinstance(data, dict):
        return []
    in_project = scope in ("project", "local")
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    out = []
    if perms.get("defaultMode") == "bypassPermissions":
        out.append(('permissions.defaultMode "bypassPermissions"',
                    "every session starts in bypass mode, which runs commands, edits files and uses tools without "
                    "asking" + (" (Claude Code 2.1.257 and later ignore this in a project's files; earlier versions "
                                "honor it)" if in_project else ""),
                    'set "defaultMode" to "default" (or remove it)'))
    # Claude Code ignores this key in a shared project file (settings reference, scope "User, local, or managed")
    if data.get("skipDangerousModePermissionPrompt") is True and scope != "project":
        out.append(("skipDangerousModePermissionPrompt",
                    "Claude Code doesn't warn you before it switches to bypass mode",
                    'remove "skipDangerousModePermissionPrompt", and Claude Code warns you again'))
    if data.get("enableAllProjectMcpServers") is True:
        out.append(("enableAllProjectMcpServers",
                    "every MCP server a project's .mcp.json lists is approved without asking, so a repository you "
                    "clone can start a program on your machine",
                    'remove "enableAllProjectMcpServers", and approve the servers you want by name in '
                    '"enabledMcpjsonServers"'))
    allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
    broad = [r for r in allow if isinstance(r, str) and BROAD_SHELL_RULE.match(r)]
    if broad:
        out.append(("permissions.allow " + ", ".join('"%s"' % r for r in broad),
                    "any shell command runs without asking" + (" once you trust the folder" if scope == "project"
                                                               else ""),
                    "replace %s with rules for the commands you mean, such as \"Bash(npm run test *)\""
                    % ", ".join('"%s"' % r for r in broad)))
    return out


def _claude_files(home: Path, environ) -> list:
    """(path, scope) for every Claude Code settings file to read: yours (in ~/.claude and $CLAUDE_CONFIG_DIR), managed,
    and the project ones the persistence check finds (sentinel/claude_settings.py)."""
    files = []
    for d in _config_dirs(home / ".claude", environ.get("CLAUDE_CONFIG_DIR")):
        files += [(d / "settings.json", "user"), (d / "settings.local.json", "user")]
    files += [(p, "managed") for p in MANAGED_FILES]
    files += [(p, "project" if p.name == "settings.json" else "local")
              for p, _ in project_files(home, known_projects(home))]
    return files


def _claude_finding(finding, path: Path, scope: str, items: list):
    what = "; ".join("%s: %s" % (setting, does) for setting, does, _ in items)
    fixes = "; ".join(fix for _, _, fix in items)
    settings = [setting for setting, _, _ in items]
    details = {"path": str(path), "scope": scope, "settings": settings}
    root = path.parent.parent
    # skipDangerousModePermissionPrompt alone removes only the warning before bypass mode, not a prompt
    removes = any(s != "skipDangerousModePermissionPrompt" for s in settings)
    off = "safety prompts" if removes else "warning before bypass mode"
    hidden_act = ("You may have chosen this. It also means a prompt hidden in a file Claude reads can act without you "
                  "seeing it first." if removes else
                  "You may have chosen this. On its own it removes only that warning: it matters when Claude Code is "
                  "started in bypass mode (claude --dangerously-skip-permissions).")
    undo = "To undo, put the old lines back."
    tracked = None
    if scope == "local":
        # Claude Code treats an untracked settings.local.json as the user's own and a tracked one as the repository's
        tracked = _git_tracked(path)
        details["git_tracked"] = tracked
    if scope == "user":
        return finding("medium", "Claude Code %s turned off in your settings" % off,
                       "%s turns off Claude Code's %s. %s. %s" % (path, off, what, hidden_act),
                       "To turn it back on, edit %s: %s. %s" % (path, fixes, undo), details)
    if scope == "managed":
        return finding("medium", "Claude Code %s turned off by managed settings" % off,
                       "%s, installed by whoever administers this machine, turns off Claude Code's %s for every "
                       "account on it. %s." % (path, off, what),
                       "If you administer this machine, edit %s with sudo: %s. Otherwise ask whoever does. %s"
                       % (path, fixes, undo), details)
    if scope == "local" and tracked is False:
        return finding("medium", "Claude Code %s turned off for one project: %s" % (off, root),
                       "%s turns off Claude Code's %s in this project. %s. Git doesn't track the file, so Claude Code "
                       "treats it as yours, and so does Sereno. If you didn't write it, treat it as the project's. %s"
                       % (path, off, what, hidden_act),
                       "To turn it back on, edit %s: %s. %s" % (path, fixes, undo), details)
    why = ("A repository someone else wrote can do this to you; if this one is yours, it does it to everyone who "
           "clones it.")
    if scope == "local":
        why += (" Git tracks this settings.local.json, so it came with the repository." if tracked else
                " Sereno couldn't ask git whether this settings.local.json came with the repository, so it's treated "
                "as if it did.")
    return finding("high", "A project folder switches off Claude Code's %s: %s" % (off, root),
                   "%s is part of the project in %s and turns off Claude Code's %s for whoever runs it there. %s. %s"
                   % (path, root, off, what, why),
                   "Read %s before you run Claude Code in %s. If you didn't put these lines there, remove them. If "
                   "they're yours, keep them only in %s, out of git. %s"
                   % (path, root, root / ".claude" / "settings.local.json", undo), details)


def _claude_findings(finding, home: Path, environ) -> list:
    out, seen = [], set()
    for path, scope in _claude_files(home, environ):
        real = os.path.realpath(str(path))
        if real in seen:
            continue
        seen.add(real)
        try:
            text = _read(path)
            if text is None:
                continue
            data = json.loads(text)
        except (OSError, ValueError) as e:
            out.append(_not_checked(finding, path, e, "its permission settings"))
            continue
        items = claude_prompts_off(data, scope)
        if items:
            out.append(_claude_finding(finding, path, scope, items))
        if scope == "user" and isinstance(data, dict) and isinstance(data.get("env"), dict):
            # Claude Code reads CLAUDE_CODE_OAUTH_TOKEN and the API keys from a settings file's env block too
            for name in CRED_VARS:
                value = data["env"].get(name)
                f = _credential_finding(finding, name, value, path, None) if isinstance(value, str) else None
                if f:
                    out.append(f)
    return out


# ── Codex ──

def _key_parts(key: str) -> list:
    """A TOML key or table name split on its dots, quotes removed: profiles."my.box" -> ["profiles", "my.box"]."""
    return [p.strip().strip("\"'") for p in re.findall(r"\"[^\"]*\"|'[^']*'|[^.]+", key) if p.strip()]


def _toml_value(raw: str) -> str:
    """A TOML string's contents; anything else as written, without a trailing comment."""
    m = re.match(r"^\"((?:[^\"\\]|\\.)*)\"|^'([^']*)'", raw)
    if m:
        return m.group(1) if m.group(1) is not None else m.group(2)
    return raw.split("#", 1)[0].strip()


def toml_tables(text: str) -> dict:
    """{table name: {key: value}} from a TOML file's `key = value` lines, "" being the top level. Enough to read
    Codex's approval_policy and sandbox_mode without tomllib, which is Python 3.11+. Table headers and dotted keys are
    followed; the inside of a multi-line string or array is skipped; inline tables and arrays aren't read."""
    tables, current, open_quote, depth = {"": {}}, "", None, 0
    for raw in text.splitlines():
        line = raw.strip()
        if open_quote:
            if open_quote in line:
                open_quote = None
            continue
        if depth > 0:  # inside a multi-line array, where a line like ["x"] isn't a table header
            depth += line.count("[") - line.count("]")
            continue
        if not line or line.startswith("#"):
            continue
        header = re.match(r"^\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(?:#.*)?$", line)
        if header:
            current = ".".join(_key_parts(header.group(1)))
            tables.setdefault(current, {})
            continue
        pair = re.match(r"^((?:[\w-]+|\"[^\"]*\"|'[^']*')(?:\s*\.\s*(?:[\w-]+|\"[^\"]*\"|'[^']*'))*)\s*=\s*(.*)$", line)
        if not pair:
            continue
        parts, value = _key_parts(pair.group(1)), pair.group(2).strip()
        for quote in ('"""', "'''"):
            if value.startswith(quote) and value.count(quote) == 1:
                open_quote = quote
        if value.startswith("["):
            depth = max(0, value.count("[") - value.count("]"))
        table = ".".join(p for p in [current] + parts[:-1] if p)
        tables.setdefault(table, {})[parts[-1]] = _toml_value(value)
    return tables


def codex_unasked_unsandboxed(tables: dict) -> list:
    """Where Codex never asks and has no sandbox: "" for the top level, else a profile's name. A profile counts with
    its own values over the top level's, and only when it sets one of the two itself."""
    top = tables.get("", {})

    def risky(t):
        return (t.get("approval_policy", top.get("approval_policy")) == "never"
                and t.get("sandbox_mode", top.get("sandbox_mode")) == "danger-full-access")
    out = [""] if risky(top) else []
    for name in sorted(tables):
        t = tables[name]
        if name.startswith("profiles.") and ("approval_policy" in t or "sandbox_mode" in t) and risky(t):
            out.append(name[len("profiles."):])
    return out


def _codex_findings(finding, home: Path, environ) -> list:
    out, seen = [], set()
    for d in _config_dirs(home / ".codex", environ.get("CODEX_HOME")):
        path = d / "config.toml"
        real = os.path.realpath(str(path))
        if real in seen:
            continue
        seen.add(real)
        try:
            text = _read(path)
        except OSError as e:
            out.append(_not_checked(finding, path, e, "its approval settings"))
            continue
        if text is None:
            continue
        for profile in codex_unasked_unsandboxed(toml_tables(text)):
            which = ' for the profile "%s" (codex --profile %s)' % (profile, profile) if profile else ""
            out.append(finding(
                "medium",
                "Codex runs commands without asking and without a sandbox (your config%s)"
                % (', profile "%s"' % profile if profile else ""),
                ('%s sets approval_policy = "never" with sandbox_mode = "danger-full-access"%s, so Codex runs any '
                 "command, with full access to your files and the network, without asking you. You may have chosen "
                 "this. It also means a prompt hidden in a file Codex reads can act without you seeing it first."
                 % (path, which)),
                ('To turn the prompt back on, set approval_policy = "on-request"%s in %s. Or keep it and set '
                 'sandbox_mode = "workspace-write", which keeps Codex inside your project folder. To undo, set them '
                 "back." % (" under [profiles.%s]" % profile if profile else "", path)),
                {"path": str(path), "profile": profile or None}))
    return out


# ── Gemini CLI and VS Code ──

def gemini_shell_allowed(data) -> list:
    """The tools.allowed entries in Gemini CLI settings that let every shell command run without a confirmation."""
    tools = data.get("tools") if isinstance(data, dict) and isinstance(data.get("tools"), dict) else {}
    allowed = tools.get("allowed") if isinstance(tools.get("allowed"), list) else []
    return [r for r in allowed if isinstance(r, str) and r.strip() in GEMINI_SHELL_TOOLS]


def _json_settings(finding, path: Path, what: str):
    """(data, None) for a JSON settings file that may hold comments, (None, None) when it isn't there, or
    (None, an info finding) when it can't be read or parsed. Comments are stripped outside strings only (mcp.py)."""
    try:
        text = _read(path)
        if text is None:
            return None, None
        return json.loads(strip_jsonc(text)), None
    except (OSError, ValueError) as e:
        return None, _not_checked(finding, path, e, what)


def _gemini_findings(finding, home: Path) -> list:
    path = home / ".gemini" / "settings.json"
    data, problem = _json_settings(finding, path, "its tool approvals")
    if problem:
        return [problem]
    rules = gemini_shell_allowed(data)
    if not rules:
        return []
    listed = ", ".join('"%s"' % r for r in rules)
    return [finding("medium", "Gemini CLI runs every shell command without asking (your settings)",
                    "%s lists %s under tools.allowed, so Gemini CLI runs any shell command without asking you. You may "
                    "have chosen this. It also means a prompt hidden in a file Gemini reads can act without you seeing "
                    "it first." % (path, listed),
                    'To get the prompt back, remove %s from tools.allowed in %s, or list only the commands you mean, '
                    'such as "run_shell_command(git status)". To undo, put it back.' % (listed, path),
                    {"path": str(path), "rules": rules})]


def _vscode_findings(finding, home: Path) -> list:
    out = []
    for rel in VSCODE_FILES:
        path = home / rel
        data, problem = _json_settings(finding, path, "its agent approval settings")
        if problem:
            out.append(problem)
            continue
        keys = [k for k in VSCODE_AUTO_APPROVE if isinstance(data, dict) and data.get(k) is True]
        if keys:
            out.append(finding(
                "medium", "VS Code approves every agent tool call without asking (your settings)",
                "%s sets %s to true, so the chat agent runs commands, edits files and uses tools without asking you. "
                "You may have chosen this. It also means a prompt hidden in a file the agent reads can act without "
                "you seeing it first." % (path, " and ".join(keys)),
                'To get the prompts back, set %s to false in %s (in VS Code: Settings, search "auto approve"). To '
                "undo, set it back to true." % (" and ".join(keys), path),
                {"path": str(path), "settings": keys}))
    return out


# ── Shell startup files: skip flags and credentials ──

def _logical_lines(text: str) -> list:
    """(first line number, text) with lines ending in a backslash joined to the next, as the shell reads them."""
    out, buf, start = [], [], 0
    for n, line in enumerate(text.splitlines(), 1):
        if not buf:
            start = n
        if line.endswith("\\"):
            buf.append(line[:-1])
            continue
        buf.append(line)
        out.append((start, " ".join(buf)))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def _code(line: str) -> str:
    """A shell or fish line without its comment: from a # that starts a word, outside quotes."""
    quote, i = None, 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
        i += 1
    return line


def skip_flags(code: str) -> list:
    """(agent, flag) for each launch flag in one shell line that switches an agent's prompts off."""
    found = [(agent, flag) for agent, flag, pattern in AGENT_FLAGS if pattern.search(code)]
    if CODEX_NEVER.search(code) and CODEX_NO_SANDBOX.search(code):
        found.append(("codex", "--ask-for-approval never with --sandbox danger-full-access"))
    return found


def credential_assignments(code: str) -> list:
    """(variable, value as written) for each assignment to an agent credential variable in one shell or fish line:
    NAME=value (with or without export, or as ${NAME=value}), and fish's set -gx NAME value. $NAME=... isn't one."""
    out = []
    for name in CRED_VARS:
        for m in re.finditer(r"(?<![\w$])%s=(\"[^\"]*\"|'[^']*'|[^\s;&|)}`'\"]*)" % name, code):
            out.append((name, m.group(1)))
        for m in re.finditer(r"\bset\s+(?:--?[A-Za-z-]+\s+)*%s\b(?:\s+(\"[^\"]*\"|'[^']*'|[^\s;&|]+))?" % name, code):
            out.append((name, m.group(1) or ""))
    return out


def _literal(value: str) -> str:
    """The value as written when it's a literal; "" when it's empty or comes from somewhere else: a variable, or a
    command's output ($(...), backticks, or fish's (...))."""
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    if not v or "$" in v or "`" in v or v.startswith("("):
        return ""
    return v


def _looks_like_key(value: str) -> bool:
    """A real key or token rather than a placeholder such as "ollama", which local model servers ask for: 20 characters
    or more, or shaped like a known token (sentinel/redact.py). Every agent key format Sereno knows is longer."""
    return len(value) >= 20 or redact(value) != value


def _credential_finding(finding, name: str, value: str, path: Path, line):
    """A finding for a credential variable assigned in a file, or None when the value isn't a literal. The value never
    goes into the finding."""
    if not _literal(value):
        return None
    where = "%s:%d" % (path, line) if line else str(path)
    details = {"path": str(path), "line": line, "variable": name}
    if not _looks_like_key(_literal(value)):
        return finding("info", "Agent credential variable set to a short value: %s (%s)" % (name, where),
                       "%s is set to a short value in %s. It looks like a placeholder rather than a key (local model "
                       "servers often want one), so it isn't counted as an issue. Sereno doesn't show it."
                       % (name, where),
                       "If it's a real key, move it out of the file and replace it.", details)
    try:
        mode = stat.S_IMODE(os.stat(str(path)).st_mode)
    except OSError:
        mode = 0
    others = (" Other accounts on this machine can read %s too (mode %03o)." % (path, mode)) if mode & 0o044 else ""
    year = " This token stays valid for a year." if name == "CLAUDE_CODE_OAUTH_TOKEN" else ""
    return finding("high", "Agent credential written in a file: %s (%s)" % (name, where),
                   "%s is set to a literal value in %s. Anything that can read the file has it: backups, dotfile "
                   "repositories, and every program you run.%s%s Sereno doesn't show the value."
                   % (name, where, others, year),
                   "Take it out of %s and keep it in your system's keychain or a password manager, loading it when you "
                   'need it (for example export %s="$(secret-tool lookup service %s)" in a shell file). Then revoke '
                   "it where you made it and make a new one, because copies of the file may already hold it. To undo, "
                   "put the line back." % (where, name, name), details)


def _flag_finding(finding, path: Path, lineno: int, code: str, flags: list):
    m = ALIAS_NAME.match(code)
    kind, name = (("alias", m.group(1)) if m and m.group(1) else
                  ("function", m.group(2) or m.group(3)) if m else (None, None))
    shown = ", ".join("%s %s" % f for f in flags)
    agents = " and ".join(sorted(set(agent for agent, _ in flags)))
    where = "%s:%d" % (path, lineno)
    return finding(
        "medium", "AI agent started without its safety prompts: %s (%s)" % (shown, where),
        ("Line %d of %s%s starts %s, so %s runs commands and edits files without asking you. You may have chosen "
         "this. It also means a prompt hidden in a file the agent reads can act without you seeing it first. Sereno "
         "doesn't quote the line, in case it holds a secret."
         % (lineno, path, " (%s %s)" % (kind, name) if name else "", shown, agents)),
        ("To get the prompts back, remove %s from line %d of %s, then open a new terminal. To undo, put it back."
         % (" and ".join(flag for _, flag in flags), lineno, path)),
        {"path": str(path), "line": lineno, "flags": ["%s %s" % f for f in flags], "name": name})


def _shell_files(home: Path) -> list:
    files = [home / f for f in SHELL_FILES]
    for d in FISH_DIRS:
        files += sorted((home / d).glob("*.fish"))
    return files


def _shell_findings(finding, home: Path) -> list:
    out = []
    for path in _shell_files(home):
        try:
            text = _read(path)
        except OSError as e:
            out.append(_not_checked(finding, path, e, "its aliases and variables"))
            continue
        if text is None:
            continue
        for lineno, line in _logical_lines(text):
            code = _code(line)
            flags = skip_flags(code)
            if flags:
                out.append(_flag_finding(finding, path, lineno, code, flags))
            for name, value in credential_assignments(code):
                f = _credential_finding(finding, name, value, path, lineno)
                if f:
                    out.append(f)
    return out


# ── Login files and the environment ──

def _login_files(home: Path, environ) -> list:
    files = [(d / ".credentials.json", "Claude Code")
             for d in _config_dirs(home / ".claude", environ.get("CLAUDE_CONFIG_DIR"))]
    files += [(d / "auth.json", "Codex") for d in _config_dirs(home / ".codex", environ.get("CODEX_HOME"))]
    files.append((home / ".gemini" / "oauth_creds.json", "Gemini CLI"))
    return files


def _login_file_findings(finding, home: Path, environ) -> list:
    """Agent login files that other accounts can read or write. Only their permissions are read, never their
    contents."""
    out, seen = [], set()
    for path, tool in _login_files(home, environ):
        real = os.path.realpath(str(path))
        if real in seen:
            continue
        seen.add(real)
        try:
            mode = stat.S_IMODE(os.stat(str(path)).st_mode)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as e:
            out.append(finding("info", "Couldn't check %s, so it wasn't checked" % path,
                               "Sereno couldn't read its permissions (%s). That's not the same as safe."
                               % type(e).__name__, "", {"path": str(path)}))
            continue
        if mode & 0o077:
            who = "every account on this machine" if mode & 0o007 else "accounts in its group"
            out.append(finding(
                "high", "%s login file open to other accounts: %s (mode %03o)" % (tool, path, mode),
                ("%s holds your %s login. With mode %03o, %s, and programs running as them, can read it and use your "
                 "login. A login file should be readable by you only (mode 600)." % (path, tool, mode, who)),
                ("Run: chmod 600 %s. %s keeps working. To undo: chmod %03o %s." % (path, tool, mode, path)),
                {"path": str(path), "tool": tool, "mode": "%03o" % mode}))
    return out


def _environment_findings(finding, environ) -> list:
    present = [name for name in CRED_VARS if environ.get(name)]
    if not present:
        return []
    return [finding("info", "Agent credentials in Sereno's environment: %s" % ", ".join(present),
                    "%s %s set in the environment Sereno was started from. That's a normal way to run AI agents. It "
                    "means every program started from that shell can read %s. Sereno didn't look at the value%s."
                    % (", ".join(present), "is" if len(present) == 1 else "are", "it" if len(present) == 1 else "them",
                       "" if len(present) == 1 else "s"),
                    "", {"variables": present})]


# ── The check ──

def check_agent_safety(finding, home: Path = None, environ=None) -> list:
    """Findings for AI agents set to skip their safety prompts and for agent logins left exposed. `finding(severity,
    title, description, remediation, details)` builds one (the scanner passes it, as for mcp.py). environ defaults to
    os.environ; it's where CLAUDE_CONFIG_DIR, CODEX_HOME and the credential variables are looked up."""
    home = home or Path.home()
    environ = os.environ if environ is None else environ
    return (_claude_findings(finding, home, environ) + _codex_findings(finding, home, environ)
            + _gemini_findings(finding, home) + _vscode_findings(finding, home) + _shell_findings(finding, home)
            + _login_file_findings(finding, home, environ) + _environment_findings(finding, environ))
