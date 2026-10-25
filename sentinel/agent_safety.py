"""AI coding agents set to skip their own safety prompts, and agent logins left exposed (2026-10-24).

Claude Code, Codex and Gemini CLI ask before they run a command or change a file. Each can be told not to ask, in a
settings file, a shell alias or a launch flag. People do that on purpose, and it's their call. But an agent that never
asks will also act on a prompt hidden in a file it reads, and the s1ngularity/Nx malware (2025-08-26) drove installed
agents with exactly these skip flags. A project folder can also carry settings that switch prompts off for whoever
works in it. And the agents' logins are worth stealing: a CLAUDE_CODE_OAUTH_TOKEN stays valid for a year.

What's reported:
- medium (advice): prompts turned off in your own settings or shell files, with what that means and how to turn the
  prompt back on. An administrator's managed settings count as advice too, and so does a project's
  .claude/settings.local.json that git says it doesn't track, because that's where Claude Code saves your "don't ask
  again" answers.
- high: a project folder's Claude Code settings that switch prompts off (a repo someone else wrote can do this),
  including a settings.local.json git can't vouch for (the folder isn't a repository, as a download isn't); an agent
  login file that other accounts can read; an agent API key or token written into a shell startup file or into your
  Claude Code settings.
- info: an agent credential set in the environment Sereno runs in (that's how people run agents); a value that looks
  like a placeholder; a key left in a commented-out line; a file Sereno couldn't read, so it wasn't checked.

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
from .mcp import git_ls_file, strip_jsonc
from .redact import redact

# Agent credentials people put in shell files. Claude Code reads the first three (the OAuth token that
# `claude setup-token` prints is valid for a year), Codex the fourth, Gemini CLI the fifth.
CRED_VARS = ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GEMINI_API_KEY")
SHELL_FILES = (".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".profile", ".zshrc", ".zprofile", ".zshenv",
               ".config/fish/config.fish")
# Folders whose files the shell reads at startup: fish's conf.d, and functions/ where `alias --save` and `funcsave`
# write; ~/.bashrc.d, whose every file Fedora's .bashrc sources; oh-my-zsh's custom/*.zsh.
SHELL_DIRS = ((".config/fish/conf.d", "*.fish"), (".config/fish/functions", "*.fish"), (".bashrc.d", "*"),
              (".oh-my-zsh/custom", "*.zsh"))
# fish's universal variables (set -U, set -Ux), kept in plain text: SETUVAR [--export] NAME:value, with \xHH escapes
FISH_UNIVERSAL = Path(".config") / "fish" / "fish_variables"
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
# Claude Code permissions.allow rules that let every shell command through. A bare tool name, or nothing but wildcards
# (the docs say `Bash(*)` equals `Bash` and `:*` is a trailing wildcard; "Shell" is in the settings reference's own
# example). Or a program that runs whatever it's given (python3 -c, sh -c, env, xargs), alone or with a wildcard:
# Bash(python3:*) lets any command through as surely as Bash does. The programs are Claude Code's own list (2.1.309:
# the allow rules its auto mode won't trust), compared without case; PowerShell's adds Windows launchers, each also by
# its .exe name. A rule naming a command, such as Bash(git:*) or Bash(npm run test *), isn't reported.
SHELL_RUNNERS = ("python", "python3", "python2", "node", "deno", "tsx", "ruby", "perl", "php", "lua", "npx", "bunx",
                 "npm run", "yarn run", "pnpm run", "bun run", "bash", "sh", "ssh")
BASH_RUNNERS = SHELL_RUNNERS + ("zsh", "fish", "eval", "exec", "env", "xargs", "sudo")
POWERSHELL_RUNNERS = SHELL_RUNNERS + (
    "pwsh", "powershell", "cmd", "wsl", "iex", "invoke-expression", "icm", "invoke-command", "start-process", "saps",
    "start", "start-job", "sajb", "start-threadjob", "invoke-wmimethod", "iwmi", "invoke-cimmethod", "icim", "wmic",
    "register-objectevent", "register-engineevent", "register-wmievent", "register-scheduledjob", "new-pssession",
    "nsn", "enter-pssession", "etsn", "add-type", "new-object")
# PowerShell's rules also count a program by its .exe name (python.exe, npm.exe run)
POWERSHELL_NAMES = POWERSHELL_RUNNERS + tuple(re.sub(r"^(\S+)", r"\1.exe", n) for n in POWERSHELL_RUNNERS)
SHELL_RULE = re.compile(r"^\s*(Bash|Shell|PowerShell)\s*(?:\((.*)\))?\s*$", re.S)


def _command(*names: str) -> str:
    """A regex for one of the names run as a command: at the start of one (after ;, &, |, (, {, ` or alias x=), or
    after a wrapper such as sudo, env or npx, with variable assignments and flags before it; a path to it counts. Not
    another command's argument (conda install gemini -y) or part of a longer name (gemini-api). A word here stops at
    the next ; & | or `, where the next command starts, unless it's quoted (X='a b'), so a long line costs one pass,
    not one per separator."""
    word = r"[^\s;&|`]"
    value = r"""(?:'[^']*'|"[^"]*"|[^\s;&|`'"])*"""
    return (r"(?:^|[;&|({`]|\balias\s+(?:-\w+\s+)*[\w.:+-]+=|"
            r"\b(?:sudo|env|command|exec|nohup|time|nice|then|do|else|npx|pnpx|bunx|dlx)\s)"
            r"\s*(?:[\"']\s*)?(?:(?:\w+=%s|-%s+)\s+)*(?:%s*/)?(?:%s)(?![\w.-])"
            % (value, word, word, "|".join(names)))


CODEX = _command("codex")
GEMINI = _command("gemini", "gemini-cli")   # npx @google/gemini-cli
# Launch flags that switch an agent's prompts off. The Claude and Codex long flags are their own; --yolo, -y and the
# mode flags count only after the agent's name, in the same command.
AGENT_FLAGS = (
    ("claude", "--dangerously-skip-permissions", re.compile(r"(?<![\w-])--dangerously-skip-permissions(?![\w-])")),
    ("claude", "--permission-mode bypassPermissions",
     re.compile(r"(?<![\w-])--(?:permission-)?mode(?:=|\s+)[\"']?bypassPermissions\b")),
    ("codex", "--dangerously-bypass-approvals-and-sandbox",
     re.compile(r"(?<![\w-])--dangerously-bypass-approvals-and-sandbox(?![\w-])")),
    ("codex", "--yolo", re.compile(CODEX + r"[^;&|]*?(?<![\w-])--yolo(?![\w-])")),
    ("gemini", "--yolo", re.compile(GEMINI + r"[^;&|]*?(?<![\w-])--yolo(?![\w-])")),
    ("gemini", "-y", re.compile(GEMINI + r"[^;&|]*?(?<![\w-])-y(?![\w-])")),
    ("gemini", "--approval-mode yolo", re.compile(GEMINI + r"[^;&|]*?(?<![\w-])--approval-mode(?:=|\s+)[\"']?yolo\b")),
)
# Codex never asking AND running without a sandbox, given as two flags (either alone keeps a safeguard), or as -c
# overrides of the config.toml keys (codex -c approval_policy=never)
CODEX_NEVER = re.compile(CODEX + r"[^;&|]*?(?<![\w-])(?:(?:-a|--ask-for-approval)(?:=|\s+)[\"']?|"
                         r"(?:-c|--config)(?:=|\s+)[\"']?approval_policy\s*=\s*[\"']?)never\b")
CODEX_NO_SANDBOX = re.compile(CODEX + r"[^;&|]*?(?<![\w-])(?:(?:-s|--sandbox)(?:=|\s+)[\"']?|"
                              r"(?:-c|--config)(?:=|\s+)[\"']?sandbox_mode\s*=\s*[\"']?)danger-full-access\b")
ALIAS_NAME = re.compile(r"^\s*(?:alias\s+(?:-\w+\s+)*([\w.:+-]+)|function\s+([\w.:+-]+)|([\w.:+-]+)\s*\(\s*\))")
# A long value that's still a placeholder: words joined by _ - or . in one case (your_api_key_here, YOUR-KEY-HERE),
# one character repeated (xxxxxxxx), a <hole>, or an ellipsis
PLACEHOLDER = re.compile(r"^(?:[a-z]+(?:[_.-][a-z]+)+|[A-Z]+(?:[_.-][A-Z]+)+|(.)\1*)$|[<>]|\.\.\.")


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

def broad_shell_rule(rule: str) -> bool:
    """Whether a Claude Code permissions.allow rule lets any shell command through (see SHELL_RUNNERS)."""
    m = SHELL_RULE.match(rule)
    if not m:
        return False
    if m.group(2) is None:
        return True
    bare = re.sub(r"\s+", "", m.group(2))
    if set(bare[:-2] if bare.endswith(":*") else bare) <= {"*"}:   # Bash(), Bash(*), Bash(:*), Bash(**), Bash(*:*)
        return True
    words = m.group(2).strip().lower()
    powershell = m.group(1) == "PowerShell"
    for name in POWERSHELL_NAMES if powershell else BASH_RUNNERS:
        if words in (name, name + ":*", name + " *", name + "*"):
            return True
        # a flag, then a wildcard (python3 -c *, sh -c:*). In a Bash rule, python -m with a dotted module
        # (python3 -m http.server *) names one program, as Claude Code reads it; PowerShell has no such exception
        if words.startswith(name + " -") and words.endswith("*") and (powershell or not (
                re.match(r"python[\d.]*$", name)
                and re.match(r"-m\s+\w+\.[\w.]+(?:\s*:|\s+)$", words[len(name) + 1:-1]))):
            return True
    return False


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
    # Claude Code ignores this key in a shared project file (settings reference, scope "User, local, or managed"). It
    # writes the key to your settings itself when you accept the bypass-mode warning once (2.1.309: "Whether the user
    # has accepted the bypass permissions mode dialog"), so in your own settings it's usually your old answer.
    if data.get("skipDangerousModePermissionPrompt") is True and scope != "project":
        out.append(("skipDangerousModePermissionPrompt",
                    "Claude Code doesn't warn you before it switches to bypass mode"
                    + (" (it saves this when you accept that warning once)" if scope == "user" else ""),
                    'remove "skipDangerousModePermissionPrompt", and Claude Code warns you again'))
    if data.get("enableAllProjectMcpServers") is True:
        out.append(("enableAllProjectMcpServers",
                    "every MCP server a project's .mcp.json lists is approved without asking, so a repository you "
                    "clone can start a program on your machine",
                    'remove "enableAllProjectMcpServers", and approve the servers you want by name in '
                    '"enabledMcpjsonServers"'))
    allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
    broad = [r for r in allow if isinstance(r, str) and broad_shell_rule(r)]
    if broad:
        runner = any(re.search(r"\w", SHELL_RULE.match(r).group(2) or "") for r in broad)   # a program, not a wildcard
        # Claude Code holds a project's allow rules, settings.local.json's included, until you trust the folder
        out.append(("permissions.allow " + ", ".join('"%s"' % r for r in broad),
                    "any shell command runs without asking" + (" once you trust the folder" if in_project else "")
                    + (" (python3, bash, env and the like run whatever they're given)" if runner else ""),
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


def _local_file_in_git(path: Path) -> str:
    """Whether git tracks a project's settings.local.json: "tracked", "untracked", "no repo" (its folder isn't in a git
    repository, like a download or a copied folder), or "unknown" (git refused the repository, failed, or isn't there).
    Only git's own "not tracked" (exit 1) makes it untracked; Claude Code 2.1.309 reads git's answer the same way."""
    answer = git_ls_file(path)
    if answer is None:
        return "unknown"
    code, error = answer
    if code in (0, 1):
        return "tracked" if code == 0 else "untracked"
    return "no repo" if code == 128 and "not a git repository" in error else "unknown"


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
                  # in your own settings, the setting's text already says Claude Code saved your answer there
                  "%sOn its own it removes only that warning: it matters when Claude Code is started in bypass mode "
                  "(claude --dangerously-skip-permissions)."
                  % ("" if scope == "user" else "You may have chosen this. "))
    undo = "To undo, put the old lines back."
    git = None
    if scope == "local":
        # Claude Code saves your "don't ask again" answers in a project's settings.local.json; a tracked one came with
        # the repository, and one git can't vouch for may have come with the folder
        git = _local_file_in_git(path)
        details["git_tracked"] = {"tracked": True, "untracked": False}.get(git)
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
    if git == "untracked":
        return finding("medium", "Claude Code %s turned off for one project: %s" % (off, root),
                       "%s turns off Claude Code's %s in this project. %s. Git doesn't track the file, so it's most "
                       "likely yours (Claude Code saves your \"don't ask again\" answers there), and Sereno treats it "
                       "as yours. If you didn't write it, treat it as the project's. %s"
                       % (path, off, what, hidden_act),
                       "To turn it back on, edit %s: %s. %s" % (path, fixes, undo), details)
    why = ("A repository someone else wrote can do this to you; if this one is yours, it does it to everyone who "
           "clones it.")
    keep = "If they're yours, keep them only in %s, out of git." % (root / ".claude" / "settings.local.json")
    if git == "tracked":
        why += " Git tracks this settings.local.json, so it came with the repository."
        keep = ("If they're yours, stop tracking the file so it stays on your machine: git -C %s rm --cached "
                ".claude/settings.local.json (to undo: git add it again)." % root)
    elif git:
        why += (" The folder isn't in a git repository, so Sereno can't tell whether you wrote this "
                "settings.local.json or it came with the folder (a download or a copied folder brings it along); "
                "it's treated as if it came with the folder." if git == "no repo" else
                " Sereno couldn't ask git whether this settings.local.json came with the repository, so it's treated "
                "as if it did.")
        keep = "If you wrote them yourself, they're yours to keep: Sereno can't tell that from git."
    return finding("high", "A project folder switches off Claude Code's %s: %s" % (off, root),
                   "%s is part of the project in %s and turns off Claude Code's %s for whoever runs it there. %s. %s"
                   % (path, root, off, what, why),
                   "Read %s before you run Claude Code in %s. If you didn't put these lines there, remove them. %s %s"
                   % (path, root, keep, undo), details)


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
        except (OSError, ValueError, RecursionError) as e:   # RecursionError: JSON nested too deep to parse
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
    except (OSError, ValueError, RecursionError) as e:
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
    r"""(first line number, text) with a line ending in a backslash joined to the next, the backslash and the line break
    removed, as the shell reads them. A backslash that is escaped (\\) or sits in a comment doesn't continue a line.
    Each line is read once, carrying the open quote over, so a long run of continued lines costs one pass."""
    out, parts, start, quote, before = [], [], 0, None, " "
    for n, line in enumerate(text.splitlines(), 1):
        if not parts:
            start, quote, before = n, None, " "
        comment, quote = _scan(line, quote, before)
        if comment is None and (len(line) - len(line.rstrip("\\"))) % 2:
            line = line[:-1]
            parts.append(line)
            before = line[-1] if line else before
            continue
        parts.append(line)
        out.append((start, "".join(parts)))
        parts = []
    if parts:
        out.append((start, "".join(parts)))
    return out


def _scan(line: str, quote=None, before: str = " "):
    r"""Read one shell or fish line: (where its comment starts, or None; the quote still open at its end). A comment
    starts at a # that starts a word, outside quotes. Outside quotes a backslash escapes the next character, so \'
    doesn't open a quote and \# doesn't start a comment. For a line continued from the one before, quote is the quote
    open where it starts and before is the character just before it."""
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = None
        elif c == "\\":
            i += 1
        elif c in "\"'":
            quote = c
        elif c == "#" and (line[i - 1] if i else before).isspace():
            return i, quote
        i += 1
    return None, quote


def _code(line: str) -> str:
    """A shell or fish line without its comment (see _scan)."""
    comment, _ = _scan(line)
    return line if comment is None else line[:comment]


def skip_flags(code: str) -> list:
    """(agent, flag) for each launch flag in one shell line that switches an agent's prompts off."""
    found = [(agent, flag) for agent, flag, pattern in AGENT_FLAGS if pattern.search(code)]
    if CODEX_NEVER.search(code) and CODEX_NO_SANDBOX.search(code):
        found.append(("codex", "--ask-for-approval never with --sandbox danger-full-access"))
    return found


def credential_assignments(code: str) -> list:
    """(variable, value as written) for each assignment to an agent credential variable in one shell or fish line:
    NAME=value (with or without export, or as ${NAME=value}), and fish's set -gx NAME value. $NAME=... isn't one. A
    default in ${NAME:-value} or ${NAME:=value} counts when it looks like a key: it's written in the file all the same
    (and ${NAME:-unset} is only a word to print)."""
    out = []
    for name in CRED_VARS:
        for m in re.finditer(r"(?<![\w$])%s=(\"[^\"]*\"|'[^']*'|[^\s;&|)}`'\"]*)" % name, code):
            out.append((name, m.group(1)))
        for m in re.finditer(r"\$\{%s(?::?-|:=)([^}]*)\}" % name, code):
            if _looks_like_key(_literal(m.group(1))):
                out.append((name, m.group(1)))
        for m in re.finditer(r"\bset\s+(?:-\S*\s+)*%s\b(?:\s+(\"[^\"]*\"|'[^']*'|[^\s;&|]+))?" % name, code):
            out.append((name, m.group(1) or ""))
    return out


def fish_universal(text: str) -> list:
    """(line number, variable, value) for each agent credential in fish's fish_variables file."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r"SETUVAR\s+(?:--export\s+)?(\w+):(.*)$", line)
        if m and m.group(1) in CRED_VARS:
            out.append((n, m.group(1), re.sub(r"\\x([0-9a-fA-F]{2})", lambda h: chr(int(h.group(1), 16)), m.group(2))))
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
    """A real key or token rather than a placeholder: shaped like a known token (sentinel/redact.py), or 20 characters
    or more that aren't a placeholder like your_api_key_here (PLACEHOLDER). A short value such as "ollama", which local
    model servers ask for, isn't one; every agent key format Sereno knows is longer."""
    if redact(value) != value:
        return True
    return len(value) >= 20 and not PLACEHOLDER.search(value)


def _credential_finding(finding, name: str, value: str, path: Path, line, remove: str = None):
    """A finding for a credential variable assigned in a file, or None when the value isn't a literal. The value never
    goes into the finding. remove is how to take it out, when that's more than editing the line."""
    if not _literal(value):
        return None
    where = "%s:%d" % (path, line) if line else str(path)
    details = {"path": str(path), "line": line, "variable": name}
    if not _looks_like_key(_literal(value)):
        return finding("info", "Agent credential variable set to a placeholder: %s (%s)" % (name, where),
                       "%s is set in %s to a value that looks like a placeholder rather than a key (short, or words "
                       "like your_key_here; local model servers often want one), so it isn't counted as an issue. "
                       "Sereno doesn't show it." % (name, where),
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
                   "%s and keep it in your system's keychain or a password manager, loading it when you need it (for "
                   'example export %s="$(secret-tool lookup service %s)" in a shell file). Then revoke it where you '
                   "made it and make a new one, because copies of the file may already hold it. To undo, put the line "
                   "back." % (remove or "Take it out of %s" % where, name, name), details)


def _commented_key_finding(finding, name: str, path: Path, line: int):
    where = "%s:%d" % (path, line)
    return finding("info", "Agent key left in a commented-out line: %s (%s)" % (name, where),
                   "Line %d of %s sets %s to what looks like a key, in a comment. The shell doesn't use it, but "
                   "commenting a line out doesn't remove it: the key is still in the file, its backups and any dotfile "
                   "repository. Sereno doesn't show it." % (line, path, name),
                   "If the key still works, revoke it where you made it, then delete the line. To undo, put the line "
                   "back.", {"path": str(path), "line": line, "variable": name})


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
    for d, pattern in SHELL_DIRS:
        files += sorted(p for p in (home / d).glob(pattern) if p.is_file())
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
            for name, value in credential_assignments(line[len(code):]):   # the comment, if there is one
                if _looks_like_key(_literal(value)):
                    out.append(_commented_key_finding(finding, name, path, lineno))
    path = home / FISH_UNIVERSAL
    try:
        text = _read(path)
    except OSError as e:
        return out + [_not_checked(finding, path, e, "its universal variables")]
    for lineno, name, value in fish_universal(text or ""):
        f = _credential_finding(finding, name, value, path, lineno,
                                "Remove it with `set -Ue %s` (fish keeps set -U variables in %s)" % (name, path))
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
