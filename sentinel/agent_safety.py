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
from .paths import skip_list
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
# fish's set [flags] NAME [value] (see _fish_sets)
FISH_SET = re.compile(r"(?<![\w-])set\s+")
FISH_SET_NAME = re.compile(r"(%s)\b(?:\s+(\"[^\"]*\"|'[^']*'|[^\s;&|]+))?" % "|".join(CRED_VARS))
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


# Launch flags that switch an agent's prompts off. Claude's and Codex's long flags are their own, so they count
# wherever they're written. --yolo, -y and the mode flags count only as the arguments of codex or gemini run as a
# command (see _launches), not in another command's arguments (conda install gemini -y) or in a message.
AGENT_FLAGS = (
    ("claude", "--dangerously-skip-permissions", re.compile(r"(?<![\w-])--dangerously-skip-permissions(?![\w-])")),
    ("claude", "--permission-mode bypassPermissions",
     re.compile(r"(?<![\w-])--(?:permission-)?mode(?:=|\s+)[\"']?bypassPermissions\b")),
    ("codex", "--dangerously-bypass-approvals-and-sandbox",
     re.compile(r"(?<![\w-])--dangerously-bypass-approvals-and-sandbox(?![\w-])")),
)
CODEX_PAIR = ("codex", "--ask-for-approval never with --sandbox danger-full-access")
# The order flags are listed in a finding
FLAG_ORDER = tuple((agent, flag) for agent, flag, _ in AGENT_FLAGS) + (
    ("codex", "--yolo"), ("gemini", "--yolo"), ("gemini", "-y"), ("gemini", "--approval-mode yolo"), CODEX_PAIR)
AGENT_NAMES = (("codex", ("codex",)), ("gemini", ("gemini", "gemini-cli")))   # npx @google/gemini-cli


def _launcher(takes: str = "", before=0, how: str = "args", code: str = ""):
    """A launcher's options that take the next word as their value, the words before the command it runs (a number,
    or a pattern for one word that may be left out), how that command is read (see LAUNCHERS), and its options whose
    value is code for a shell."""
    return frozenset(takes.split()), before, how, frozenset(code.split())


NPX_TAKES = "-p --package"
UVX_TAKES = ("-p -w -f --from --with --with-editable --with-requirements --python --index --index-url "
             "--extra-index-url --default-index --find-links")
UV_RUN = _launcher(UVX_TAKES + " --extra --group --only-group --package --env-file --directory --project")
MISE_EXEC = _launcher(how="--", code="-c --command")
CONDA_RUN = _launcher("-n -p --name --prefix --cwd")
TMUX_NEW = _launcher("-c -e -F -f -l -n -p -s -t -x -y", how="sh")
# nvm exec's version, which can be left out: 20, v20.1, lts/iron, node
NVM_VERSION = re.compile(r"(?:v?\d[\w.]*|lts/\S*|node|stable|unstable|iojs|system|default)$")
# Programs that run the command after them: sudo -u root codex, timeout 1h codex, envchain work codex. Each has its
# options that take the next word as their value (read as getopt reads them: sudo -Hu bob is -H, then -u bob), how
# many words come before the command (timeout's duration, envchain's namespace), and how the command is read:
# "args", the words after them; "--", the words after a -- (in mise exec node@20 -- codex, the words before it name
# tools); "sh", their words joined and run by a shell (watch runs them with sh -c, sg with /bin/sh); "none", nothing
# but what a code option gives (tmux -c; tmux's own options come before its command, after which -c names a folder);
# "anywhere", the same with the options read wherever they're written (su bob -c '...'). An option whose value is code
# for a shell (su -c, script -c, flock FILE -c, env -S, whose words come before the rest) has that code read.
LAUNCHERS = {
    "sudo": _launcher("-a -C -c -D -g -p -R -r -T -t -U -u --auth-type --close-from --login-class --chdir --group "
                      "--host --prompt --chroot --role --type --command-timeout --other-user --user"),
    "doas": _launcher("-a -C -u"), "env": _launcher("-C -u --chdir --unset", code="-S --split-string"),
    "command": _launcher(), "builtin": _launcher(), "exec": _launcher("-a"), "nohup": _launcher(),
    "noglob": _launcher(), "nocorrect": _launcher(), "unbuffer": _launcher(), "setsid": _launcher(),
    "firejail": _launcher(), "time": _launcher("-f -o --format --output"), "nice": _launcher("-n --adjustment"),
    "ionice": _launcher("-c -n -p -P -u --class --classdata --pid --pgid --uid"),
    "timeout": _launcher("-k -s --kill-after --signal", 1), "stdbuf": _launcher("-i -o -e --input --output --error"),
    "caffeinate": _launcher("-t -w"), "chrt": _launcher("-T -P -D --sched-runtime --sched-period --sched-deadline", 1),
    "taskset": _launcher(before=1), "envchain": _launcher(before=1),
    "flock": _launcher("-w -E --wait --timeout --conflict-exit-code", 1, code="-c --command"),
    "watch": _launcher("-n -q --interval --equexit", how="sh"),
    "xargs": _launcher("-a -d -E -I -L -n -P -s --arg-file --delimiter --max-lines --max-args --max-procs "
                       "--max-chars --process-slot-var"),
    "npx": _launcher(NPX_TAKES), "pnpx": _launcher(NPX_TAKES), "bunx": _launcher(NPX_TAKES),
    "uvx": _launcher(UVX_TAKES), "dotenv": _launcher("-e -v -p"),   # dotenv-cli: dotenv -e .env -- codex
    "su": _launcher(how="anywhere", code="-c --command -C --session-command"),
    "script": _launcher("-E -I -O -B -T -m --echo --log-in --log-out --log-io --log-timing --logging-format",
                        code="-c --command"),
    "sg": _launcher(before=1, how="sh", code="-c"), "screen": _launcher("-c -e -h -p -S -s -t -T"),
    "systemd-run": _launcher("-u -p -E -M -H --unit --property --setenv --machine --host --slice --description --uid "
                             "--gid --nice --working-directory"),
    "tmux": _launcher("-f -L -S -T", how="none", code="-c"),   # tmux -c '...' runs it with your shell
}
# Programs whose subcommand runs a command (npm exec codex, uv tool run gemini, op run -- codex, tmux new 'codex'),
# each with its own options that take a value, which can come before the subcommand
SUBCOMMANDS = {
    "npm": ("", {("exec",): _launcher(NPX_TAKES), ("x",): _launcher(NPX_TAKES)}),
    "pnpm": ("", {("dlx",): _launcher(NPX_TAKES), ("exec",): _launcher(NPX_TAKES)}),
    "yarn": ("", {("dlx",): _launcher(NPX_TAKES), ("exec",): _launcher(NPX_TAKES)}),
    "bun": ("", {("x",): _launcher(NPX_TAKES)}),
    "uv": ("--directory --project --cache-dir --config-file",
           {("run",): UV_RUN, ("tool", "run"): _launcher(UVX_TAKES)}),
    "asdf": ("", {("exec",): _launcher()}),
    "pixi": ("", {("exec",): _launcher("-s -c -w --spec --channel --with --platform"),
                  ("run",): _launcher("-e --environment --manifest-path")}),
    "mise": ("-C -E -j --cd --env --jobs", {("exec",): MISE_EXEC, ("x",): MISE_EXEC}),
    "direnv": ("", {("exec",): _launcher(before=1)}),
    "nvm": ("", {("exec",): _launcher(before=NVM_VERSION)}),
    "op": ("--account --cache --config --encoding --session",
           {("run",): _launcher("--env-file --account --cache --config --encoding --session")}),
    "doppler": ("--scope --token --api-host --configuration",
                {("run",): _launcher("-p -c --project --config --token --scope --name-transformer --mount "
                                     "--mount-format --mount-template --mount-max-reads --fallback",
                                     code="--command")}),
    "infisical": ("--domain --token", {("run",): _launcher("--env --path --projectId --token --tags --domain",
                                                           code="--command")}),
    "dotenv": ("-f -q -e --file --quote --export", {("run",): _launcher()}),   # python-dotenv: dotenv run codex
    "conda": ("", {("run",): CONDA_RUN}), "mamba": ("", {("run",): CONDA_RUN}),
    "micromamba": ("", {("run",): CONDA_RUN}),
    "poetry": ("", {("run",): _launcher()}), "pipenv": ("", {("run",): _launcher()}),
    "tmux": ("-c -f -L -S -T", {(sub,): TMUX_NEW for sub in (
        "new", "new-session", "new-window", "neww", "split-window", "splitw", "respawn-pane", "respawnp",
        "respawn-window", "respawnw")}),
}
# Commands whose output is a program's path, so that $(which codex) --yolo runs codex: each with the options that
# make it print one (command -v; fish's command -s)
LOOKUPS = {"which": ("-a",), "command": ("-v", "-s", "--search"), "type": ("-p", "-P"), "whence": ("-p",)}
# Words of the shell's own (bash, zsh, fish) after which a command starts
SHELL_KEYWORDS = ("if", "then", "else", "elif", "do", "while", "until", "!", "coproc", "and", "or", "not", "begin")
SHELLS = ("sh", "bash", "zsh", "dash", "ksh", "fish")
# fish's abbr options that take the next word as their value
ABBR_TAKES = ("-p", "--position", "-r", "--regex", "-c", "--command")
ASSIGNMENT = re.compile(r"[A-Za-z_]\w*\+?=")
ALIAS_NAME = re.compile(r"^\s*(?:alias\s+(?:-\S*\s+)*([\w.:+-]+)|function\s+([\w.:+-]+)|([\w.:+-]+)\s*\(\s*\)|"
                        r"abbr\s+(?:(?:%s)\s+\S+\s+|-\S*\s+)*([\w.:+-]+))" % "|".join(ABBR_TAKES))
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


def _claude_files(home: Path, environ, skip=None) -> list:
    """(path, scope) for every Claude Code settings file to read: yours (in ~/.claude and $CLAUDE_CONFIG_DIR), managed,
    and the project ones the persistence check finds (sentinel/claude_settings.py), outside the skip list's folders:
    one on the list or linked into it is left out before it's looked at."""
    skip = skip_list(skip)
    files = []
    for d in _config_dirs(home / ".claude", environ.get("CLAUDE_CONFIG_DIR")):
        files += [(d / "settings.json", "user"), (d / "settings.local.json", "user")]
    files += [(p, "managed") for p in MANAGED_FILES]
    files = [(p, scope) for p, scope in files if not skip.covers(p)]
    files += [(p, "project" if p.name == "settings.json" else "local")
              for p, _ in project_files(home, known_projects(home, skip), skip)]
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


def _claude_findings(finding, home: Path, environ, skip=None) -> list:
    out, seen = [], set()
    for path, scope in _claude_files(home, environ, skip):
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
        # one way to read each character (_key_parts strips the spaces): \s* around a lazy name that can also hold
        # spaces took 31 s on a [ and 2,000 spaces
        header = re.match(r"^\[\[?([^\[\]]+)\]\]?\s*(?:#.*)?$", line)
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


def _codex_findings(finding, home: Path, environ, skip=None) -> list:
    skip = skip_list(skip)
    out, seen = [], set()
    for d in _config_dirs(home / ".codex", environ.get("CODEX_HOME")):
        path = d / "config.toml"
        if skip.covers(path):
            continue
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


def _gemini_findings(finding, home: Path, skip=None) -> list:
    path = home / ".gemini" / "settings.json"
    if skip_list(skip).covers(path):
        return []
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


def _vscode_findings(finding, home: Path, skip=None) -> list:
    skip = skip_list(skip)
    out = []
    for rel in VSCODE_FILES:
        path = home / rel
        if skip.covers(path):
            continue
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


def _commands(text: str) -> list:
    """Each simple command in a line of shell or fish code, as its words with quotes and escapes taken off, as the
    shell reads them. A command ends at ; & | and at ( ) and a word-initial { or }; $(...), (...) and `...` hold
    commands of their own, read the same way. One that looks a program up ($(which codex)) stands for that program;
    what any other puts into a word isn't known, so it adds nothing to it. A redirection (>log, 2>&1, &>log, <<EOF)
    takes the word after it as its target, and neither is a word of the command. A # that starts a word starts a
    comment. One pass, with a stack rather than recursion, however deep the nesting."""
    out, stack = [], []
    # word: its characters so far, or None between words. target: the next word is a redirection's target
    words, word, quote, closer, target = [], None, None, None, False
    escaped = -1   # the index just past the last character a backslash escaped
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        i += 1
        if c == "`" and closer == "`" or c == ")" and closer == ")" and quote is None:
            if word is not None and not target:   # the end of a command substitution: back to the command it's in
                words.append("".join(word))
            if words:
                out.append(words)
            program = _looked_up(words)
            words, word, quote, closer, target = stack.pop()
            word = [] if word is None else word
            word.extend(program)
        elif quote == "'":
            if c == "'":
                quote = None
            else:
                word.append(c)
        elif c == "\\":
            word = [] if word is None else word
            if quote == '"' and text[i:i + 1] not in ("$", "`", '"', "\\"):
                word.append(c)   # inside double quotes a backslash escapes only these
            else:
                word.append(text[i:i + 1])
                i += 1
                escaped = i
        elif c == "`" or c == "(" and (quote is None or text[i - 2:i - 1] == "$" and escaped != i - 1):
            if c == "(" and word and word[-1] == "$":
                word.pop()   # the $ of $( is the substitution's
            stack.append((words, word, quote, closer, target))
            words, word, quote, closer, target = [], None, None, ")" if c == "(" else "`", False
        elif quote == '"':
            if c == '"':
                quote = None
            else:
                word.append(c)
        elif c in "'\"":
            word, quote = [] if word is None else word, c
        elif c == "#" and word is None:
            break
        elif c in "<>" or c == "&" and text[i:i + 1] == ">":
            # a file descriptor's number written just before the operator (2>) is part of the redirection
            if word is not None and not target and not "".join(word).isdigit():
                words.append("".join(word))
            word, target = None, True
            if text[i:i + 1] == "&":   # >&2, <&0. A | after > is a pipe: fish's 2>| pipes errors on
                i += 1
        elif c.isspace() or c in ";&|)" or c in "{}" and word is None:
            if word is not None:
                if not target:
                    words.append("".join(word))
                word, target = None, False
            if not c.isspace():
                target = False
                if words:
                    out.append(words)
                    words = []
        else:
            word = [] if word is None else word
            word.append(c)
    while True:
        if word is not None and not target:
            words.append("".join(word))
        if words:
            out.append(words)
        if not stack:
            return out
        words, word, quote, closer, target = stack.pop()
        word = [] if word is None else word


def _looked_up(words: list) -> str:
    """The program a command substitution stands for when all it does is look one up: which codex, command -v codex,
    type -p gemini (see LOOKUPS). Otherwise "". Only a program's name, and only a short one, goes up: copying a long
    one into each of a thousand nested $(which $(which ...)) took seconds."""
    if len(words) < 2 or words[0] not in LOOKUPS or words[-1][:1] == "-":
        return ""
    options, name = words[1:-1], _program(words[-1])
    if all(o in LOOKUPS[words[0]] for o in options) and (options or words[0] == "which") and len(name) <= 64:
        return name
    return ""


def _program(word: str) -> str:
    """The program a command word names: its file name, without an npm version (@openai/codex@0.1 -> codex)."""
    name = word.rsplit("/", 1)[-1]
    return name.split("@", 1)[0]


def _getopt(words: list, i: int, takes=(), code=(), permute: bool = False):
    """Read options from words[i] on as getopt reads them: -Hu bob is -H, then -u with the value bob; -ubob gives -u
    the value bob; --user=bob and --user bob both give --user the value bob (for the options in takes and code). Returns
    (the index of the first word that's neither an option nor an option's value, with a -- that ends the options left
    there; the value of the first option in code, or None). With permute, words that aren't options are passed over,
    as su reads its options wherever they're written. One look at each character."""
    n = len(words)
    while i < n and words[i] != "--":
        a = words[i]
        i += 1
        if a[:1] != "-":
            if permute:
                continue
            return i - 1, None
        if a[:2] == "--":
            name, eq, value = a.partition("=")
            if name in takes or name in code:
                if not eq:
                    value, i = (words[i] if i < n else ""), i + 1
                if name in code:
                    return i, value
            continue
        for k in range(1, len(a)):
            if "-" + a[k] in takes or "-" + a[k] in code:
                value = a[k + 1:]   # the rest of the word, or the next word when it's the last letter
                if not value:
                    value, i = (words[i] if i < n else ""), i + 1
                if "-" + a[k] in code:
                    return i, value
                break
    return i, None


def _skip_options(words: list, i: int, takes=()) -> int:
    """The index of the first word from i on that isn't an option, the value of one in takes, or the -- that ends
    them."""
    i = _getopt(words, i, takes)[0]
    return i + 1 if i < len(words) and words[i] == "--" else i


def _alias_bodies(args: list) -> list:
    """The code each alias defined by an alias command stands for: NAME=VALUE (bash, zsh, fish), or fish's
    alias NAME DEFINITION..., whose words fish joins with spaces."""
    args = args[_skip_options(args, 0):]
    if args and "=" not in args[0]:
        return [" ".join(args[1:])]
    return [a.split("=", 1)[1] for a in args if "=" in a]


def _abbr_body(args: list) -> list:
    """The expansion of a fish abbreviation, abbr [-a] [options] NAME EXPANSION..., its words joined with spaces as
    fish joins them. A line that erases, lists or renames one leaves nothing a command could be read from."""
    name = _skip_options(args, 0, ABBR_TAKES)
    return [" ".join(args[_skip_options(args, name + 1, ABBR_TAKES):])]   # options can follow the name too


def _shell_string(args: list):
    """The code a shell is given to run (bash -c '...', -lc, fish -c or --command=...), or None."""
    command, i = False, 0
    while i < len(args):
        a = args[i]
        if a.startswith("--command="):
            return a[len("--command="):]
        if a == "--command":
            return args[i + 1] if i + 1 < len(args) else None
        if a in ("-o", "+o", "-O", "+O"):   # set -o and shopt names
            i += 2
        elif a[:2] == "--":   # a long option, or -- itself
            i += 1
        elif a[:1] in ("-", "+") and len(a) > 1:
            command = command or "c" in a
            i += 1
        else:
            return a if command else None
    return None


def _launched(words: list, i: int, name: str):
    """What the launcher words[i] runs (see LAUNCHERS and SUBCOMMANDS): the index of its command's first word
    (len(words) or more when there's none), or the code it gives a shell to run; None when words[i] isn't a launcher.
    It reads up to the command, or to the -- before it, once."""
    spec, j, n = None, i + 1, len(words)
    if name in SUBCOMMANDS:
        takes, subcommands = SUBCOMMANDS[name]
        k = _getopt(words, i + 1, frozenset(takes.split()))[0]
        for sub, launcher in subcommands.items():
            if tuple(words[k:k + len(sub)]) == sub:
                spec, j = launcher, k + len(sub)
    spec = spec or LAUNCHERS.get(name)
    if spec is None:
        return None
    takes, before, how, code = spec
    j, value = _getopt(words, j, takes, code, how == "anywhere")
    if value is not None:   # env -S: the string's words come before the rest, which are the command's arguments
        return " ".join([value] + words[j:]) if name == "env" else value
    if j < n and words[j] == "--":
        j += 1
    elif how == "--":   # the words before the -- name tools
        while j < n and words[j] != "--":
            j += 1
        j += 1
    j += before if isinstance(before, int) else int(j < n and bool(before.match(words[j])))
    if j < n and words[j] in code:   # after the words before the command: flock FILE -c '...'
        return words[j + 1] if j + 1 < n else ""
    if how == "sh":
        return " ".join(words[j:])
    return n if how in ("none", "anywhere") else j


def _command_run(words: list):
    """What one simple command runs: (agent, its arguments) for codex or gemini, after any variable assignments,
    shell keywords and launchers (sudo -u root, timeout 1h, npx -y, bun x, op run --); else (None, the code it holds
    for a shell to read: an alias's body, an abbreviation's expansion, eval's words, sh -c's or su -c's string)."""
    i, n = 0, len(words)
    while i < n:
        w = words[i]
        if ASSIGNMENT.match(w) or w in SHELL_KEYWORDS or not w:   # not w: a $(...) of its own, which may be empty
            i += 1
            continue
        step = _launched(words, i, _program(w))
        if step is None:
            break
        if isinstance(step, str):
            return None, [step]
        i = step
    if i >= n:
        return None, []
    name, args = _program(words[i]), words[i + 1:]
    for agent, names in AGENT_NAMES:
        if name in names:
            return agent, args
    if name == "alias":
        return None, _alias_bodies(args)
    if name == "abbr":
        return None, _abbr_body(args)
    if name == "eval":
        return None, [" ".join(args)]
    if name in SHELLS:
        string = _shell_string(args)
        return None, [] if string is None else [string]
    return None, []


def _launches(code: str) -> list:
    """(agent, its arguments) for each run of codex or gemini in a line of shell or fish code, as a command (see
    _command_run) or in code an alias, abbreviation, eval or sh -c holds, read up to three levels deep. Each level reads
    parts of the one before, so the whole costs a few passes over the line."""
    found, todo = [], [(code, 0)]
    while todo:
        text, depth = todo.pop()
        for words in _commands(text):
            agent, rest = _command_run(words)
            if agent:
                found.append((agent, rest))
            elif depth < 3:
                todo += [(inner, depth + 1) for inner in rest]
    return found


def _option(args: list, i: int, short: str, long: str):
    """The value args[i] gives an option: -a never, -a=never, -anever, --ask-for-approval never or
    --ask-for-approval=never (short may be ""); None when args[i] isn't that option."""
    a = args[i]
    if a == long or short and a == short:
        return args[i + 1] if i + 1 < len(args) else ""
    if a.startswith(long + "="):
        return a[len(long) + 1:]
    if short and a.startswith(short):
        return a[len(short):].lstrip("=")
    return None


def _agent_flags(agent: str, args: list) -> list:
    """(agent, flag) for each of a codex or gemini command's arguments, up to a --, that switch its prompts off. Codex
    counts only when it's told both never to ask and to run without a sandbox (either alone keeps a safeguard), by
    flags or by -c overrides of the config.toml keys (codex -c approval_policy=never)."""
    out, never, unsandboxed = [], False, False
    for i, a in enumerate(args):
        if a == "--":
            break
        if a == "--yolo" or agent == "gemini" and a in ("-y", "--yolo=true"):
            out.append((agent, a.split("=")[0]))
        if agent == "gemini":
            if "yolo" in (_option(args, i, "", "--approval-mode"), _option(args, i, "", "--approvalMode")):
                out.append(("gemini", "--approval-mode yolo"))
            continue
        config = _option(args, i, "-c", "--config")
        key, _, value = (config or "").partition("=")
        setting = (key.strip(), value.strip().strip("\"'"))
        never = never or _option(args, i, "-a", "--ask-for-approval") == "never" or setting == (
            "approval_policy", "never")
        unsandboxed = unsandboxed or _option(args, i, "-s", "--sandbox") == "danger-full-access" or setting == (
            "sandbox_mode", "danger-full-access")
    if never and unsandboxed:
        out.append(CODEX_PAIR)
    return out


def skip_flags(code: str) -> list:
    """(agent, flag) for each launch flag in one shell line that switches an agent's prompts off."""
    found = set((agent, flag) for agent, flag, pattern in AGENT_FLAGS if pattern.search(code))
    for agent, args in _launches(code):
        found.update(_agent_flags(agent, args))
    return [f for f in FLAG_ORDER if f in found]


def credential_assignments(code: str) -> list:
    """(variable, value as written) for each assignment to an agent credential variable in one shell or fish line:
    NAME=value (with or without export, or as ${NAME=value}), and fish's set -gx NAME value. $NAME=... isn't one. A
    default in ${NAME:-value} or ${NAME:=value} counts when it looks like a key: it's written in the file all the same
    (and ${NAME:-unset} is only a word to print)."""
    out, sets = [], _fish_sets(code)
    for name in CRED_VARS:
        for m in re.finditer(r"(?<![\w$])%s=(\"[^\"]*\"|'[^']*'|[^\s;&|)}`'\"]*)" % name, code):
            out.append((name, m.group(1)))
        # a default holding a $ comes from elsewhere (_literal); stopping at one keeps a line of unclosed ${NAME:-
        # to one pass
        for m in re.finditer(r"\$\{%s(?::?-|:=)([^}$]*)\}" % name, code):
            if _looks_like_key(_literal(m.group(1))):
                out.append((name, m.group(1)))
        out += [(name, value) for variable, value in sets if variable == name]
    return out


def _fish_sets(code: str) -> list:
    """(variable, value as written) for each of fish's `set [flags] NAME [value]` in a line that sets an agent
    credential variable. Each run of flags is found once, from the end of the line back, so a set that starts inside
    another's flags (set -a/set -a/set ..., 17 s for 14 KB when each set read the flags after it again) costs nothing
    more: one pass, however the line is built."""
    tokens = [m.start() for m in re.finditer(r"\S+", code)]
    index = {start: k for k, start in enumerate(tokens)}
    # after[k]: the first word from the k-th on that isn't a flag (a flag starts with -)
    after = [len(tokens)] * (len(tokens) + 1)
    for k in range(len(tokens) - 1, -1, -1):
        after[k] = after[k + 1] if code[tokens[k]] == "-" else k
    out, seen = [], set()
    for start in FISH_SET.finditer(code):
        k = after[index.get(start.end(), len(tokens))]
        m = FISH_SET_NAME.match(code, tokens[k]) if k < len(tokens) and k not in seen else None
        if m:
            seen.add(k)
            out.append((m.group(1), m.group(2) or ""))
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
    model servers ask for, isn't one; every agent key format Sereno knows is longer. redact() takes seconds on a few
    thousand characters of some shapes (a-a-a-...), so it's asked only about what the length rule leaves open (under
    20 characters, or shaped like a placeholder), up to 256 characters: a real token has digits or capitals, which no
    placeholder shape allows, so a long one never gets that far."""
    if len(value) >= 20 and not PLACEHOLDER.search(value):
        return True
    return len(value) <= 256 and redact(value) != value


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
    kind, name = next(((kind, m.group(g)) for g, kind in ((1, "alias"), (2, "function"), (3, "function"),
                                                          (4, "abbreviation")) if m and m.group(g)), (None, None))
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


def _shell_files(home: Path, skip=None) -> list:
    """The shell startup files to read. The folders of them (SHELL_DIRS) are listed only when they're not on the skip
    list, and a file that is on it, or links into it, is left out before it's looked at."""
    skip = skip_list(skip)
    files = [home / f for f in SHELL_FILES if not skip.covers(home / f)]
    for d, pattern in SHELL_DIRS:
        if skip.covers(home / d):
            continue
        files += sorted(p for p in (home / d).glob(pattern) if not skip.covers(p) and p.is_file())
    return files


def _shell_findings(finding, home: Path, skip=None) -> list:
    skip = skip_list(skip)
    out = []
    for path in _shell_files(home, skip):
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
    if skip.covers(path):
        return out
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


def _login_file_findings(finding, home: Path, environ, skip=None) -> list:
    """Agent login files that other accounts can read or write. Only their permissions are read, never their
    contents, and not even those for one on the skip list or linked into it."""
    skip = skip_list(skip)
    out, seen = [], set()
    for path, tool in _login_files(home, environ):
        if skip.covers(path):
            continue
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

def check_agent_safety(finding, home: Path = None, environ=None, skip=None) -> list:
    """Findings for AI agents set to skip their safety prompts and for agent logins left exposed. `finding(severity,
    title, description, remediation, details)` builds one (the scanner passes it, as for mcp.py). environ defaults to
    os.environ; it's where CLAUDE_CONFIG_DIR, CODEX_HOME and the credential variables are looked up. skip: the folders
    not to enter (sentinel/paths.py): every file read here is checked against it first, including a project settings
    file the walk finds, a known project, a shell file and the folders of them."""
    home = home or Path.home()
    environ = os.environ if environ is None else environ
    skip = skip_list(skip)
    return (_claude_findings(finding, home, environ, skip) + _codex_findings(finding, home, environ, skip)
            + _gemini_findings(finding, home, skip) + _vscode_findings(finding, home, skip)
            + _shell_findings(finding, home, skip) + _login_file_findings(finding, home, environ, skip)
            + _environment_findings(finding, environ))
