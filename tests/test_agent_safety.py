"""AI agents set to skip their own safety prompts, and agent logins left exposed (2026-10-24).

Each rule fires on a planted file and stays quiet on its safe twin. No planted secret value may appear in any finding.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from sentinel import agent_safety as ag
from sentinel import mcp, scanner
from sentinel.scanner import CHECK_NAMES, Finding, SentinelScanner

LOCAL_FILE_IN_GIT = ag._local_file_in_git   # the real one; the home fixture replaces it

ANTHROPIC_KEY = "sk-ant-api03-" + "Zq7wR" * 18
OAUTH_TOKEN = "sk-ant-oat01-" + "x9YpL" * 15
OPENAI_KEY = "sk-proj-" + "Ab3kT" * 12
GEMINI_KEY = "AIza" + "Gm4Qv" * 7
SECRETS = (ANTHROPIC_KEY, OAUTH_TOKEN, OPENAI_KEY, GEMINI_KEY)


def make(severity, title, description, remediation, details):
    return Finding(check="agent_safety", severity=severity, title=title, description=description,
                   remediation=remediation, details=details)


def write(path: Path, data, mode=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    if mode is not None:
        os.chmod(str(path), mode)
    return path


def fish_escape(value: str) -> str:
    """A value as fish writes it in fish_variables: - and other punctuation as \\xHH."""
    return "".join(c if c.isalnum() else "\\x%02x" % ord(c) for c in value)


def never_shown(findings, *secrets):
    """No secret, nor a distinctive piece of one, appears anywhere in a finding."""
    for f in findings:
        text = " ".join([f.title, f.description, f.remediation, repr(f.details)])
        for s in secrets or SECRETS:
            assert s not in text and s[12:24] not in text, "a secret value leaked into: %s" % f.title


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setattr(ag, "MANAGED_FILES", ())   # never read the real /etc/claude-code in a test
    monkeypatch.setattr(ag, "_local_file_in_git", lambda path: "untracked")
    return h


def run(home, environ=None):
    """The check's findings. The check must never stop on what it reads: through the scanner, a crash becomes "Check
    couldn't run" and every other finding of the check is lost, so a crash here fails the test."""
    try:
        return ag.check_agent_safety(make, home, environ if environ is not None else {})
    except (NameError, ImportError, SyntaxError):
        raise   # a broken check, not an input it couldn't handle
    except Exception as e:
        pytest.fail("the check stopped on its input: %s: %s" % (type(e).__name__, e))


def sev_titles(findings):
    return sorted((f.severity, f.title) for f in findings)


# ── Claude Code settings ──

def test_your_own_settings_are_advice(home):
    write(home / ".claude" / "settings.json", {
        "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash", "Bash(npm run test *)", "Read"]},
        "skipDangerousModePermissionPrompt": True, "enableAllProjectMcpServers": True})
    out = run(home)
    assert [(f.severity, f.title) for f in out] == [
        ("medium", "Claude Code safety prompts turned off in your settings")]
    assert out[0].details["settings"] == ['permissions.defaultMode "bypassPermissions"',
                                          "skipDangerousModePermissionPrompt", "enableAllProjectMcpServers",
                                          'permissions.allow "Bash"']
    assert "To turn it back on" in out[0].remediation and "To undo" in out[0].remediation
    # the project-only notes stay out of your own settings
    assert "2.1.257" not in out[0].description and "once you trust" not in out[0].description


def test_your_local_settings_file_is_read_too(home):
    write(home / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash(git status)", "Bash"]}})
    out = run(home)
    assert [(f.severity, f.details["scope"], f.details["settings"]) for f in out] == [
        ("medium", "user", ['permissions.allow "Bash"'])]


def test_safe_settings_are_quiet(home):
    write(home / ".claude" / "settings.json", {
        "permissions": {"defaultMode": "acceptEdits", "allow": ["Bash(npm run test *)", "Bash(git status)", "Read"]},
        "skipDangerousModePermissionPrompt": "yes", "enableAllProjectMcpServers": False,
        "defaultMode": "bypassPermissions"})    # not under permissions: Claude Code doesn't read it there
    write(home / ".claude" / "settings.local.json", {"permissions": {"defaultMode": "plan"},
                                                     "enableAllProjectMcpServers": "true"})   # a string isn't true
    assert run(home) == []


@pytest.mark.parametrize("rule,broad", [
    ("Bash", True), ("Bash(*)", True), ("Bash(:*)", True), ("Bash( * )", True), ("Shell", True), ("Shell(*)", True),
    ("PowerShell", True), ("PowerShell(*)", True), ("Bash()", True), ("Bash(**)", True), ("Bash(*:*)", True),
    ("Bash(* *)", True),
    # a program that runs whatever it's given, alone, with a wildcard, or with a flag and a wildcard
    ("Bash(bash:*)", True), ("Bash(env *)", True), ("Bash(python3:*)", True), ("Bash(xargs*)", True),
    ("Bash(sudo)", True), ("Bash(SSH:*)", True), ("Bash(npm run *)", True), ("Bash(sh -c:*)", True),
    ("Bash(python3 -c *)", True), ("Bash(python -m pip *)", True), ("PowerShell(iex:*)", True),
    ("PowerShell(pwsh -Command *)", True), ("PowerShell(python3 *)", True),
    # rules naming a command
    ("Bash(npm run test *)", False), ("Bash(ls*)", False), ("Bashful", False), ("WebFetch", False),
    ("Bash(git:*)", False), ("mcp__srv__tool", False), ("bash", False), ("Bash(:)", False), ("Bash(sudo apt:*)", False),
    ("Bash(python3 script.py *)", False), ("Bash(python3 -m http.server *)", False), ("Bash(pythonista:*)", False),
    ("Bash(env FOO=1 make:*)", False), ("Bash(iex:*)", False), ("PowerShell(Get-ChildItem *)", False),
    ("Bash(sh -c)", False), ("Bash *", False),   # not a rule form Claude Code reads (Tool or Tool(content))
    ("Bash(node -m foo.bar *)", True),            # only python's -m names a module
    ("Bash(python3 -m pytest *)", True),          # Claude Code reads an undotted module as any program
    # Claude Code trims a rule's content and keeps a line break in it
    ("Bash( python3:* )", True), ("Bash(*\n)", True), ("Bash(w*)", False),
    # every python's -m with a dotted module names one program, with a :* too
    ("Bash(python -m http.server *)", False), ("Bash(python2 -m json.tool *)", False),
    ("Bash(python3 -m http.server:*)", False),
    # PowerShell has no -m exception, and counts a program by its .exe name too; Bash doesn't
    ("PowerShell(python3 -m http.server *)", True), ("PowerShell(python.exe:*)", True),
    ("PowerShell(npm.exe run *)", True), ("PowerShell(pwsh.exe -Command *)", True), ("Bash(python.exe:*)", False),
])
def test_broad_shell_rule(rule, broad):
    assert ag.broad_shell_rule(rule) is broad


# Claude Code 2.1.309's own lists of programs that run whatever they're given (written out, not read from Sereno)
CC_SHELL_RUNNERS = ["python", "python3", "python2", "node", "deno", "tsx", "ruby", "perl", "php", "lua", "npx", "bunx",
                    "npm run", "yarn run", "pnpm run", "bun run", "bash", "sh", "ssh"]
CC_BASH_ONLY = ["zsh", "fish", "eval", "exec", "env", "xargs", "sudo"]
CC_POWERSHELL_ONLY = [
    "pwsh", "powershell", "cmd", "wsl", "iex", "invoke-expression", "icm", "invoke-command", "start-process", "saps",
    "start", "start-job", "sajb", "start-threadjob", "invoke-wmimethod", "iwmi", "invoke-cimmethod", "icim", "wmic",
    "register-objectevent", "register-engineevent", "register-wmievent", "register-scheduledjob", "new-pssession", "nsn",
    "enter-pssession", "etsn", "add-type", "new-object"]


@pytest.mark.parametrize("name", CC_SHELL_RUNNERS + CC_BASH_ONLY)
def test_every_program_on_claude_codes_bash_list_is_broad(name):
    for form in ("Bash(%s)", "Bash(%s:*)", "Bash(%s *)", "Bash(%s*)", "Bash(%s -x *)"):
        assert ag.broad_shell_rule(form % name.upper()), form % name


@pytest.mark.parametrize("name", CC_SHELL_RUNNERS + CC_POWERSHELL_ONLY)
def test_every_program_on_claude_codes_powershell_list_is_broad(name):
    exe = name.replace(" ", ".exe ", 1) if " " in name else name + ".exe"
    for form in ("PowerShell(%s)", "PowerShell(%s:*)", "PowerShell(%s *)", "PowerShell(%s -x *)"):
        assert ag.broad_shell_rule(form % name) and ag.broad_shell_rule(form % exe), form % name
    if name in CC_POWERSHELL_ONLY:
        assert not ag.broad_shell_rule("Bash(%s:*)" % name)   # Windows launchers count in PowerShell rules only


def test_the_warning_alone_is_named_as_a_warning(home):
    """Claude Code saves skipDangerousModePermissionPrompt itself when you accept the bypass-mode warning once."""
    write(home / ".claude" / "settings.json", {"skipDangerousModePermissionPrompt": True})
    out = run(home)
    assert [f.title for f in out] == ["Claude Code warning before bypass mode turned off in your settings"]
    assert "removes only that warning" in out[0].description and "hidden in a file" not in out[0].description
    assert "it saves this when you accept that warning once" in out[0].description
    assert "You may have chosen this" not in out[0].description
    assert 'remove "skipDangerousModePermissionPrompt"' in out[0].remediation and "To undo" in out[0].remediation
    # in a project's own file, Claude Code didn't put it there
    write(home / "code" / "app" / ".claude" / "settings.local.json", {"skipDangerousModePermissionPrompt": True})
    local = next(f for f in run(home) if f.details["scope"] == "local")
    assert "You may have chosen this" in local.description and "accept" not in local.description


def test_a_projects_settings_are_high(home):
    write(home / "code" / "app" / ".claude" / "settings.json", {
        "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}, "enableAllProjectMcpServers": True})
    out = run(home)
    assert sev_titles(out) == [("high", "A project folder switches off Claude Code's safety prompts: %s"
                                % (home / "code" / "app"))]
    assert "2.1.257" in out[0].description and "once you trust the folder" in out[0].description
    assert out[0].details["scope"] == "project"
    assert "keep them only in %s, out of git" % (home / "code" / "app" / ".claude" / "settings.local.json") \
        in out[0].remediation


def test_a_shared_project_file_cant_skip_the_warning(home):
    """Claude Code ignores skipDangerousModePermissionPrompt in a shared .claude/settings.json, and honors it in a
    project's settings.local.json."""
    write(home / "code" / "app" / ".claude" / "settings.json", {"skipDangerousModePermissionPrompt": True})
    assert run(home) == []
    write(home / "code" / "app" / ".claude" / "settings.local.json", {"skipDangerousModePermissionPrompt": True})
    assert [f.details["settings"] for f in run(home)] == [["skipDangerousModePermissionPrompt"]]


@pytest.mark.parametrize("git,severity,tracked,says,fix", [
    ("untracked", "medium", False, "Git doesn't track the file, so it's most likely yours", "To turn it back on"),
    ("tracked", "high", True, "Git tracks this settings.local.json", "rm --cached .claude/settings.local.json"),
    ("no repo", "high", None, "The folder isn't in a git repository", "they're yours to keep"),
    ("unknown", "high", None, "couldn't ask git", "they're yours to keep"),
])
def test_a_projects_local_file_is_yours_only_when_git_says_it_doesnt_track_it(home, monkeypatch, git, severity,
                                                                               tracked, says, fix):
    write(home / "code" / "app" / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash"]}})
    monkeypatch.setattr(ag, "_local_file_in_git", lambda path: git)
    out = run(home)
    assert [(f.severity, f.details["git_tracked"]) for f in out] == [(severity, tracked)]
    assert says in out[0].description and fix in out[0].remediation
    # Claude Code holds a project's allow rules, settings.local.json's too, until you trust the folder
    assert "once you trust the folder" in out[0].description
    assert "keep them only in" not in out[0].remediation


@pytest.mark.parametrize("answer,state", [
    ((0, ""), "tracked"),
    ((1, "error: pathspec 'settings.local.json' did not match any file(s) known to git\n"), "untracked"),
    ((128, "fatal: not a git repository (or any of the parent directories): .git\n"), "no repo"),
    ((128, "fatal: detected dubious ownership in repository at '/srv/x'\n"), "unknown"),
    ((129, "usage: git ls-files"), "unknown"),
    ((2, "fatal: not a git repository"), "unknown"),
    (None, "unknown"),
])
def test_only_gits_own_not_tracked_answer_makes_a_local_file_untracked(monkeypatch, answer, state):
    monkeypatch.setattr(ag, "git_ls_file", lambda path: answer)
    assert LOCAL_FILE_IN_GIT(Path("/x/.claude/settings.local.json")) == state


def test_a_local_bypass_mode_isnt_said_to_be_honored_as_yours(home):
    """Claude Code 2.1.309 ignores bypass mode in any project file, settings.local.json included."""
    write(home / "code" / "app" / ".claude" / "settings.local.json",
          {"permissions": {"defaultMode": "bypassPermissions"}})
    out = run(home)
    assert [f.severity for f in out] == ["medium"]
    assert "2.1.257 and later ignore this in a project's files" in out[0].description
    assert "Claude Code treats it as yours" not in out[0].description and "don't ask again" in out[0].description


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_git_decides_whose_local_file_it_is(home, monkeypatch):
    monkeypatch.setattr(ag, "_local_file_in_git", LOCAL_FILE_IN_GIT)
    proj = home / "code" / "app"
    write(proj / ".claude" / "settings.local.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    assert [(f.severity, f.details["git_tracked"]) for f in run(home)] == [("high", None)]   # not a repository yet
    assert "isn't in a git repository" in run(home)[0].description
    subprocess.run(["git", "init", "-q", str(proj)], check=True)
    assert [f.severity for f in run(home)] == ["medium"]
    subprocess.run(["git", "-C", str(proj), "add", ".claude/settings.local.json"], check=True)
    assert [f.severity for f in run(home)] == ["high"]


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_a_scanned_folders_git_config_cant_run_a_program(home, monkeypatch, tmp_path):
    """A downloaded folder can carry its own .git/config. Its core.fsmonitor command runs on `git ls-files` unless
    it's switched off; Sereno only reads."""
    monkeypatch.setattr(ag, "_local_file_in_git", LOCAL_FILE_IN_GIT)
    proj = home / "Downloads" / "template"
    write(proj / ".claude" / "settings.local.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    subprocess.run(["git", "init", "-q", str(proj)], check=True)
    marker = tmp_path / "RAN"
    hook = write(tmp_path / "hook.sh", "#!/bin/sh\ntouch '%s'\n" % marker, mode=0o755)
    subprocess.run(["git", "-C", str(proj), "config", "core.fsmonitor", str(hook)], check=True)
    out = run(home)
    assert not marker.exists(), "the scanned folder's git config ran a program"
    assert [(f.severity, f.details["git_tracked"]) for f in out] == [("medium", False)]
    assert mcp._git_tracked(proj / ".claude" / "settings.local.json") is False and not marker.exists()


def test_known_projects_past_the_walk_are_read(home):
    deep = home / "a" / "b" / "c" / "d" / "deep"
    write(deep / ".claude" / "settings.json", {"permissions": {"allow": ["Bash"]}})
    assert run(home) == []
    write(home / ".claude.json", {"projects": {str(deep): {}}})
    assert [f.severity for f in run(home)] == ["high"]


def test_managed_settings_are_advice(home, monkeypatch, tmp_path):
    managed = write(tmp_path / "etc" / "managed-settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    monkeypatch.setattr(ag, "MANAGED_FILES", (managed, tmp_path / "missing.json"))
    out = run(home)
    assert sev_titles(out) == [("medium", "Claude Code safety prompts turned off by managed settings")]
    assert "sudo" in out[0].remediation


def test_claude_config_dir_is_read_and_read_once(home, tmp_path):
    alt = tmp_path / "claude-work"
    write(alt / "settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    assert run(home) == []
    out = run(home, {"CLAUDE_CONFIG_DIR": str(alt)})
    assert [f.details["path"] for f in out] == [str(alt / "settings.json")]
    write(home / ".claude" / "settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    assert len(run(home, {"CLAUDE_CONFIG_DIR": str(home / ".claude")})) == 1


def test_an_unreadable_settings_file_is_not_checked_never_clean(home):
    write(home / ".claude" / "settings.json", "{ not json")
    out = run(home)
    assert [(f.severity, f.title) for f in out] == [
        ("info", "Couldn't read %s, so it wasn't checked" % (home / ".claude" / "settings.json"))]
    assert "not the same as clean" in out[0].description


def test_a_credential_in_your_settings_env_is_named_never_shown(home):
    write(home / ".claude" / "settings.json", {"env": {
        "ANTHROPIC_API_KEY": ANTHROPIC_KEY, "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN, "OPENAI_API_KEY": "${OPENAI}",
        "GEMINI_API_KEY": "", "OTHER_TOKEN": OPENAI_KEY}})
    write(home / "code" / "app" / ".claude" / "settings.json", {"env": {"ANTHROPIC_API_KEY": ANTHROPIC_KEY}})
    out = run(home)
    assert sorted((f.severity, f.details["variable"]) for f in out) == [
        ("high", "ANTHROPIC_API_KEY"), ("high", "CLAUDE_CODE_OAUTH_TOKEN")]
    assert all(f.details["path"] == str(home / ".claude" / "settings.json") for f in out)
    assert "valid for a year" in next(f for f in out if f.details["variable"] == "CLAUDE_CODE_OAUTH_TOKEN").description
    never_shown(out)


# ── Codex ──

def test_codex_never_asking_with_no_sandbox(home):
    write(home / ".codex" / "config.toml", 'model = "o4"\napproval_policy = "never"  # yolo\n'
                                           'sandbox_mode = "danger-full-access"\n')
    out = run(home)
    assert sev_titles(out) == [("medium", "Codex runs commands without asking and without a sandbox (your config)")]
    assert out[0].details["profile"] is None


@pytest.mark.parametrize("config", [
    'approval_policy = "never"\nsandbox_mode = "workspace-write"\n',       # never asks, but sandboxed
    'approval_policy = "on-request"\nsandbox_mode = "danger-full-access"\n',  # no sandbox, but asks
    '# approval_policy = "never"\nsandbox_mode = "danger-full-access"\n',  # commented out
    'sandbox_mode = "danger-full-access"\n[profiles.safe]\napproval_policy = "on-request"\n',
    'sandbox_mode = "danger-full-access"\n[mcp_servers.x]\napproval_policy = "never"\n',  # not a profile
    'instructions = """\napproval_policy = "never"\n"""\nsandbox_mode = "danger-full-access"\n',
    'notify = [\n  ["x"],\n  ["y"]\n]\n[profiles.p]\nmodel = "m"\n',
])
def test_codex_safe_twins(home, config):
    write(home / ".codex" / "config.toml", config)
    assert run(home) == []


def test_codex_profiles_and_dotted_keys(home):
    write(home / ".codex" / "config.toml",
          'sandbox_mode = "danger-full-access"\nprofiles.fast.approval_policy = "never"\n'
          '[profiles.yolo]\napproval_policy = "never"\n[profiles."my.box"]\napproval_policy = \'never\'\n'
          '[profiles.ask]\napproval_policy = "on-request"\n[profiles.nothing]\nmodel = "x"\n')
    assert sorted(str(f.details["profile"]) for f in run(home)) == ["fast", "my.box", "yolo"]


def test_a_codex_profile_takes_the_top_levels_other_value(home):
    write(home / ".codex" / "config.toml", 'approval_policy = "never"\nsandbox_mode = "workspace-write"\n'
                                           '[profiles.full]\nsandbox_mode = "danger-full-access"\n')
    assert [f.details["profile"] for f in run(home)] == ["full"]


def test_codex_after_a_multiline_array_reads_the_top_level(home):
    write(home / ".codex" / "config.toml",
          'notify = [\n  ["x"],\n  ["y"]\n]\napproval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
    assert [f.details["profile"] for f in run(home)] == [None]


def test_codex_home_is_read(home, tmp_path):
    write(tmp_path / "codex" / "config.toml", 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
    assert run(home) == []
    assert len(run(home, {"CODEX_HOME": str(tmp_path / "codex")})) == 1


# ── Gemini CLI and VS Code ──

@pytest.mark.parametrize("settings,flagged", [
    ({"tools": {"allowed": ["run_shell_command"]}}, True),
    ({"tools": {"allowed": [" ShellTool "]}}, True),
    ({"tools": {"allowed": ["run_shell_command(git status)", "read_file"]}}, False),
    ({"general": {"defaultApprovalMode": "yolo"}}, False),   # Gemini CLI ignores yolo from settings
    ({"tools": {"autoAccept": True}}, False),                # read-only tools only
    ({"tools": "run_shell_command"}, False),
])
def test_gemini_settings(home, settings, flagged):
    write(home / ".gemini" / "settings.json", "// comments are allowed\n" + json.dumps(settings))
    out = run(home)
    assert [f.severity for f in out] == (["medium"] if flagged else [])


def test_broken_gemini_settings_are_not_checked(home):
    write(home / ".gemini" / "settings.json", '{"tools": {"allowed": ["run_shell_command"]')
    assert [(f.severity, f.details["path"]) for f in run(home)] == [("info", str(home / ".gemini" / "settings.json"))]


VSCODE = ('{\n  // my settings\n  "editor.fontSize": 14, /* block */\n  "http.proxy": "http://proxy.example//x",\n'
          '  "%s": %s,\n}\n')


@pytest.mark.parametrize("key,value,flagged", [
    ("chat.tools.global.autoApprove", "true", True),
    ("chat.tools.autoApprove", "true", True),
    ("chat.tools.global.autoApprove", "false", False),
    ("chat.tools.terminal.autoApprove", '{"rm": false}', False),
    ("chat.tools.global.autoApprove", '"true"', False),
])
def test_vscode_auto_approve_with_comments(home, key, value, flagged):
    write(home / ".config" / "Code" / "User" / "settings.json", VSCODE % (key, value))
    out = run(home)
    assert [f.details.get("settings") for f in out] == ([[key]] if flagged else [])


def test_vscode_on_macos_and_a_broken_file(home):
    write(home / "Library" / "Application Support" / "Code" / "User" / "settings.json",
          '{"chat.tools.global.autoApprove": true}')
    write(home / ".config" / "Code" / "User" / "settings.json", '{"chat.tools.global.autoApprove": ')
    assert sorted(f.severity for f in run(home)) == ["info", "medium"]


# ── Shell startup files ──

@pytest.mark.parametrize("line,flags", [
    ("alias c='claude --dangerously-skip-permissions'", [("claude", "--dangerously-skip-permissions")]),
    ("alias c='claude --permission-mode bypassPermissions'", [("claude", "--permission-mode bypassPermissions")]),
    ("claude --mode=bypassPermissions", [("claude", "--permission-mode bypassPermissions")]),
    ("alias cx='codex --dangerously-bypass-approvals-and-sandbox'",
     [("codex", "--dangerously-bypass-approvals-and-sandbox")]),
    ("alias cx='npx @openai/codex --yolo'", [("codex", "--yolo")]),
    ("codex -a never -s danger-full-access", [("codex", "--ask-for-approval never with --sandbox danger-full-access")]),
    ("codex --sandbox=danger-full-access --ask-for-approval=never",
     [("codex", "--ask-for-approval never with --sandbox danger-full-access")]),
    ("alias g='gemini --yolo'", [("gemini", "--yolo")]),
    ("alias g='gemini -m pro -y'", [("gemini", "-y")]),
    ("gemini --approval-mode=yolo", [("gemini", "--approval-mode yolo")]),
    ("gemini --approval-mode 'yolo'", [("gemini", "--approval-mode yolo")]),
    # safe twins
    ("alias c='claude'", []),
    ("alias c='claude --allow-dangerously-skip-permissions'", []),
    ("alias c='claude --permission-mode acceptEdits'", []),
    ("alias cx='codex --full-auto'", []),
    ("codex -a never", []),
    ("codex -s danger-full-access", []),
    ("npm install --yolo", []),
    ("apt-get install -y gemini-tools", []),
    ("alias g='gemini'; apt install -y curl", []),
    ("gemini --approval-mode auto_edit", []),
    ("alias g='gemini -yes'", []),
])
def test_skip_flags(line, flags):
    assert ag.skip_flags(line) == flags


def test_a_skip_alias_is_advice_with_file_and_line(home):
    write(home / ".bashrc", "# alias c='claude --dangerously-skip-permissions'\n\n"
                            "alias c='claude --dangerously-skip-permissions'\n"
                            "alias ok='claude'  # --dangerously-skip-permissions is off\n")
    out = run(home)
    assert [(f.severity, f.details["line"], f.details["name"]) for f in out] == [("medium", 3, "c")]
    assert "%s:3" % (home / ".bashrc") in out[0].title and "(alias c)" in out[0].description
    assert "alias c=" not in out[0].description   # the line isn't quoted


def test_continued_lines_fish_functions_and_zsh(home):
    write(home / ".zshrc", "export PATH=$PATH:~/bin\ngem() {\n  gemini \\\n    --yolo \"$@\"\n}\n")
    write(home / ".config" / "fish" / "functions" / "cx.fish",
          "function cx\n    codex --yolo $argv\nend\n")
    out = run(home)
    assert sorted((Path(f.details["path"]).name, f.details["line"]) for f in out) == [(".zshrc", 3), ("cx.fish", 2)]
    zsh = next(f for f in out if f.details["path"].endswith(".zshrc"))
    assert zsh.details["name"] is None   # the flag is on a line inside the function, not its header


@pytest.mark.parametrize("rc,line", [
    ("export ANTHROPIC_API_KEY=%s\n" % ANTHROPIC_KEY, "ANTHROPIC_API_KEY"),
    ("export CLAUDE_CODE_OAUTH_TOKEN=\"%s\"\n" % OAUTH_TOKEN, "CLAUDE_CODE_OAUTH_TOKEN"),
    ("typeset -x OPENAI_API_KEY='%s'\n" % OPENAI_KEY, "OPENAI_API_KEY"),
    ("alias c='ANTHROPIC_API_KEY=%s claude'\n" % ANTHROPIC_KEY, "ANTHROPIC_API_KEY"),
    ("GEMINI_API_KEY=%s gemini\n" % GEMINI_KEY, "GEMINI_API_KEY"),
    ("export ANTHROPIC_AUTH_TOKEN=%s\n" % OAUTH_TOKEN, "ANTHROPIC_AUTH_TOKEN"),
    (': "${OPENAI_API_KEY=%s}"\n' % OPENAI_KEY, "OPENAI_API_KEY"),     # assigns when unset
    ("export ANTHROPIC_API_KEY=abcdefghijklmnopqrstuvwx\n", "ANTHROPIC_API_KEY"),  # 24 characters, no known shape
    ("export OPENAI_API_KEY=sk-abcdefghijklmnop\n", "OPENAI_API_KEY"),  # 19 characters, shaped like a key
])
def test_a_literal_credential_in_a_shell_file_is_high(home, rc, line):
    write(home / ".profile", "# my profile\n" + rc, mode=0o600)
    out = run(home)
    assert [(f.severity, f.details["variable"], f.details["line"]) for f in out] == [("high", line, 2)]
    assert "%s:2" % (home / ".profile") in out[0].title
    assert "Other accounts" not in out[0].description   # mode 600
    never_shown(out)


def test_a_credential_in_fish_config_and_a_readable_file_says_so(home):
    write(home / ".config" / "fish" / "config.fish", "set -gx ANTHROPIC_API_KEY %s\n" % ANTHROPIC_KEY, mode=0o644)
    out = run(home)
    assert [(f.severity, f.details["variable"]) for f in out] == [("high", "ANTHROPIC_API_KEY")]
    assert "Other accounts on this machine can read" in out[0].description and "(mode 644)" in out[0].description
    never_shown(out)


def test_a_group_readable_shell_file_says_so(home):
    write(home / ".zshrc", "export GEMINI_API_KEY=%s\n" % GEMINI_KEY, mode=0o640)
    out = run(home)
    assert "(mode 640)" in out[0].description
    never_shown(out)


def test_credentials_from_elsewhere_are_fine(home):
    write(home / ".bashrc", "\n".join([
        'export ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"',
        "export ANTHROPIC_API_KEY=$(security find-generic-password -w -s anthropic)",
        'export OPENAI_API_KEY="$(pass show openai)"',
        "export CLAUDE_CODE_OAUTH_TOKEN=`cat ~/.secret`",
        'export ANTHROPIC_AUTH_TOKEN="`cat ~/.anthropic/token`"',
        "export ANTHROPIC_API_KEY=",
        'export OPENAI_API_KEY=""',
        "export ANTHROPIC_API_KEY",
        "unset ANTHROPIC_API_KEY",
        "export MY_ANTHROPIC_API_KEY=%s" % ANTHROPIC_KEY,   # not an agent variable
        "export X=$ANTHROPIC_API_KEY=%s" % ANTHROPIC_KEY,    # $NAME=... isn't an assignment to NAME
        "# export ANTHROPIC_API_KEY=your_anthropic_key_here",   # a placeholder in a comment
        'echo "${ANTHROPIC_API_KEY:-unset}"', 'echo "${OPENAI_API_KEY:-$(pass show openai)}"', ""]))
    write(home / ".config" / "fish" / "conf.d" / "keys.fish",
          "set -gx GEMINI_API_KEY (secret-tool lookup service gemini)\nset -e OPENAI_API_KEY\n"
          "set -gx OPENAI_API_KEY $OTHER\n")
    assert run(home) == []


def test_a_short_placeholder_is_a_note_not_an_issue(home):
    write(home / ".bashrc", "export OPENAI_API_KEY=ollama\n")
    out = run(home)
    assert [(f.severity, f.details["variable"]) for f in out] == [("info", "OPENAI_API_KEY")]
    assert "ollama" not in out[0].title + out[0].description + out[0].remediation + repr(out[0].details)


def test_a_skip_alias_holding_a_key_names_both_and_shows_neither(home):
    write(home / ".bash_aliases",
          "alias c='ANTHROPIC_API_KEY=%s claude --dangerously-skip-permissions'\n" % ANTHROPIC_KEY)
    out = run(home)
    assert sorted((f.severity, f.details.get("variable")) for f in out) == [("high", "ANTHROPIC_API_KEY"),
                                                                           ("medium", None)]
    never_shown(out)


def test_a_file_ending_on_a_continued_line(home):
    write(home / ".bashrc", "alias ok='ls'\nalias c='claude \\\n--dangerously-skip-permissions' \\")
    assert [f.details["line"] for f in run(home)] == [2]


def test_every_documented_shell_file_is_read(home):
    names = [".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".profile", ".zshrc", ".zprofile", ".zshenv",
             ".config/fish/config.fish", ".config/fish/conf.d/agents.fish", ".config/fish/functions/c.fish",
             ".bashrc.d/ai", ".bashrc.d/keys.sh", ".oh-my-zsh/custom/aliases.zsh"]
    for name in names:
        write(home / name, "alias c='claude --dangerously-skip-permissions'\n")
    write(home / ".config" / "fish" / "conf.d" / "notes.txt", "alias c='claude --dangerously-skip-permissions'\n")
    write(home / ".oh-my-zsh" / "custom" / "plugins" / "x" / "x.zsh",   # a plugin oh-my-zsh loads only by name
          "alias c='claude --dangerously-skip-permissions'\n")
    (home / ".bashrc.d" / "sub").mkdir()   # a folder there is skipped, not "couldn't read"
    assert sorted(f.details["path"] for f in run(home)) == sorted(str(home / n) for n in names)


def test_the_name_of_a_function_is_reported(home):
    write(home / ".bashrc", "yolo() { claude --dangerously-skip-permissions \"$@\"; }\n"
                            "function cc { claude --permission-mode bypassPermissions; }\n")
    assert [(f.details["name"], "(function %s)" % f.details["name"] in f.description) for f in run(home)] == [
        ("yolo", True), ("cc", True)]


@pytest.mark.parametrize("line,flagged", [
    ("alias c='echo #hi; claude --dangerously-skip-permissions'", True),      # a # inside quotes isn't a comment
    ('alias c="echo \\" #x\\"; claude --dangerously-skip-permissions"', True),  # nor after an escaped quote
    ("alias c='claude' #--dangerously-skip-permissions", False),
    ("alias c=claude#--dangerously-skip-permissions", True),                  # a # inside a word isn't one either
])
def test_comments_are_found_outside_quotes_only(home, line, flagged):
    write(home / ".bashrc", line + "\n")
    assert len(run(home)) == (1 if flagged else 0)


def test_documented_managed_settings_locations():
    assert ag.MANAGED_FILES == (Path("/etc/claude-code/managed-settings.json"),
                                Path("/Library/Application Support/ClaudeCode/managed-settings.json"))


def test_a_file_where_a_folder_should_be_is_just_missing(home):
    write(home / ".codex", "not a folder")
    write(home / ".claude", "not a folder")
    write(home / ".gemini", "not a folder")
    assert run(home, {"CLAUDE_CONFIG_DIR": str(home / ".bashrc")}) == []


def test_codex_top_level_once_and_codex_home_read_once(home):
    write(home / ".codex" / "config.toml", 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
                                           '[profiles.other]\nmodel = "x"\n')
    assert [f.details["profile"] for f in run(home, {"CODEX_HOME": str(home / ".codex")})] == [None]


def test_a_login_file_reached_twice_is_reported_once(home):
    write(home / ".claude" / ".credentials.json", "{}", mode=0o644)
    assert len(run(home, {"CLAUDE_CONFIG_DIR": str(home / ".claude")})) == 1


def test_odd_shapes_dont_break_the_check(home, monkeypatch):
    """Settings in shapes the tools wouldn't accept are read as far as they go; the check itself never stops (through
    the scanner, a crash would be a "Check couldn't run" finding)."""
    monkeypatch.setattr(scanner, "_home", lambda: home)
    for name in ag.CRED_VARS + ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    write(home / ".claude" / "settings.json", {"permissions": {"allow": [42, {"x": 1}, None, "Bash"]},
                                               "env": {"ANTHROPIC_API_KEY": 12345, "OPENAI_API_KEY": None}})
    write(home / ".claude" / "settings.local.json", ["a", "list"])
    write(home / "code" / "app" / ".claude" / "settings.json", {"permissions": "Bash", "env": "x"})
    write(home / "alt" / "settings.json", {"env": "ANTHROPIC_API_KEY=x"})   # yours, through CLAUDE_CONFIG_DIR
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / "alt"))
    write(home / ".gemini" / "settings.json", {"tools": {"allowed": "run_shell_command"}})
    write(home / ".config" / "Code" / "User" / "settings.json", '["chat.tools.global.autoApprove"]')
    write(home / ".codex" / "config.toml", "[[[ nonsense\n= = =\n\"unclosed = \n")
    result = SentinelScanner(checks=["agent_safety"]).scan()
    assert [(f.severity, f.details.get("settings")) for f in result.findings] == [
        ("medium", ['permissions.allow "Bash"'])]


@pytest.mark.parametrize("line,flags", [
    # gemini and codex count as the command run, not as another command's argument or part of a longer name
    ("alias bio='conda install -c bioconda gemini -y'", []),
    ("alias rmg='pip uninstall gemini-api -y'", []),
    ("brew install gemini-cli -y", []),
    ("which gemini -y", []),
    ("alias cx='codex'; foo --yolo", []),
    ("alias cx='codex' && cp -y a b", []),
    ("npx -y @google/gemini-cli -y", [("gemini", "-y")]),
    ("pnpm dlx @google/gemini-cli --yolo", [("gemini", "--yolo")]),
    ("sudo -E codex --yolo", [("codex", "--yolo")]),
    ("env FOO=1 gemini --yolo", [("gemini", "--yolo")]),
    ("/usr/local/bin/gemini --approval-mode yolo", [("gemini", "--approval-mode yolo")]),
    ("if true; then gemini -y; fi", [("gemini", "-y")]),
    ("x=$(codex --yolo exec hi)", [("codex", "--yolo")]),
    ("g() { gemini --yolo; }", [("gemini", "--yolo")]),
    ('exec codex --yolo "$@"', [("codex", "--yolo")]),
    ("command gemini -y", [("gemini", "-y")]),
    ("alias x='gemini-api -y'", []),
    # codex's -c overrides of approval_policy and sandbox_mode
    ("alias cx='codex -c approval_policy=never -c sandbox_mode=danger-full-access'",
     [("codex", "--ask-for-approval never with --sandbox danger-full-access")]),
    ("codex --config 'approval_policy=\"never\"' --config=sandbox_mode=danger-full-access",
     [("codex", "--ask-for-approval never with --sandbox danger-full-access")]),
    ("codex -a never -c sandbox_mode='danger-full-access'",
     [("codex", "--ask-for-approval never with --sandbox danger-full-access")]),
    ("codex -c approval_policy=never", []),
    ("codex -c sandbox_mode=danger-full-access -c approval_policy=on-request", []),
    ("make -c approval_policy=never -c sandbox_mode=danger-full-access", []),
    # wrappers and command substitution put the agent in command position too
    ("nohup gemini --yolo &", [("gemini", "--yolo")]),
    ("x=`codex --yolo exec hi`", [("codex", "--yolo")]),
    # the agent installed, or named in a message, isn't the agent run
    ("npm i -g @openai/codex --yolo", []),
    ("pip install gemini-api --yolo", []),
    ('echo "run gemini --approval-mode yolo for speed"', []),
    ('echo "try: codex -a never" && codex -s danger-full-access', []),
    ('echo "try: codex -s danger-full-access" && codex -a never', []),
    # a quoted value can hold a space or a separator; an unquoted ; ends the command, so gemini is b's argument
    ("X='a;b' codex --yolo", [("codex", "--yolo")]),
    ('FOO="a b" gemini -y', [("gemini", "-y")]),
    ("X=a;b gemini --yolo", []),
])
def test_skip_flags_need_the_agent_as_the_command(line, flags):
    assert ag.skip_flags(line) == flags


@pytest.mark.parametrize("rc,found", [
    # the shell removes a backslash-newline outright: the key on the next line is the value
    ("export ANTHROPIC_API_KEY=\\\n%s\n" % ANTHROPIC_KEY, [("high", 1)]),
    # a comment ends at its line, backslash or not
    ("# fast mode \\\nalias c='claude --dangerously-skip-permissions'\n", [("medium", 2)]),
    ("export X=1  # note \\\nalias c='claude --dangerously-skip-permissions'\n", [("medium", 2)]),
    # the backslash goes with the line break, so a # after it starts a comment
    ("alias c='claude' \\\n# --dangerously-skip-permissions\n", []),
    # an escaped backslash doesn't continue the line
    ("echo a \\\\\nalias c='claude --dangerously-skip-permissions'\n", [("medium", 2)]),
    # \' outside quotes isn't a quote, so the comment after it stays a comment
    ("echo It\\'s ok # claude --dangerously-skip-permissions\n", []),
    # a default written in ${NAME:-...} or ${NAME:=...} is in the file all the same
    ('export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-%s}"\n' % ANTHROPIC_KEY, [("high", 1)]),
    (': "${OPENAI_API_KEY:=%s}"\n' % OPENAI_KEY, [("high", 1)]),
    ("export GEMINI_API_KEY=${GEMINI_API_KEY-%s}\n" % GEMINI_KEY, [("high", 1)]),
    ('echo "${ANTHROPIC_API_KEY:-not set}"\n', []),
    # a quote left open on a continued line stays open, so this # isn't a comment and the line goes on
    ('claude --model "opus \\\n#1" \\\n--dangerously-skip-permissions\n', [("medium", 1)]),
    # a # right after the joined text is mid-word (opus#1), not a comment, even after a line of just a backslash
    ("claude --name opus\\\n#1 \\\n--dangerously-skip-permissions\n", [("medium", 1)]),
    ("claude --name opus\\\n\\\n#1 \\\n--dangerously-skip-permissions\n", [("medium", 1)]),
    # a quote left open at the end of a line that isn't continued doesn't carry over: an apostrophe in a here-document
    # doesn't turn the comment after it into code that goes on to the next line
    ("cat <<EOF\nDon't panic\nEOF\n# fast mode \\\nalias c='claude --dangerously-skip-permissions'\n", [("medium", 5)]),
    ("echo 'unfinished\n# claude --dangerously-skip-permissions\n", []),
])
def test_shell_lines_are_read_as_the_shell_reads_them(home, rc, found):
    write(home / ".bashrc", rc, mode=0o600)
    out = run(home)
    assert [(f.severity, f.details["line"]) for f in out] == found
    never_shown(out)


@pytest.mark.parametrize("value", ["your_openai_api_key_here", "YOUR-ANTHROPIC-KEY-GOES-HERE", "your.anthropic.key.here",
                                   "x" * 32,
                                   "<paste your key here>", "sk-...replace-me-with-your-key"])
def test_a_long_placeholder_is_a_note_not_an_issue(home, value):
    write(home / ".bashrc", 'export OPENAI_API_KEY="%s"\n' % value)
    out = run(home)
    assert [(f.severity, f.title) for f in out] == [
        ("info", "Agent credential variable set to a placeholder: OPENAI_API_KEY (%s:1)" % (home / ".bashrc"))]
    assert value not in out[0].description + out[0].remediation + repr(out[0].details)


@pytest.mark.parametrize("length,severity", [(19, "info"), (20, "high")])
def test_twenty_characters_is_where_a_value_counts_as_a_key(home, length, severity):
    write(home / ".bashrc", 'export OPENAI_API_KEY="%s"\n' % ("Zq7wRk2P" * 3)[:length], mode=0o600)
    assert [f.severity for f in run(home)] == [severity]


def test_long_lines_are_read_in_one_pass(home):
    """A line of thousands of ; or | used to be read once per separator (27 s for 20,000)."""
    import time
    write(home / ".bashrc", ";" * 20000 + "\n" + "|a" * 10000 + "\n" + "; '" + ";" * 20000 + "\n"
          + "alias c='claude --dangerously-skip-permissions'\n")
    start = time.time()
    assert [f.details["line"] for f in run(home)] == [4]
    assert time.time() - start < 5


def test_long_runs_of_continued_lines_are_read_in_one_pass(home):
    """Continued lines used to be read again with each line joined (233 s for 4,000)."""
    import time
    write(home / ".bashrc", "docker run \\\n" + "  --opt value \\\n" * 4000 + "  image\n"
          + "alias c='claude --dangerously-skip-permissions'\n")
    start = time.time()
    assert [f.details["line"] for f in run(home)] == [4003]
    assert time.time() - start < 5


def test_a_key_in_a_commented_out_line_is_a_note(home):
    write(home / ".bashrc", "# export ANTHROPIC_API_KEY=%s\nexport EDITOR=vim  # OPENAI_API_KEY=%s\n"
                            "# set -gx GEMINI_API_KEY %s\n# export OPENAI_API_KEY=your_key_goes_here\n"
                            % (ANTHROPIC_KEY, OPENAI_KEY, GEMINI_KEY))
    out = run(home)
    assert [(f.severity, f.details["variable"], f.details["line"]) for f in out] == [
        ("info", "ANTHROPIC_API_KEY", 1), ("info", "OPENAI_API_KEY", 2), ("info", "GEMINI_API_KEY", 3)]
    assert all("still in the file" in f.description and "revoke" in f.remediation for f in out)
    never_shown(out)


def test_fish_universal_variables_are_read(home):
    write(home / ".config" / "fish" / "fish_variables",
          "# This file contains fish universal variable definitions.\n# VERSION: 3.0\n"
          "SETUVAR __fish_initialized:3400\nSETUVAR --export ANTHROPIC_API_KEY:%s\n"
          "SETUVAR OPENAI_API_KEY:ollama\nSETUVAR fish_greeting:%s\nSETUVAR GEMINI_API_KEY:%s\n"
          % (fish_escape(ANTHROPIC_KEY), fish_escape(OPENAI_KEY), fish_escape("your-key-goes-here-please")),
          mode=0o600)
    out = run(home)
    path = home / ".config" / "fish" / "fish_variables"
    # the escapes are undone before the value is judged: your\x2dkey... is the placeholder your-key-...
    assert [(f.severity, f.details["variable"], f.details["line"]) for f in out] == [
        ("high", "ANTHROPIC_API_KEY", 4), ("info", "OPENAI_API_KEY", 5), ("info", "GEMINI_API_KEY", 7)]
    assert "set -Ue ANTHROPIC_API_KEY" in out[0].remediation and str(path) in out[0].title
    never_shown(out)
    never_shown(out, fish_escape(ANTHROPIC_KEY))


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads everything")
def test_unreadable_claude_settings_and_fish_variables_are_not_checked(home):
    write(home / ".claude" / "settings.json", {"permissions": {"defaultMode": "bypassPermissions"}}, mode=0o000)
    write(home / ".config" / "fish" / "fish_variables", "SETUVAR --export ANTHROPIC_API_KEY:x\n", mode=0o000)
    try:
        out = run(home)
    finally:
        os.chmod(str(home / ".claude" / "settings.json"), 0o644)
        os.chmod(str(home / ".config" / "fish" / "fish_variables"), 0o644)
    assert sorted((f.severity, f.details["path"]) for f in out) == [
        ("info", str(home / ".claude" / "settings.json")), ("info", str(home / ".config" / "fish" / "fish_variables"))]
    assert all("wasn't checked" in f.title for f in out)


def test_a_fish_set_line_with_many_flags_is_read_quickly():
    import time
    start = time.time()
    assert ag.credential_assignments("set " + "--a " * 20 + "X") == []   # took 8 s when each flag matched two ways
    assert ag.credential_assignments("set -g --export ANTHROPIC_API_KEY abc") == [("ANTHROPIC_API_KEY", "abc")]
    assert time.time() - start < 1


@pytest.mark.parametrize("line,found", [
    ("set -gx ANTHROPIC_API_KEY abc", [("ANTHROPIC_API_KEY", "abc")]),
    ("set ANTHROPIC_API_KEY", [("ANTHROPIC_API_KEY", "")]),
    ("set -Ux OPENAI_API_KEY 'a b'; set -x GEMINI_API_KEY \"c\"",
     [("OPENAI_API_KEY", "'a b'"), ("GEMINI_API_KEY", '"c"')]),
    ("begin; set -l x 1; set --export ANTHROPIC_AUTH_TOKEN t; end", [("ANTHROPIC_AUTH_TOKEN", "t")]),
    ("set -gx ANTHROPIC_API_KEY abc;echo", [("ANTHROPIC_API_KEY", "abc")]),
    # a set that starts inside another's flags reads the same name: one assignment, not two
    ("set -q/set -gx ANTHROPIC_API_KEY abc", [("ANTHROPIC_API_KEY", "abc")]),
    ("set -gx ANTHROPIC_API_KEY_OLD abc", []),          # another variable
    ("xset -gx ANTHROPIC_API_KEY abc", []),             # not set
    ("-set ANTHROPIC_API_KEY abc", []),
    ("set -gx X ANTHROPIC_API_KEY", []),                # the name isn't the first word after the flags
    ("set -gx", []), ("set ", []), ("set", []),
])
def test_fish_set_lines_are_read_as_before(line, found):
    """The one-pass reader reads fish's set as the old pattern did (verify round 2 changed only its speed)."""
    assert ag.credential_assignments(line) == found


def test_a_fish_file_full_of_sets_doesnt_slow_the_check(home):
    """The verifier's line: a 14 KB comment of sets in config.fish took 14.9 s through the scanner at 94cc7d5."""
    import time
    write(home / ".config" / "fish" / "config.fish",
          "# set " + "-x/set " * 2000 + "\nset " + "-x;set " * 2000 + "\nset \nset -gx\nalias cx 'codex --yolo'\n")
    start = time.time()
    assert [(f.severity, f.details["line"]) for f in run(home)] == [("medium", 5)]
    assert time.time() - start < 5


def test_a_one_line_triple_quoted_toml_value_ends_on_its_line(home):
    write(home / ".codex" / "config.toml", 'instructions = """be brief"""\napproval_policy = "never"\n'
                                           'sandbox_mode = "danger-full-access"\n')
    assert [f.details["profile"] for f in run(home)] == [None]


CODEX_PAIR = ("codex", "--ask-for-approval never with --sandbox danger-full-access")


@pytest.mark.parametrize("line,flags", [
    # fish: alias NAME DEFINITION (no =), and abbreviations, whose words fish joins and runs
    ("alias cx 'codex --yolo'", [("codex", "--yolo")]),
    ("alias --save cx 'codex --yolo'", [("codex", "--yolo")]),
    ("alias ca 'codex -a never -s danger-full-access'", [CODEX_PAIR]),
    ("alias -- cx='codex --yolo'", [("codex", "--yolo")]),
    ("abbr -a gy gemini --yolo", [("gemini", "--yolo")]),
    ("abbr --add --position anywhere gy -- gemini -y", [("gemini", "-y")]),
    ("abbr gy 'gemini --approval-mode yolo'", [("gemini", "--approval-mode yolo")]),
    ("abbr -a gy -r '^g$' gemini --yolo", [("gemini", "--yolo")]),
    ("abbr -a gy --regex '^g$' gemini --yolo", [("gemini", "--yolo")]),
    ("abbr -a gy -c git gemini --yolo", [("gemini", "--yolo")]),
    ("abbr -a gy --command git gemini --yolo", [("gemini", "--yolo")]),
    # an assignment's value can hold a command substitution with spaces in it
    ("alias g='GEMINI_API_KEY=$(secret-tool lookup service gemini) gemini -y'", [("gemini", "-y")]),
    ("x=$(echo $(codex --yolo))", [("codex", "--yolo")]),
    # the name escaped or quoted, as people do to skip an alias of the same name
    ("alias g2='\\gemini --yolo'", [("gemini", "--yolo")]),
    ('"gemini" --yolo', [("gemini", "--yolo")]),
    ("'codex' --yolo", [("codex", "--yolo")]),
    # wrappers, with their own options and values
    ("alias cx='timeout 3600 codex --yolo'", [("codex", "--yolo")]),
    ("timeout -s KILL 1h codex --yolo", [("codex", "--yolo")]),
    ("caffeinate -i codex --yolo", [("codex", "--yolo")]),
    ("stdbuf -oL gemini -y", [("gemini", "-y")]),
    ("uvx --from gemini-cli gemini --yolo", [("gemini", "--yolo")]),
    ("bun x @google/gemini-cli --yolo", [("gemini", "--yolo")]),
    ("npm exec -- @openai/codex --yolo", [("codex", "--yolo")]),
    ("npx -y @openai/codex@latest --yolo", [("codex", "--yolo")]),
    ("ls | xargs -n 1 codex --yolo", [("codex", "--yolo")]),
    ("watch -n 5 gemini -y", [("gemini", "-y")]),
    ("builtin command gemini -y", [("gemini", "-y")]),
    ("sudo -u alice codex --yolo", [("codex", "--yolo")]),
    ("nice -n 10 gemini --yolo", [("gemini", "--yolo")]),
    ("case $1 in y) gemini -y;; esac", [("gemini", "-y")]),
    # code run from a string
    ("eval 'codex --yolo'", [("codex", "--yolo")]),
    ("bash -lc 'codex --yolo'", [("codex", "--yolo")]),
    ("fish --command='gemini -y'", [("gemini", "-y")]),
    # attached option values and yargs' other spellings
    ("codex -anever -sdanger-full-access", [CODEX_PAIR]),
    ("gemini --approvalMode yolo", [("gemini", "--approval-mode yolo")]),
    ("gemini --yolo=true", [("gemini", "--yolo")]),
    # safe twins
    ("alias cx 'codex'", []),
    ("abbr -e gy", []),
    ("abbr -a gy -f yolo_gemini", []),            # expands through a function
    ("abbr -a x echo gemini --yolo", []),
    ("sudo -u codex make --yolo", []),            # codex is the account here
    ("timeout 3600 make gemini -y", []),
    ("echo $(date) gemini -y", []),               # still echo's argument after a substitution
    ("eval echo codex --yolo", []),
    ("bash -c 'echo codex --yolo'", []),
    ("bash setup.sh codex --yolo", []),
    ("gemini -- --yolo", []),                     # after --, words are the prompt
    ("gemini 'fix --yolo mode'", []),
    ("codex -a never; codex -s danger-full-access", []),   # each command keeps one safeguard
    ("alias cx='codex -a never' cy='codex -s danger-full-access'", []),
])
def test_agents_run_through_wrappers_aliases_and_abbreviations_are_found(line, flags):
    assert ag.skip_flags(line) == flags


# Every wrapper (with an option that takes a value), shell keyword, shell and package runner, written out here rather
# than read from the module's tables, so that dropping one from a table fails
@pytest.mark.parametrize("line", [
    "sudo codex --yolo", "doas -u alice codex --yolo", "env -u OPENAI_API_KEY codex --yolo", "env - codex --yolo",
    "command codex --yolo", "builtin codex --yolo", "exec -a cx codex --yolo", "nohup codex --yolo",
    "noglob codex --yolo", "nocorrect codex --yolo", "time -f %e codex --yolo", "nice -n 5 codex --yolo",
    "ionice -c 3 codex --yolo", "timeout -k 5 1h codex --yolo", "stdbuf -i 0 codex --yolo",
    "caffeinate -t 600 codex --yolo", "unbuffer codex --yolo", "watch -n 5 codex --yolo",
    "xargs -a list.txt codex --yolo", "npx -p tsx codex --yolo", "pnpx -p tsx codex --yolo",
    "bunx -p tsx codex --yolo", "uvx -p 3.12 codex --yolo", "PATH+=:/opt/bin codex --yolo",
    "if codex --yolo", "then codex --yolo", "else codex --yolo", "elif codex --yolo", "do codex --yolo",
    "while codex --yolo", "until codex --yolo", "! codex --yolo", "coproc codex --yolo", "and codex --yolo",
    "or codex --yolo", "not codex --yolo", "begin codex --yolo",
    "sh -c 'codex --yolo'", "bash -c 'codex --yolo'", "zsh -c 'codex --yolo'", "dash -c 'codex --yolo'",
    "ksh -c 'codex --yolo'", "fish -c 'codex --yolo'", "fish --command 'codex --yolo'", "bash -c -- 'codex --yolo'",
    "bash -o pipefail -c 'codex --yolo'", "bash +o posix -c 'codex --yolo'", "bash -O extglob -c 'codex --yolo'",
    "bash +O extglob -c 'codex --yolo'",
    "npm exec codex --yolo", "npm x codex --yolo", "pnpm dlx codex --yolo", "pnpm exec codex --yolo",
    "yarn dlx codex --yolo", "yarn exec codex --yolo", "bun x codex --yolo",
    "npm exec --package @openai/codex -- codex --yolo",
    # command substitutions and subshells, closed where the shell closes them
    'x=$(echo ")"; codex --yolo)', 'x="$(codex --yolo)"', "(codex --yolo)", "$(which sudo) codex --yolo",
    "eval codex --yolo", "alias x=\"eval 'bash -c \\\"codex --yolo\\\"'\"",   # three levels of code inside code
    "codex --yolo $(",   # a substitution that goes on to the next line
    "codex --model x#1 --yolo",   # a # inside a word isn't a comment
    "make build && codex --yolo", "sleep 1 & codex --yolo", "make || codex --yolo",
    # launchers 6d6abb4 found by matching anywhere and 94cc7d5's table missed (verify round 2), and their kin
    "asdf exec codex --yolo", "pixi exec codex --yolo", "pixi exec -s nodejs codex --yolo", "pixi run codex --yolo",
    "mise exec -- codex --yolo", "mise x node@20 python@3.12 -- codex --yolo", "mise -C ~/p exec -- codex --yolo",
    "mise exec -c 'codex --yolo'", "op run --env-file=.env -- codex --yolo", "op run --env-file .env -- codex --yolo",
    "op --account me run -- codex --yolo", "doppler run -- codex --yolo", "doppler run -p app -c dev -- codex --yolo",
    "doppler run --command 'codex --yolo'", "infisical run --env=dev -- codex --yolo",
    "infisical run --env dev -- codex --yolo", "infisical run --command='codex --yolo'", "dotenv -- codex --yolo",
    "dotenv -e .env -- codex --yolo", "dotenv run codex --yolo", "dotenv -f .env run -- codex --yolo",
    "envchain openai codex --yolo", "setsid -f codex --yolo", "flock /tmp/l codex --yolo",
    "flock -w 5 /tmp/l codex --yolo", "flock /tmp/l -c 'codex --yolo'", "taskset -c 0 codex --yolo",
    "taskset 0x3 codex --yolo", "uv run codex --yolo", "uv run --with rich codex --yolo", "uv tool run codex --yolo",
    "uv --directory x tool run --from y codex --yolo", "direnv exec . codex --yolo", "nvm exec 20 codex --yolo",
    "nvm exec codex --yolo", "nvm exec --silent lts/iron codex --yolo", "conda run -n ai codex --yolo",
    "mamba run -n ai codex --yolo", "micromamba run -p /opt/env codex --yolo", "poetry run codex --yolo",
    "pipenv run codex --yolo", "chrt -i 0 codex --yolo", "chrt -T 5 -i 0 codex --yolo",
    "systemd-run --user -u ai codex --yolo", "firejail --noprofile codex --yolo", "screen -dmS ai codex --yolo",
    "script -qc 'codex --yolo' /dev/null", "script -c 'codex --yolo'", "script -B t -c 'codex --yolo'",
    "sg docker -c 'codex --yolo'", "sg docker 'codex --yolo'", "env -S 'codex --yolo'", "env -S'codex' --yolo",
    "env --split-string='codex --yolo'", "env -C /tmp codex --yolo", "doas -a bsdauth codex --yolo",
    "ionice -p 1 codex --yolo", "watch -n5 'codex --yolo'", "watch 'codex --yolo'", "watch -q 3 codex --yolo",
    "su -c 'codex --yolo' bob", "su bob -c 'codex --yolo'", "su - bob --command='codex --yolo'",
    "su -lc 'codex --yolo' bob", "su -s /bin/sh -C 'codex --yolo' bob", "su --session-command='codex --yolo' bob",
    "flock /tmp/l --command 'codex --yolo'", "script --command 'codex --yolo'", "mise exec --command 'codex --yolo'",
    "tmux new -d 'codex --yolo'", "tmux new-session -d -s ai codex --yolo", "tmux -L work new-window 'codex --yolo'",
    "tmux split-window -h -t 1 'codex --yolo'", "tmux -c 'codex --yolo'", "tmux neww 'codex --yolo'",
    "tmux splitw 'codex --yolo'", "tmux respawn-pane -k 'codex --yolo'", "tmux respawnp 'codex --yolo'",
    "tmux respawn-window 'codex --yolo'", "tmux respawnw 'codex --yolo'", "nvm exec node codex --yolo",
    "nvm exec v20.1 codex --yolo", "nvm exec default codex --yolo", "nvm exec system codex --yolo",
    "nvm exec stable codex --yolo", "nvm exec unstable codex --yolo", "nvm exec iojs codex --yolo",
    # getopt's ways to give a value: clustered (-Hu bob), attached (-ubob), long (--user bob), and -- ending them
    "sudo -Hu bob codex --yolo", "sudo -iu bob codex --yolo", "sudo -EHu bob codex --yolo", "sudo -ubob codex --yolo",
    "sudo --user bob codex --yolo", "sudo --user=bob codex --yolo", "sudo -- codex --yolo",
    "sudo -c staff codex --yolo", "sudo -a pam codex --yolo", "sudo -ulou codex --yolo",   # a user named lou
    # a substitution that looks the program up runs it
    "$(which codex) --yolo", '"$(command -v codex)" --yolo', "`type -p codex` --yolo", "$(which -a codex) --yolo",
    "$(which /usr/local/bin/codex) --yolo", "(command -s codex) --yolo", "$(which $(which codex)) --yolo",
    "$(command --search codex) --yolo", "$(type -P codex) --yolo", "$(whence -p codex) --yolo",
    "$(which /" + "opt/" * 20 + "codex) --yolo",   # a long path to a short name
    "$(which) codex --yolo", "$(which -a) codex --yolo",   # nothing looked up: no output, and codex is the command
    # a redirection's target isn't a word of the command, and it can touch the words around it
    "codex --yolo>log", "codex 2>&1 --yolo", "codex &>log --yolo", "codex --yolo&>log", ">log codex --yolo",
    "codex <<<input --yolo", "codex >>log --yolo", "codex 2> /dev/null --yolo", "codex > $(mktemp) --yolo",
    "x=$(codex 2>&1 --yolo)", "make >$(codex --yolo)",   # a substitution in a target still runs
    "/usr/bin/env codex --yolo",
    # a | after > is a pipe, as in fish's 2>| (bash's >| would write to a file named codex; read as a pipe, to find it)
    "make 2>| codex --yolo",
])
def test_every_wrapper_keyword_shell_and_runner_is_read_through(line):
    assert ag.skip_flags(line) == [("codex", "--yolo")]


@pytest.mark.parametrize("line", [
    # where the agent's name is a value, a tool, a file, an account or a namespace, not the program run
    "sudo -Hu codex make --yolo", "sudo -ucodex make --yolo", "su codex -c 'make --yolo'", "su -c 'echo codex --yolo'",
    "mise exec codex -- make --yolo", "mise exec codex --yolo", "flock /tmp/codex make --yolo",
    "envchain codex make --yolo", "direnv exec codex make --yolo", "taskset codex make --yolo",
    "nvm exec 20 make codex --yolo", "tmux new -s codex make --yolo", "watch -n 5 'echo codex --yolo'",
    "op run -- make codex --yolo", "sg codex 'make --yolo'", "timeout 5 make codex --yolo", "chrt 0 make codex --yolo",
    # a redirection's target is a file, and an escaped \$( isn't a substitution
    "codex > --yolo", "codex 2>--yolo", "codex >--yolo &", "x=$(codex >--yolo)", "codex >--yolo>x",
    "uv tool install codex --yolo", 'echo "\\$(codex --yolo)"',
    "echo $(which codex) --yolo", "$(which codex --yolo)", "$(command codex) --yolo", "$(command -p codex) --yolo",
    "$(which make) codex --yolo", "command -v codex >/dev/null && echo --yolo", "dotenv run make codex --yolo",
    # su runs only the code its -c gives, and its other words are an account and the shell's arguments
    "su -c codex bob --yolo", "su -- codex --yolo",
    # tmux's own words name tmux commands, and after one, -c names its starting folder
    "tmux codex --yolo", "tmux attach -c 'codex --yolo'",
])
def test_launchers_read_the_agent_only_where_it_runs(line):
    assert ag.skip_flags(line) == []


UVX = ("-p -w -f --from --with --with-editable --with-requirements --python --index --index-url --extra-index-url "
       "--default-index --find-links")
NPX = "-p --package"
# Every option a launcher reads a value for, written out here rather than read from the module's tables: dropping one
# would read its value (V) as the program run, and codex would go unfound
LAUNCHER_OPTIONS = [
    ("sudo %s V codex --yolo", "-a -C -c -D -g -p -R -r -T -t -U -u --auth-type --close-from --login-class --chdir "
                               "--group --host --prompt --chroot --role --type --command-timeout --other-user --user"),
    ("doas %s V codex --yolo", "-a -C -u"), ("env %s V codex --yolo", "-C -u --chdir --unset"),
    ("exec %s V codex --yolo", "-a"), ("time %s V codex --yolo", "-f -o --format --output"),
    ("nice %s V codex --yolo", "-n --adjustment"),
    ("ionice %s V codex --yolo", "-c -n -p -P -u --class --classdata --pid --pgid --uid"),
    ("timeout %s V 1h codex --yolo", "-k -s --kill-after --signal"),
    ("stdbuf %s V codex --yolo", "-i -o -e --input --output --error"), ("caffeinate %s V codex --yolo", "-t -w"),
    ("chrt %s V 0 codex --yolo", "-T -P -D --sched-runtime --sched-period --sched-deadline"),
    ("flock %s V /tmp/l codex --yolo", "-w -E --wait --timeout --conflict-exit-code"),
    ("watch %s V codex --yolo", "-n -q --interval --equexit"),
    ("xargs %s V codex --yolo", "-a -d -E -I -L -n -P -s --arg-file --delimiter --max-lines --max-args --max-procs "
                                "--max-chars --process-slot-var"),
    ("npx %s V codex --yolo", NPX), ("pnpx %s V codex --yolo", NPX), ("bunx %s V codex --yolo", NPX),
    ("npm exec %s V codex --yolo", NPX), ("npm x %s V codex --yolo", NPX), ("pnpm dlx %s V codex --yolo", NPX),
    ("pnpm exec %s V codex --yolo", NPX), ("yarn dlx %s V codex --yolo", NPX), ("yarn exec %s V codex --yolo", NPX),
    ("bun x %s V codex --yolo", NPX), ("uvx %s V codex --yolo", UVX), ("uv tool run %s V codex --yolo", UVX),
    ("uv run %s V codex --yolo", UVX + " --extra --group --only-group --package --env-file --directory --project"),
    ("uv %s V run codex --yolo", "--directory --project --cache-dir --config-file"),
    ("dotenv %s V -- codex --yolo", "-e -v -p"), ("dotenv %s V run codex --yolo", "-f -q -e --file --quote --export"),
    ("script %s V -c 'codex --yolo'", "-E -I -O -B -T -m --echo --log-in --log-out --log-io --log-timing "
                                      "--logging-format"),
    ("screen %s V codex --yolo", "-c -e -h -p -S -s -t -T"),
    ("systemd-run %s V codex --yolo", "-u -p -E -M -H --unit --property --setenv --machine --host --slice "
                                      "--description --uid --gid --nice --working-directory"),
    ("tmux %s V new codex --yolo", "-c -f -L -S -T"), ("tmux %s V -c 'codex --yolo'", "-f -L -S -T"),
    ("tmux new %s V codex --yolo", "-c -e -F -f -l -n -p -s -t -x -y"),
    ("pixi exec %s V codex --yolo", "-s -c -w --spec --channel --with --platform"),
    ("pixi run %s V codex --yolo", "-e --environment --manifest-path"),
    ("mise %s V exec -- codex --yolo", "-C -E -j --cd --env --jobs"),
    ("op %s V run -- codex --yolo", "--account --cache --config --encoding --session"),
    ("op run %s V codex --yolo", "--env-file --account --cache --config --encoding --session"),
    ("doppler %s V run codex --yolo", "--scope --token --api-host --configuration"),
    ("doppler run %s V codex --yolo", "-p -c --project --config --token --scope --name-transformer --mount "
                                      "--mount-format --mount-template --mount-max-reads --fallback"),
    ("infisical %s V run codex --yolo", "--domain --token"),
    ("infisical run %s V codex --yolo", "--env --path --projectId --token --tags --domain"),
    ("conda run %s V codex --yolo", "-n -p --name --prefix --cwd"), ("mamba run %s V codex --yolo", "-n -p --name"),
    ("micromamba run %s V codex --yolo", "-n -p --prefix --cwd"),
]


@pytest.mark.parametrize("template,options", LAUNCHER_OPTIONS, ids=[t.split(" %s")[0] for t, _ in LAUNCHER_OPTIONS])
def test_every_option_a_launcher_takes_a_value_for_is_read_with_its_value(template, options):
    missed = [o for o in options.split() if ag.skip_flags(template % o) != [("codex", "--yolo")]]
    assert missed == []


@pytest.mark.parametrize("line,flags", [
    ("codex -a=never -s=danger-full-access", [CODEX_PAIR]),
    ("codex -c 'approval_policy = never' -c 'sandbox_mode = \"danger-full-access\"'", [CODEX_PAIR]),
    ("gemini --yolo -y --approval-mode yolo", [("gemini", "--yolo"), ("gemini", "-y"), ("gemini", "--approval-mode yolo")]),
    # twins: where the shell would read the line otherwise
    ("echo `date` gemini -y", []),         # the second backtick closes the first
    ('"\\gemini" --yolo', []),             # in double quotes, \g keeps its backslash: no such program
    ("echo a\\; gemini -y", []),            # an escaped ; is a word, not the end of the command
    ("echo ${HOME} gemini -y", []),        # a { inside a word doesn't start a command
    ("alias x='codex # --yolo later'", []),
    ("echo 'x; gemini -y'", []),
    ("bash -- codex --yolo", []),          # bash runs a script named codex
    ("zsh --no-rcs 'codex --yolo'", []),   # a script file of that name; a long option isn't -c
    ("sh 'gemini -y'", []),
    ("gemini -a never -s danger-full-access", []),
    ("alias n=npm", []),
    ("gemini --approval-mode", []),
    # a redirection between an option and its value isn't the value
    ("codex -a 2>/dev/null never -s danger-full-access", [CODEX_PAIR]),
])
def test_options_and_quoting_are_read_as_the_tools_and_shell_read_them(line, flags):
    assert ag.skip_flags(line) == flags


def test_an_option_left_without_its_value_doesnt_stop_the_check(home, monkeypatch):
    """An option at the end of a line has no value to read. Through the scanner a crash on it would replace every
    finding of the check with "Check couldn't run"."""
    monkeypatch.setattr(scanner, "_home", lambda: home)
    for name in ag.CRED_VARS + ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    write(home / ".bashrc", "alias g='gemini --approval-mode'\nalias c='codex -a'\nalias s='codex -s'\n"
                            "alias x='codex --config'\nalias f='fish --command'\nalias b='bash -o'\n"
                            "alias y='gemini --yolo'\n")
    result = SentinelScanner(checks=["agent_safety"]).scan()
    assert [(f.severity, f.details.get("line")) for f in result.findings] == [("medium", 7)]


def test_the_name_of_an_alias_or_abbreviation_with_options_is_reported(home):
    write(home / ".config" / "fish" / "config.fish",
          "alias --save cx 'codex --yolo'\nalias -- cy='codex --yolo'\nabbr -a -p anywhere gz gemini -y\n")
    assert [(f.details["name"], f.description.count("(abbreviation gz)")) for f in run(home)] == [
        ("cx", 0), ("cy", 0), ("gz", 1)]


def test_fish_aliases_abbreviations_and_wrapped_agents_are_reported_by_name(home):
    """6d6abb4 found each of these; the command-position rule of 78ae22d found none."""
    write(home / ".config" / "fish" / "config.fish",
          "alias cx 'codex --yolo'\nabbr -a gy gemini --yolo\nalias ca 'codex -a never -s danger-full-access'\n")
    write(home / ".bashrc", "alias g='GEMINI_API_KEY=$(secret-tool lookup service gemini) gemini -y'\n"
                            "alias g2='\\gemini --yolo'\nalias cx='timeout 3600 codex --yolo'\n")
    out = run(home)
    assert sorted((Path(f.details["path"]).name, f.details["line"], f.severity, f.details["name"], f.details["flags"])
                  for f in out) == [
        (".bashrc", 1, "medium", "g", ["gemini -y"]), (".bashrc", 2, "medium", "g2", ["gemini --yolo"]),
        (".bashrc", 3, "medium", "cx", ["codex --yolo"]), ("config.fish", 1, "medium", "cx", ["codex --yolo"]),
        ("config.fish", 2, "medium", "gy", ["gemini --yolo"]),
        ("config.fish", 3, "medium", "ca", ["codex --ask-for-approval never with --sandbox danger-full-access"])]
    assert "(abbreviation gy)" in next(f for f in out if f.details["name"] == "gy").description


@pytest.mark.parametrize("read,text", [
    # ( and { each started another try over the rest of the word. Each input here took 8 s or more at 78ae22d
    pytest.param(ag.skip_flags, "(" * 10000, id="parens"),
    pytest.param(ag.skip_flags, "{" * 10000, id="braces"),
    pytest.param(ag.skip_flags, "X=(" * 2100, id="assignments"),
    # an unclosed ${NAME:- scanned on to the end of the line, once per occurrence
    pytest.param(ag.credential_assignments, "${ANTHROPIC_API_KEY:-" * 4000, id="defaults"),
    # from each -set, the flags after it were tried again
    pytest.param(ag.credential_assignments, "set " + "-set " * 2500, id="fish-set"),
    # and from each set after any other character but a letter, digit, _ or -: 17 s for 2,000 at 94cc7d5
    pytest.param(ag.credential_assignments, "set " + "-a/set " * 2500, id="fish-set-after-slash"),
    pytest.param(ag.credential_assignments, "set " + "".join("-a%sset " % c for c in "/;'(.:=") * 400,
                 id="fish-set-after-punctuation"),
    # a looked-up program's name was copied into every level of nested $(which $(which ...)): 6 s for 43 KB
    pytest.param(ag.skip_flags, "$(which " * 3000 + "A" * 16000 + ")" * 3000, id="nested-lookups"),
    # every launcher and redirection, chained: each reads its own words once
    pytest.param(ag.skip_flags, "mise x a -- op run -- su -c tmux new watch sg g dotenv run 2>&1 >x " * 300,
                 id="launchers"),
    # \s* around a lazy name that can hold spaces
    pytest.param(ag.toml_tables, "[" + " " * 1400 + "x", id="toml-header"),
    # redact() on thousands of characters of a-a-a-
    pytest.param(ag._looks_like_key, "a-" * 2500 + "a", id="redact"),
    # code inside code is read a few levels deep, not once per eval
    pytest.param(ag.skip_flags, "eval " * 5000 + "codex --yolo", id="evals"),
])
def test_text_built_to_be_slow_is_read_in_one_pass(read, text):
    import time
    start = time.time()
    read(text)
    assert time.time() - start < 2


def test_slow_lines_in_a_shell_file_dont_slow_the_check(home):
    import time
    write(home / ".bashrc", "(" * 8000 + "\n" + "{" * 8000 + "\n" + "\\a" * 20000 + "\n" + "$(" * 8000 + "\n"
          + "export CFG='[" + ",".join('{"k%d":"v%d"}' % (i, i) for i in range(800)) + "]'\n"
          + 'export OPENAI_API_KEY="' + "a-" * 2000 + 'a"\n' + "alias c='codex --yolo'\n")
    start = time.time()
    assert [(f.severity, f.details["line"]) for f in run(home)] == [("info", 6), ("medium", 7)]
    assert time.time() - start < 5


@pytest.mark.parametrize("length,key", [(256, True), (257, False)])
def test_a_long_placeholder_shaped_value_is_checked_for_a_token_up_to_256_characters(length, key):
    # all lowercase with a dash, so it reads as a placeholder; redact() knows sk- as a key's start
    assert ag._looks_like_key("sk-" + "a" * (length - 3)) is key


DEEP = "[" * 100000 + "]" * 100000


def test_json_nested_too_deep_is_not_checked_and_the_rest_still_reported(home, monkeypatch):
    """A project folder can hold a file nested too deep for Python's JSON parser. That file isn't checked; every other
    finding of the check still comes through (through the scanner, a crash would lose them all)."""
    monkeypatch.setattr(scanner, "_home", lambda: home)
    for name in ag.CRED_VARS + ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    write(home / "code" / "evil" / ".claude" / "settings.json", DEEP)
    write(home / "code" / "victim" / ".claude" / "settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    write(home / ".claude" / ".credentials.json", "{}", mode=0o644)
    write(home / ".gemini" / "settings.json", DEEP)
    write(home / ".config" / "Code" / "User" / "settings.json", DEEP)
    result = SentinelScanner(checks=["agent_safety"]).scan()
    got = sorted((f.severity, f.details.get("path")) for f in result.findings)
    assert got == [("high", str(home / ".claude" / ".credentials.json")),
                   ("high", str(home / "code" / "victim" / ".claude" / "settings.json")),
                   ("info", str(home / ".config" / "Code" / "User" / "settings.json")),
                   ("info", str(home / ".gemini" / "settings.json")),
                   ("info", str(home / "code" / "evil" / ".claude" / "settings.json"))]


def test_json_nested_too_deep_doesnt_stop_the_persistence_or_mcp_checks(home, monkeypatch):
    """Through the scanner, a check that stops becomes one "Check couldn't run" finding and loses all its others."""
    monkeypatch.setattr(scanner, "_home", lambda: home)
    evil = home / "code" / "evil"
    planted = [evil / ".claude" / "settings.json", evil / ".mcp.json", home / ".claude.json"]
    for path in planted:
        write(path, DEEP)
    findings = SentinelScanner(checks=["persistence", "mcp_servers"]).scan().findings
    assert [f.title for f in findings if "couldn't run" in f.title] == []
    assert sorted((f.check, f.severity, f.details.get("path")) for f in findings
                  if f.details.get("path") in {str(p) for p in planted}) == [
        ("mcp_servers", "info", str(home / ".claude.json")), ("mcp_servers", "info", str(evil / ".mcp.json")),
        ("persistence", "info", str(evil / ".claude" / "settings.json"))]


def test_python_and_friends_in_your_allow_list_are_advice(home):
    write(home / ".claude" / "settings.local.json", {"permissions": {"allow": [
        "Bash(git:*)", "Bash(python3:*)", "Bash(xargs:*)", "Bash(sudo apt:*)"]}})
    out = run(home)
    assert [(f.severity, f.details["settings"]) for f in out] == [
        ("medium", ['permissions.allow "Bash(python3:*)", "Bash(xargs:*)"'])]
    assert "python3, bash, env and the like run whatever they're given" in out[0].description
    write(home / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash(*)"]}})
    assert "run whatever they're given" not in run(home)[0].description
    write(home / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash(*)", "Bash(env:*)"]}})
    assert "run whatever they're given" in run(home)[0].description


# ── Login files and the environment ──

def test_login_files_open_to_others_are_high(home, tmp_path):
    write(home / ".claude" / ".credentials.json", '{"token": "%s"}' % OAUTH_TOKEN, mode=0o644)
    write(home / ".codex" / "auth.json", '{"OPENAI_API_KEY": "%s"}' % OPENAI_KEY, mode=0o640)
    write(home / ".gemini" / "oauth_creds.json", "{}", mode=0o600)
    write(tmp_path / "work" / ".credentials.json", "{}", mode=0o604)
    out = run(home, {"CLAUDE_CONFIG_DIR": str(tmp_path / "work")})
    got = sorted((f.severity, f.details["tool"], f.details["mode"]) for f in out)
    assert got == [("high", "Claude Code", "604"), ("high", "Claude Code", "644"), ("high", "Codex", "640")]
    claude = next(f for f in out if f.details["mode"] == "644")
    assert "chmod 600 %s" % (home / ".claude" / ".credentials.json") in claude.remediation
    assert "chmod 644" in claude.remediation   # the undo
    assert "every account on this machine" in claude.description
    assert "accounts in its group" in next(f for f in out if f.details["tool"] == "Codex").description
    never_shown(out)


def test_gemini_and_codex_home_login_files(home, tmp_path):
    write(home / ".gemini" / "oauth_creds.json", "{}", mode=0o644)
    write(tmp_path / "codex" / "auth.json", "{}", mode=0o666)
    out = run(home, {"CODEX_HOME": str(tmp_path / "codex")})
    assert sorted((f.details["tool"], f.details["mode"]) for f in out) == [("Codex", "666"), ("Gemini CLI", "644")]


def test_login_files_for_you_only_are_quiet(home):
    write(home / ".claude" / ".credentials.json", "{}", mode=0o600)
    write(home / ".codex" / "auth.json", "{}", mode=0o400)
    assert run(home) == []


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads everything")
def test_what_sereno_cant_read_is_not_checked_never_clean(home):
    write(home / ".bashrc", "alias c='claude --dangerously-skip-permissions'\n", mode=0o000)
    write(home / ".codex" / "auth.json", "{}", mode=0o644)
    os.chmod(str(home / ".codex"), 0o000)
    try:
        out = run(home)
    finally:
        os.chmod(str(home / ".codex"), 0o755)
        os.chmod(str(home / ".bashrc"), 0o644)
    # a locked ~/.codex hides both its config and its login file: each is "not checked", neither is clean
    assert sorted((f.severity, f.details["path"]) for f in out) == [
        ("info", str(home / ".bashrc")), ("info", str(home / ".codex" / "auth.json")),
        ("info", str(home / ".codex" / "config.toml"))]
    assert all("wasn't checked" in f.title for f in out)


def test_credentials_in_the_environment_are_a_note_by_name(home):
    out = run(home, {"ANTHROPIC_API_KEY": ANTHROPIC_KEY, "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN, "OPENAI_API_KEY": "",
                     "PATH": "/usr/bin"})
    assert [(f.severity, f.details["variables"]) for f in out] == [
        ("info", ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"])]
    never_shown(out)
    assert run(home, {"PATH": "/usr/bin"}) == []


def test_no_secret_value_appears_anywhere(home, tmp_path):
    """Every place a planted secret can sit, at once: settings env, shell files, a login file, the environment."""
    write(home / ".claude" / "settings.json", {"env": {"ANTHROPIC_API_KEY": ANTHROPIC_KEY},
                                               "permissions": {"defaultMode": "bypassPermissions"}})
    write(home / ".claude" / ".credentials.json", '{"accessToken": "%s"}' % OAUTH_TOKEN, mode=0o644)
    write(home / ".bashrc", "export OPENAI_API_KEY=%s\nalias g='GEMINI_API_KEY=%s gemini --yolo'\n"
                            % (OPENAI_KEY, GEMINI_KEY))
    write(home / ".config" / "fish" / "config.fish", "set -Ux CLAUDE_CODE_OAUTH_TOKEN %s\n" % OAUTH_TOKEN)
    write(home / ".config" / "fish" / "fish_variables",
          "SETUVAR --export ANTHROPIC_API_KEY:%s\n" % fish_escape(ANTHROPIC_KEY))
    write(home / ".zshrc", "# export ANTHROPIC_API_KEY=%s\nexport OPENAI_API_KEY=${OPENAI_API_KEY:-%s}\n"
                           % (ANTHROPIC_KEY, OPENAI_KEY))
    out = run(home, {"ANTHROPIC_API_KEY": ANTHROPIC_KEY, "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN})
    # 2 in settings, the login file, 3 in .bashrc, 1 in fish, 1 in fish_variables, 2 in .zshrc, the environment note
    assert len(out) == 11
    never_shown(out)
    never_shown(out, fish_escape(ANTHROPIC_KEY))


# ── Wired into the scanner and the docs ──

def test_the_scanner_runs_it_by_default_and_by_name(home, monkeypatch):
    monkeypatch.setattr(scanner, "_home", lambda: home)
    for name in ag.CRED_VARS + ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    write(home / ".bashrc", "alias c='claude --dangerously-skip-permissions'\n")
    assert "agent_safety" in CHECK_NAMES and "agent_safety" in SentinelScanner()._checks
    result = SentinelScanner(checks=["agent_safety"]).scan()
    assert [(f.check, f.severity) for f in result.findings] == [("agent_safety", "medium")]
    (home / ".bashrc").unlink()
    result = SentinelScanner(checks=["agent_safety"]).scan()
    assert result.findings == [] and result.checks_clean == 1
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)      # the scanner reads the real environment
    result = SentinelScanner(checks=["agent_safety"]).scan()
    assert [(f.severity, f.details["variables"]) for f in result.findings] == [("info", ["ANTHROPIC_API_KEY"])]
    never_shown(result.findings)


def test_the_readme_lists_every_check_name():
    readme = (Path(__file__).parent.parent / "README.md").read_text()
    line = next(l for l in readme.splitlines() if l.startswith("Check names for `--checks`"))
    assert all("`%s`" % name in line for name in CHECK_NAMES)
