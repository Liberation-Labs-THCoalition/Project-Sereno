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
from sentinel import scanner
from sentinel.scanner import CHECK_NAMES, Finding, SentinelScanner

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
    monkeypatch.setattr(ag, "_git_tracked", lambda path: False)
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
    ("Bash", True), ("Bash(*)", True), ("Bash(:*)", True), ("Bash( * )", True), ("Shell", True), ("Shell *", True),
    ("PowerShell", True), ("PowerShell(*)", True),
    ("Bash(npm run *)", False), ("Bash(ls*)", False), ("Bash()", False), ("Bashful", False), ("WebFetch", False),
    ("Bash(git:*)", False), ("mcp__srv__tool", False), ("bash", False),
])
def test_broad_shell_rule(rule, broad):
    assert bool(ag.BROAD_SHELL_RULE.match(rule)) is broad


def test_the_warning_alone_is_named_as_a_warning(home):
    write(home / ".claude" / "settings.json", {"skipDangerousModePermissionPrompt": True})
    out = run(home)
    assert [f.title for f in out] == ["Claude Code warning before bypass mode turned off in your settings"]
    assert "removes only that warning" in out[0].description and "hidden in a file" not in out[0].description


def test_a_projects_settings_are_high(home):
    write(home / "code" / "app" / ".claude" / "settings.json", {
        "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}, "enableAllProjectMcpServers": True})
    out = run(home)
    assert sev_titles(out) == [("high", "A project folder switches off Claude Code's safety prompts: %s"
                                % (home / "code" / "app"))]
    assert "2.1.257" in out[0].description and "once you trust the folder" in out[0].description
    assert out[0].details["scope"] == "project"


def test_a_shared_project_file_cant_skip_the_warning(home):
    """Claude Code ignores skipDangerousModePermissionPrompt in a shared .claude/settings.json, and honors it in a
    project's settings.local.json."""
    write(home / "code" / "app" / ".claude" / "settings.json", {"skipDangerousModePermissionPrompt": True})
    assert run(home) == []
    write(home / "code" / "app" / ".claude" / "settings.local.json", {"skipDangerousModePermissionPrompt": True})
    assert [f.details["settings"] for f in run(home)] == [["skipDangerousModePermissionPrompt"]]


@pytest.mark.parametrize("tracked,severity,says", [
    (False, "medium", "Git doesn't track the file"),
    (True, "high", "Git tracks this settings.local.json"),
    (None, "high", "couldn't ask git"),
])
def test_a_projects_local_file_is_yours_only_when_git_doesnt_track_it(home, monkeypatch, tracked, severity, says):
    write(home / "code" / "app" / ".claude" / "settings.local.json", {"permissions": {"allow": ["Bash"]}})
    monkeypatch.setattr(ag, "_git_tracked", lambda path: tracked)
    out = run(home)
    assert [(f.severity, f.details["git_tracked"]) for f in out] == [(severity, tracked)]
    assert says in out[0].description


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_git_decides_whose_local_file_it_is(home, monkeypatch):
    from sentinel.mcp import _git_tracked
    monkeypatch.setattr(ag, "_git_tracked", _git_tracked)
    proj = home / "code" / "app"
    write(proj / ".claude" / "settings.local.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    subprocess.run(["git", "init", "-q", str(proj)], check=True)
    assert [f.severity for f in run(home)] == ["medium"]
    subprocess.run(["git", "-C", str(proj), "add", ".claude/settings.local.json"], check=True)
    assert [f.severity for f in run(home)] == ["high"]


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
        "# export ANTHROPIC_API_KEY=%s" % ANTHROPIC_KEY,
        "export MY_ANTHROPIC_API_KEY=%s" % ANTHROPIC_KEY,   # not an agent variable
        'echo "${ANTHROPIC_API_KEY:-unset}"', ""]))
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
             ".config/fish/config.fish", ".config/fish/conf.d/agents.fish", ".config/fish/functions/c.fish"]
    for name in names:
        write(home / name, "alias c='claude --dangerously-skip-permissions'\n")
    write(home / ".config" / "fish" / "conf.d" / "notes.txt", "alias c='claude --dangerously-skip-permissions'\n")
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
    out = run(home, {"ANTHROPIC_API_KEY": ANTHROPIC_KEY, "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN})
    assert len(out) == 8   # 2 in settings, the login file, 3 in .bashrc, 1 in fish, the environment note
    never_shown(out)


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
