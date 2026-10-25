"""The MCP check: which launches are pinned, which configs it reads, and that it reports secrets by name only."""
import json
import os
import shutil
import subprocess
import sys

import pytest

from sentinel import mcp
from sentinel.scanner import Finding, SentinelScanner


def make(severity, title, description, remediation, details):
    return Finding(check="mcp_servers", severity=severity, title=title, description=description,
                   remediation=remediation, details=details)


SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize("command,args,name,pinned", [
    ("npx", ["-y", "pkg"], "pkg", False),
    ("npx", ["-y", "pkg@1.2.3"], "pkg", True),
    ("npx", ["-y", "@scope/pkg"], "@scope/pkg", False),
    ("npx", ["-y", "@scope/pkg@1.2.3"], "@scope/pkg", True),
    ("npx", ["pkg@latest"], "pkg", False),
    ("npx", ["-y", "pkg@^1.0.0"], "pkg", False),
    ("npx", ["--package=pkg@1.2.3", "cmd"], "pkg", True),
    ("npx", ["-p", "pkg", "cmd"], "pkg", False),
    ("npx", ["--", "pkg"], "pkg", False),
    ("C:\\tools\\npx.cmd", ["-y", "pkg"], "pkg", False),
    ("pnpm", ["dlx", "pkg"], "pkg", False),
    ("yarn", ["dlx", "pkg@1.0.0"], "pkg", True),
    ("npm", ["exec", "pkg"], "pkg", False),
    ("bun", ["x", "pkg"], "pkg", False),
    ("npx -y pkg", [], "pkg", False),
    ("npx", ["-y", "github:user/repo"], "github:user/repo", False),
    ("npx", ["-y", "github:user/repo#" + SHA], "github:user/repo#" + SHA, True),
    ("uvx", ["mcp-server-fetch"], "mcp-server-fetch", False),
    ("uvx", ["mcp-server-fetch==1.2.0"], "mcp-server-fetch", True),
    ("uvx", ["mcp-server-fetch@1.2.0"], "mcp-server-fetch", True),
    ("uvx", ["--from", "pkg==1.0", "cmd"], "pkg", True),
    ("uvx", ["--from", "pkg>=1.0", "cmd"], "pkg", False),
    ("uvx", ["--python", "3.12", "pkg"], "pkg", False),
    ("uvx", ["pkg@latest"], "pkg", False),     # uvx's explicit "always the newest" form
    ("uvx", ["pkg==1.*"], "pkg", False),
    ("uv", ["tool", "run", "pkg"], "pkg", False),
    ("pipx", ["run", "pkg"], "pkg", False),
    ("pipx", ["run", "--spec", "pkg==2.0", "cmd"], "pkg", True),
])
def test_launched_package(command, args, name, pinned):
    got = mcp.launched_package(command, args)
    assert got is not None and (got["name"], got["pinned"]) == (name, pinned)


@pytest.mark.parametrize("command,args", [("node", ["/srv/server.js"]), ("python", ["-m", "server"]),
                                          ("docker", ["run", "-i", "image"]), ("", []), ("npx", [])])
def test_commands_that_launch_no_registry_package(command, args):
    assert mcp.launched_package(command, args) is None


def test_a_local_path_is_not_flagged():
    got = mcp.launched_package("npx", ["-y", "./my-server"])
    assert got["kind"] == "local" and got["pinned"] is True


def test_jsonc_comments_and_trailing_commas_go_but_strings_stay():
    text = '{\n // a note\n "servers": { /* block */ "a": {"url": "https://x.example/p", "s": "say \\"//hi\\""},},\n}'
    try:
        data = json.loads(mcp.strip_jsonc(text))
    except ValueError:
        data = "not valid JSON after stripping"
    assert data == {"servers": {"a": {"url": "https://x.example/p", "s": 'say "//hi"'}}}


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


TOKEN = "ghp_" + "a1" * 18


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.delenv("APPDATA", raising=False)
    return h


def titles(findings):
    return sorted((f.severity, f.title) for f in findings)


def test_user_and_project_configs_are_read(home):
    deep = home / "a" / "b" / "c" / "d" / "e"
    write(home / ".claude.json", {
        "mcpServers": {"loose": {"command": "npx", "args": ["-y", "loose-server"]},
                       "pinned": {"command": "npx", "args": ["-y", "pinned-server@1.2.3"]}},
        "projects": {str(deep): {"mcpServers": {"proj": {"command": "uvx", "args": ["proj-tool"]}}}}})
    write(home / ".cursor" / "mcp.json", '{ // Cursor allows comments\n "mcpServers": {"cur": {"command": "npx",'
                                         ' "args": ["cursor-server"]}}, }')
    write(home / "code" / "app" / ".mcp.json", {"mcpServers": {"shared": {"command": "npx", "args": ["shared"]}}})
    write(deep / ".mcp.json", {"mcpServers": {"deep": {"command": "npx", "args": ["deep-server"]}}})
    out = mcp.check_mcp_servers(make, home)
    names = sorted(f.details["package"] for f in out if "no fixed version" in f.title)
    # deep-server is past the walk's depth, but its folder is a Claude Code project, so it's read
    assert names == ["cursor-server", "deep-server", "loose-server", "proj-tool", "shared"]
    assert all(f.severity == "medium" for f in out)
    proj = next(f for f in out if f.details["package"] == "proj-tool")
    assert str(deep) in proj.title


def test_a_project_config_past_the_walk_and_not_a_known_project_is_not_read(home):
    write(home / "a" / "b" / "c" / "d" / "e" / ".mcp.json",
          {"mcpServers": {"deep": {"command": "npx", "args": ["deep-server"]}}})
    assert mcp.check_mcp_servers(make, home) == []


def test_vscode_uses_servers_not_mcpServers(home):
    write(home / ".config" / "Code" / "User" / "mcp.json", {"servers": {"v": {"command": "npx", "args": ["v-srv"]}},
                                                            "mcpServers": {"x": {"command": "npx", "args": ["x"]}}})
    assert [f.details["package"] for f in mcp.check_mcp_servers(make, home)] == ["v-srv"]


def test_a_known_bad_package_is_high(home):
    write(home / ".claude.json", {"mcpServers": {
        "a": {"command": "npx", "args": ["-y", "safe-action"]},
        "b": {"command": "npx", "args": ["-y", "@tanstack/router-mcp"]},
        "c": {"command": "uvx", "args": ["Guardrails_AI"]},
        "d": {"command": "npx", "args": ["-y", "fine-server"]}}})
    out = mcp.check_mcp_servers(make, home, {"scopes": ["@tanstack"], "packages": {"safe-action": []}},
                                {"_meta": {}, "guardrails-ai": ["0.10.1"]})
    sev = {f.details["package"]: f.severity for f in out}
    assert sev == {"safe-action": "high", "@tanstack/router-mcp": "high", "Guardrails_AI": "high",
                   "fine-server": "medium"}


def test_a_plain_text_secret_is_named_never_shown(home):
    write(home / ".claude.json", {"mcpServers": {"gh": {"command": "node", "args": ["/srv/gh.js"],
                                                        "env": {"GITHUB_TOKEN": TOKEN, "REF": "${OTHER}",
                                                                "MODE": "readonly"}}}})
    out = mcp.check_mcp_servers(make, home)
    assert len(out) == 1 and out[0].details["keys"] == ["GITHUB_TOKEN"] and out[0].severity == "medium"
    assert TOKEN not in repr(out)


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_a_secret_in_a_git_tracked_config_is_high(home):
    proj = home / "code" / "app"
    write(proj / ".mcp.json", {"mcpServers": {"gh": {"command": "node", "env": {"GITHUB_TOKEN": TOKEN}}}})
    subprocess.run(["git", "init", "-q", str(proj)], check=True)
    subprocess.run(["git", "-C", str(proj), "add", ".mcp.json"], check=True)
    out = mcp.check_mcp_servers(make, home)
    assert len(out) == 1 and out[0].severity == "high" and out[0].details["git_tracked"] is True
    assert "pushed commit" in out[0].description and TOKEN not in repr(out)


def test_when_git_cannot_be_asked_the_finding_says_so(home, monkeypatch):
    write(home / ".claude.json", {"mcpServers": {"gh": {"command": "node", "env": {"GITHUB_TOKEN": TOKEN}}}})
    monkeypatch.setattr(mcp, "_git_tracked", lambda path: None)
    out = mcp.check_mcp_servers(make, home)
    assert out[0].severity == "medium" and "couldn't ask git" in out[0].description


def test_with_no_git_to_run_the_finding_says_git_couldnt_be_asked(home, monkeypatch, tmp_path):
    write(home / ".claude.json", {"mcpServers": {"gh": {"command": "node", "env": {"GITHUB_TOKEN": TOKEN}}}})
    monkeypatch.setenv("PATH", str(tmp_path / "no-programs-here"))
    out = mcp.check_mcp_servers(make, home)
    assert out[0].details["git_tracked"] is None and "couldn't ask git" in out[0].description


@pytest.mark.parametrize("answer,tracked", [
    ((0, ""), True),
    ((1, "error: pathspec '.mcp.json' did not match any file(s) known to git\n"), False),
    ((128, "fatal: not a git repository (or any of the parent directories): .git\n"), False),
    ((128, "fatal: detected dubious ownership in repository at '/srv/x'\n"), None),   # git refused to say
    ((129, "usage: git ls-files"), None),
    (None, None),
])
def test_only_gits_own_answers_say_tracked_or_not(monkeypatch, tmp_path, answer, tracked):
    monkeypatch.setattr(mcp, "git_ls_file", lambda path: answer)
    assert mcp._git_tracked(tmp_path / ".mcp.json") is tracked


def test_a_repository_git_refuses_to_read_is_said_so(home, monkeypatch):
    write(home / ".claude.json", {"mcpServers": {"gh": {"command": "node", "env": {"GITHUB_TOKEN": TOKEN}}}})
    monkeypatch.setattr(mcp, "git_ls_file",
                        lambda path: (128, "fatal: detected dubious ownership in repository at '%s'\n" % home))
    out = mcp.check_mcp_servers(make, home)
    assert out[0].details["git_tracked"] is None and "couldn't ask git" in out[0].description


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_git_is_asked_about_that_one_file_whatever_its_name(tmp_path):
    """A name git could read as a pattern (*.json) or an option (-x.json) is asked about as the file itself."""
    repo = tmp_path / "repo"
    write(repo / "a.json", {})
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "a.json"], check=True)
    assert mcp.git_ls_file(repo / "a.json") == (0, "")
    for name in ("*.json", "-x.json"):
        write(repo / name, {})
        code, error = mcp.git_ls_file(repo / name)
        assert code == 1 and "did not match" in error, name   # untracked, though a.json is tracked
    assert mcp.git_ls_file(tmp_path / "elsewhere" / "b.json")[0] == 128   # its folder isn't there, let alone a repo


def test_an_unreadable_config_is_not_checked_never_clean(home):
    write(home / ".claude.json", "{ this is not json")
    out = mcp.check_mcp_servers(make, home)
    assert len(out) == 1 and out[0].severity == "info" and "not checked" in out[0].title


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib is 3.11+")
def test_codex_toml_is_read_on_311(home):
    write(home / ".codex" / "config.toml", '[mcp_servers.fetch]\ncommand = "uvx"\nargs = ["mcp-server-fetch"]\n')
    out = mcp.check_mcp_servers(make, home)
    assert [f.details.get("package") for f in out] == ["mcp-server-fetch"]


def test_codex_toml_without_tomllib_is_reported_not_checked(home, monkeypatch):
    write(home / ".codex" / "config.toml", '[mcp_servers.fetch]\ncommand = "uvx"\nargs = ["x"]\n')
    monkeypatch.setitem(sys.modules, "tomllib", None)  # import now raises ImportError
    out = mcp.check_mcp_servers(make, home)
    assert len(out) == 1 and out[0].severity == "info" and "Codex" in out[0].description


def test_the_same_file_through_a_link_is_read_once(home):
    real = write(home / "code" / "app" / ".mcp.json", {"mcpServers": {"a": {"command": "npx", "args": ["one"]}}})
    (home / "code" / "alias").symlink_to(real.parent)
    assert len(mcp.check_mcp_servers(make, home)) == 1


def test_the_scanner_runs_it_by_default_and_by_name(home):
    write(home / ".claude.json", {"mcpServers": {"a": {"command": "npx", "args": ["-y", "loose"]}}})
    assert "mcp_servers" in SentinelScanner()._checks
    result = SentinelScanner(checks=["mcp_servers"]).scan()
    assert [f.check for f in result.findings] == ["mcp_servers"]


def test_the_guardians_package_skill_includes_it(monkeypatch):
    from sentinel import skills
    seen = []
    monkeypatch.setattr(skills, "_findings_to_result", lambda skill, checks: seen.append(checks) or "r")
    skills._scan_packages()
    assert seen == [["npm_supply_chain", "pip_supply_chain", "mcp_servers"]]
