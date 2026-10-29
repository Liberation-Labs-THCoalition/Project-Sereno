"""A version-less compromised entry is not a version-specific high (2026-10-28). An entry with versions matches only
those versions; an installed version not among them isn't flagged; an entry with no versions gives a medium "check the
version" naming the installed version and saying the list doesn't say which releases are bad. An exact match stays
critical, as it was."""
import json

import pytest

from sentinel import mcp, scanner
from sentinel.paths import SkipList
from sentinel.scanner import Finding, check_pip_supply_chain, load_known_bad_npm, load_known_bad_pip


def make(severity, title, description, remediation, details):
    return Finding(check="mcp_servers", severity=severity, title=title, description=description,
                   remediation=remediation, details=details)


def pip_installed(monkeypatch, name, version):
    out = json.dumps([{"name": name, "version": version}])
    monkeypatch.setattr(scanner, "_run", lambda cmd, timeout=30: (out, 0))


# ── pip ──

def test_pip_versioned_match_is_critical(monkeypatch):
    pip_installed(monkeypatch, "litellm", "1.82.8")
    assert [f.severity for f in check_pip_supply_chain(load_known_bad_pip())] == ["critical"]


@pytest.mark.parametrize("version", ["1.84.0", "1.82.6", "1.107.1"])
def test_pip_versioned_entry_leaves_other_versions_alone(monkeypatch, version):
    """Ember's install: litellm 1.84.0 was called high; the bad releases are 1.82.7, 1.82.8 and 1.107.0."""
    pip_installed(monkeypatch, "litellm", version)
    assert check_pip_supply_chain(load_known_bad_pip()) == []


def test_pip_version_less_entry_is_medium_and_names_the_installed_version(monkeypatch):
    pip_installed(monkeypatch, "somepkg", "2.4.1")
    [f] = check_pip_supply_chain({"somepkg": []})
    assert f.severity == "medium"
    assert f.title.startswith("Check the version: somepkg==2.4.1")
    assert "doesn't say which versions" in f.description and "2.4.1" in f.description
    assert "compromised pip package" not in f.title.lower()
    assert f.details["versions_listed"] is False


def test_the_litellm_entry_names_the_three_bad_releases():
    """OSV MAL-2026-2144: the entry already had versions at c4572f1; this keeps them."""
    assert load_known_bad_pip()["litellm"] == ["1.82.7", "1.82.8", "1.107.0"]


# ── npm ──

def _npm(tmp_path, monkeypatch, packages, name, version):
    pkg = tmp_path / "proj" / "node_modules" / name
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"version": version}))
    monkeypatch.setattr(scanner, "_home", lambda: tmp_path)
    return scanner.check_npm_supply_chain({"scopes": [], "packages": packages}, skip=SkipList())


def test_npm_versioned_match_is_critical(tmp_path, monkeypatch):
    assert [f.severity for f in _npm(tmp_path, monkeypatch, {"p": ["1.0.0"]}, "p", "1.0.0")] == ["critical"]


def test_npm_versioned_entry_leaves_other_versions_alone(tmp_path, monkeypatch):
    assert _npm(tmp_path, monkeypatch, {"p": ["1.0.0"]}, "p", "1.0.1") == []


def test_npm_version_less_entry_is_medium_and_names_the_installed_version(tmp_path, monkeypatch):
    [f] = _npm(tmp_path, monkeypatch, {"tensorlake": []}, "tensorlake", "0.9.3")
    assert f.severity == "medium"
    assert f.title.startswith("Check the version: tensorlake@0.9.3")
    assert "doesn't say which versions" in f.description and "0.9.3" in f.description


def test_the_shipped_npm_feed_has_version_less_entries_the_rule_covers():
    assert any(not v for v in load_known_bad_npm()["packages"].values())


# ── MCP servers pinned to a version ──

def _mcp(tmp_path, args, command="npx", npm=None, pip=None):
    (tmp_path / ".mcp-home").mkdir(exist_ok=True)
    home = tmp_path / ".mcp-home"
    (home / ".cursor").mkdir(exist_ok=True)
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"s": {"command": command, "args": args}}}))
    return [(f.severity, f.title) for f in mcp.check_mcp_servers(make, home, npm or {}, pip or {}, skip=SkipList())]


def test_mcp_pinned_to_a_listed_bad_version_is_critical(tmp_path):
    found = _mcp(tmp_path, ["-y", "badpkg@1.0.0"], npm={"packages": {"badpkg": ["1.0.0"]}})
    assert [s for s, _ in found] == ["critical"]
    assert found[0][1].startswith("MCP server pinned to a compromised release: badpkg 1.0.0")


def test_mcp_pinned_to_another_version_of_a_listed_package_is_quiet(tmp_path):
    assert _mcp(tmp_path, ["-y", "badpkg@1.0.1"], npm={"packages": {"badpkg": ["1.0.0"]}}) == []


def test_mcp_pinned_to_a_version_less_entry_is_medium_check_the_version(tmp_path):
    [(severity, title)] = _mcp(tmp_path, ["-y", "@corp/tool@3.0.0"], npm={"packages": {"@corp/tool": []}})
    assert severity == "medium"
    assert title.startswith("Check the version: MCP server pinned to @corp/tool 3.0.0")


@pytest.mark.parametrize("spec,expected", [("litellm==1.82.7", ["critical"]), ("litellm==1.84.0", []),
                                           ("LiteLLM[proxy]==1.107.0", ["critical"])])
def test_mcp_pinned_pypi_server_against_the_shipped_feed(tmp_path, spec, expected):
    assert [s for s, _ in _mcp(tmp_path, [spec], command="uvx", pip=load_known_bad_pip())] == expected
