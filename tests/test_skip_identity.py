"""The skip list, round 2 (2026-10-29): a path is covered by its name as written, where it really is, or what it is,
and nothing inside a skipped folder is looked up at all.

Round 1's verifier: Claude Code's ~/.claude.json lists every agent's projects on a shared account. With ~/agents/other
skipped and ~/agents/other/proj2 a link to /data/proj2, Sereno resolved the link, saw a path outside the list, read that
project's .claude/settings.json and MCP configs, and reported the other agent's paths, server names, the env var name
GITHUB_TOKEN and hook command text, while saying "Not checked: 1 folder on your skip list".

The tests here watch every lookup the code makes (os.stat, lstat, readlink, open, scandir and listdir, builtins.open,
and pathlib's own methods, which bound the os functions at import before 3.11), record where each one lands (a call
that follows links at its target; lstat and readlink at the link itself), and assert that none lands inside the skipped
folder or where a link inside it points. Each such test has a control: with nothing skipped, the same code does look
there, so the watcher can see it.
"""
import builtins
import contextlib
import io
import json
import os
import pathlib
from pathlib import Path

import pytest

from sentinel import agent_safety, baseline, claude_settings, mcp, paths, profiler, scanner
from sentinel.paths import SkipList, state_folder_note, walk
from sentinel.scanner import Finding, SentinelScanner

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
# What the other agent's project holds; none of it may reach a finding when their folder is skipped
THEIRS = ("proj2", "GITHUB_TOKEN", "other-server", "other-cursor-server", "other-vscode-server", "other-json-server",
          "OTHER-AGENT-HOOK", "other-mcp")


def make(severity, title, description, remediation, details):
    return Finding(check="t", severity=severity, title=title, description=description, remediation=remediation,
                   details=details)


def write(path: Path, data="x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


def _server(name, package="other-mcp", variable="GITHUB_TOKEN"):
    return {name: {"command": "npx", "args": ["-y", package], "env": {variable: TOKEN}}}


def plant_project(proj: Path) -> Path:
    """A Claude Code project as another agent keeps it: a hook, bypass mode, and three MCP configs with a token."""
    write(proj / ".claude" / "settings.json",
          {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "echo OTHER-AGENT-HOOK"}]}]},
           "permissions": {"defaultMode": "bypassPermissions"}})
    write(proj / ".mcp.json", {"mcpServers": _server("other-server")})
    write(proj / ".cursor" / "mcp.json", {"mcpServers": _server("other-cursor-server")})
    write(proj / ".vscode" / "mcp.json", {"servers": _server("other-vscode-server")})
    return proj


def leaked(findings) -> list:
    """The findings that carry anything of the other agent's project."""
    out = []
    for f in findings:
        text = json.dumps([f.title, f.description, f.remediation, f.details], default=str)
        hits = [t for t in THEIRS if t in text]
        if hits:
            out.append((f.title, hits))
    return out


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    (h / "agents" / "mine").mkdir(parents=True)
    (h / "agents" / "other").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(scanner, "_home", lambda: h)
    return h


@pytest.fixture
def outside(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    return d


def _skip_file(entries):
    return write(paths.sentinel_home() / "skip.json", entries)


# ── The watcher ──

class _Entry:
    """A DirEntry that reports what's asked of it: is_dir() and stat() follow a link unless told not to."""

    def __init__(self, entry, rec):
        self._e, self._rec = entry, rec
        self.name, self.path = entry.name, entry.path

    def __getattr__(self, name):
        return getattr(self._e, name)

    def __fspath__(self):
        return self.path

    def is_symlink(self):
        self._rec.note(self.path, False)
        return self._e.is_symlink()

    def is_dir(self, *, follow_symlinks=True):
        self._rec.note(self.path, follow_symlinks)
        return self._e.is_dir(follow_symlinks=follow_symlinks)

    def is_file(self, *, follow_symlinks=True):
        self._rec.note(self.path, follow_symlinks)
        return self._e.is_file(follow_symlinks=follow_symlinks)

    def stat(self, *, follow_symlinks=True):
        self._rec.note(self.path, follow_symlinks)
        return self._e.stat(follow_symlinks=follow_symlinks)


class _Listing:
    def __init__(self, it, rec):
        self._it, self._rec = it, rec

    def __iter__(self):
        return self

    def __next__(self):
        return _Entry(next(self._it), self._rec)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._it.close()

    def close(self):
        self._it.close()


class Recorder:
    """Every path looked up while recording, as where the lookup lands."""

    OS = (("stat", None), ("lstat", False), ("readlink", False), ("open", True), ("scandir", True), ("listdir", True))
    PATHLIB = (("stat", None), ("lstat", False), ("exists", True), ("is_file", True), ("is_dir", True),
               ("is_symlink", False), ("open", True), ("read_text", True), ("read_bytes", True), ("iterdir", True),
               ("glob", True), ("rglob", True), ("resolve", True))

    def __init__(self, monkeypatch):
        self.paths = []
        self.on = False
        self._busy = False
        self._realpath = os.path.realpath
        for name, follow in self.OS:
            monkeypatch.setattr(os, name, self._wrap(getattr(os, name), follow, name == "scandir"))
        opener = self._wrap(builtins.open, True, False)
        monkeypatch.setattr(builtins, "open", opener)
        monkeypatch.setattr(io, "open", opener)
        for name, follow in self.PATHLIB:
            monkeypatch.setattr(pathlib.Path, name, self._wrap(getattr(pathlib.Path, name), follow, False))

    def _wrap(self, fn, follow, listing):
        rec = self

        def watched(*args, **kwargs):
            path = args[0] if args else kwargs.get("path", kwargs.get("file", "."))
            if isinstance(path, (str, bytes, os.PathLike)):
                rec.note(path, kwargs.get("follow_symlinks", True) if follow is None else follow)
            result = fn(*args, **kwargs)
            return _Listing(result, rec) if listing else result
        return watched

    def note(self, path, follow):
        if not self.on or self._busy:
            return
        self._busy = True
        try:
            p = os.path.abspath(os.fsdecode(os.fspath(path)))
            where = self._realpath(p) if follow else os.path.join(self._realpath(os.path.dirname(p)),
                                                                  os.path.basename(p))
        finally:
            self._busy = False
        self.paths.append(where)

    @contextlib.contextmanager
    def recording(self):
        self.on = True
        try:
            yield self
        finally:
            self.on = False

    def _real(self, folder):
        self._busy = True
        try:
            return self._realpath(str(folder))
        finally:
            self._busy = False

    def inside(self, folder) -> list:
        """Lookups that landed strictly inside folder (the folder itself may be looked at, for its identity)."""
        root = self._real(folder)
        return sorted(set(p for p in self.paths if p.startswith(root + os.sep)))

    def at_or_inside(self, folder) -> list:
        root = self._real(folder)
        return sorted(set(p for p in self.paths if p == root or p.startswith(root + os.sep)))


@pytest.fixture
def touched(monkeypatch):
    return Recorder(monkeypatch)


# ── H1: the verifier's case, and its reverse ──

def _verifiers_case(home, outside):
    """~/agents/other/proj2 is a link to a project outside home, and ~/.claude.json lists it, with servers of its
    own in ~/.claude.json too."""
    proj = plant_project(outside / "proj2")
    (home / "agents" / "other" / "proj2").symlink_to(proj)
    write(home / ".claude.json", {"projects": {str(home / "agents" / "other" / "proj2"):
                                               {"mcpServers": _server("other-json-server")}}})
    return proj


CHECKS = ["persistence", "mcp_servers", "agent_safety"]


def test_the_verifiers_case_reads_nothing_of_the_project_the_link_leads_to(home, outside, touched):
    proj = _verifiers_case(home, outside)
    control = SentinelScanner(checks=CHECKS).scan()
    assert {t for _title, hits in leaked(control.findings) for t in hits} >= {
        "proj2", "GITHUB_TOKEN", "other-server", "other-cursor-server", "other-vscode-server", "other-json-server",
        "OTHER-AGENT-HOOK"}, "control: with nothing skipped, the scan reads the project and reports all of it"
    _skip_file(["~/agents/other"])
    with touched.recording():
        result = SentinelScanner(checks=CHECKS).scan()
    assert leaked(result.findings) == []
    assert touched.at_or_inside(proj) == [], "a lookup landed in the project the skipped folder's link leads to"
    assert touched.inside(home / "agents" / "other") == [], "a lookup landed inside the skipped folder"
    notes = [(f.severity, f.title, f.details["roots"]) for f in result.findings if f.check == "skip_list"]
    assert notes == [("info", "Not checked: 1 folder on your skip list", [str(home / "agents" / "other")])]


def test_a_link_from_outside_into_a_skipped_folder_is_still_not_followed(home, touched):
    """The reverse: your folder holds a link into the skipped one, and ~/.claude.json lists it."""
    proj = plant_project(home / "agents" / "other" / "theirs")
    (home / "work").mkdir()
    (home / "work" / "p").symlink_to(proj)
    write(home / ".claude.json", {"projects": {str(home / "work" / "p"): {"mcpServers": _server("other-json-server")}}})
    control = SentinelScanner(checks=CHECKS).scan()
    assert leaked(control.findings), "control: with nothing skipped, the link is followed"
    _skip_file(["~/agents/other"])
    with touched.recording():
        result = SentinelScanner(checks=CHECKS).scan()
    assert leaked(result.findings) == []
    assert touched.inside(home / "agents" / "other") == []
    assert [f.title for f in result.findings if f.check == "skip_list"] == ["Not checked: 1 folder on your skip list"]


# ── H1: each of the three ways a path can name a skipped folder, alone ──

def test_a_path_written_under_a_skipped_folder_is_decided_before_anything_is_looked_up(home, outside, touched):
    """(a) is a comparison of the path as written: nothing is resolved, so not even the folders on the way to it are
    looked up."""
    _verifiers_case(home, outside)
    skip = SkipList(["~/agents/other"])
    with touched.recording():
        assert skip.covers(home / "agents" / "other" / "proj2" / ".claude" / "settings.json")
        assert skip.covers("~/agents/other/proj2/.mcp.json")
    assert touched.paths == []


def test_a_the_path_as_written_stays_covered_when_a_link_on_it_moves(home, outside, touched):
    """(a) alone: the list names ~/ag/other, ~/ag being a link to a volume. Another agent points ~/ag at a different
    volume during the scan; ~/ag/other is still the folder the list names, so a project under it is not read, even
    though it links out to a folder the list doesn't name, and the folder's new place and identity aren't on the list."""
    (outside / "volA" / "other").mkdir(parents=True)
    (outside / "volB" / "other").mkdir(parents=True)
    proj = plant_project(outside / "proj2")
    (outside / "volB" / "other" / "proj2").symlink_to(proj)
    (home / "ag").symlink_to(outside / "volA")
    skip = SkipList(["~/ag/other"])
    (home / "ag").unlink()
    (home / "ag").symlink_to(outside / "volB")
    listed = str(home / "ag" / "other" / "proj2")
    write(home / ".claude.json", {"projects": {listed: {"mcpServers": _server("other-json-server")}}})
    with touched.recording():
        known = claude_settings.known_projects(home, skip)
        found = claude_settings.project_files(home, [listed], skip) + mcp.project_configs(home, [listed], skip)
        reported = mcp.check_mcp_servers(make, home, {}, {}, skip=skip)
        walked = list(walk(home / "ag", skip))   # a walk from ~/ag meets other by the name the list gives
    assert (known, found, leaked(reported)) == ([], [], [])
    assert walked == [(str(home / "ag"), [], [])]
    assert touched.at_or_inside(proj) == []
    assert touched.inside(outside / "volB" / "other") == []


def test_b_where_the_folder_really_is_stays_covered_when_it_is_recreated(home, outside, touched):
    """(b) alone: the list names ~/ag/other, ~/ag a link to a volume, so the folder really is at <volume>/other. It's
    recreated there during the scan (restored from a backup: a new folder, so a new identity), and a project of yours
    links into it by its real path, not through ~/ag. It's still not read."""
    (outside / "vol" / "other").mkdir(parents=True)
    (home / "ag").symlink_to(outside / "vol")
    skip = SkipList(["~/ag/other"])
    (outside / "vol" / "other").rename(outside / "vol" / "other.old")
    (outside / "vol" / "other").mkdir()
    proj = plant_project(outside / "vol" / "other" / "proj2")
    (home / "agents" / "mine" / "p").symlink_to(proj)
    listed = str(home / "agents" / "mine" / "p")
    write(home / ".claude.json", {"projects": {listed: {"mcpServers": _server("other-json-server")}}})
    with touched.recording():
        known = claude_settings.known_projects(home, skip)
        found = claude_settings.project_files(home, [listed], skip) + mcp.project_configs(home, [listed], skip)
        reported = mcp.check_mcp_servers(make, home, {}, {}, skip=skip)
    assert (known, found, leaked(reported)) == ([], [], [])
    assert touched.inside(outside / "vol" / "other") == []


def test_a_dot_dot_after_a_link_climbs_from_where_the_link_points(home, touched):
    """~/x/link/../settings.json is, to the system, the settings.json beside where link points, not ~/x/settings.json.
    A config folder named that way (CLAUDE_CONFIG_DIR=~/x/link/..) with link pointing into a skipped folder is in that
    folder, so its files aren't read."""
    other = home / "agents" / "other"
    write(other / "settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    (other / "sub").mkdir()
    (home / "x").mkdir()
    (home / "x" / "link").symlink_to(other / "sub")
    environ = {"CLAUDE_CONFIG_DIR": str(home / "x" / "link" / "..")}
    reported = agent_safety.check_agent_safety(make, home, environ=environ, skip=SkipList())
    assert [f.details["path"] for f in reported if "defaultMode" in f.description or "bypass" in f.title.lower()], \
        "control: unskipped, the folder's settings are read"
    skip = SkipList([str(other)])
    with touched.recording():
        assert skip.covers(home / "x" / "link" / ".." / "settings.json")
        reported = agent_safety.check_agent_safety(make, home, environ=environ, skip=skip)
    assert [f for f in reported if str(home / "x") in json.dumps(f.details)] == []
    assert touched.inside(other) == []


# ── M1 and (c): the folder by identity ──

def _case_insensitive(monkeypatch, top: Path):
    """Lookups under top behave as on a case-insensitive disk (macOS APFS): a name in any case finds the entry, and
    realpath keeps the case it was given, as macOS's does. Listings still give names as they're stored."""
    real_lstat, real_stat, real_listdir = os.lstat, os.stat, os.listdir
    top = str(top)

    def fold(path):
        if isinstance(path, bytes) or not isinstance(path, (str, os.PathLike)):
            return path
        p = os.fspath(path)
        if not p.startswith(top + os.sep):
            return path
        parts, cur = p[len(top) + 1:].split(os.sep), top
        for i, name in enumerate(parts):
            try:
                names = real_listdir(cur)
            except OSError:
                return os.path.join(cur, *parts[i:])
            if name not in names:
                name = next((n for n in names if n.lower() == name.lower()), name)
            cur = os.path.join(cur, name)
        return cur

    monkeypatch.setattr(os, "lstat", lambda p, *a, **k: real_lstat(fold(p), *a, **k))
    monkeypatch.setattr(os, "stat", lambda p, *a, **k: real_stat(fold(p), *a, **k))


def _inside_any_case(rec: Recorder, folder: Path) -> list:
    root = str(folder).lower()
    return sorted(set(p for p in rec.paths if p.lower().startswith(root + os.sep)))


def test_an_entry_typed_in_another_case_skips_the_folder(home, monkeypatch):
    """M1: on macOS, "~/Agents/Nexus" names ~/agents/nexus, but realpath keeps the case it's given and the walk builds
    paths from the names on disk, so no path ever matched: the folder was entered and no note appeared. The folder's
    identity, taken once when the list is read, matches it under any name."""
    nexus = home / "agents" / "nexus"
    write(nexus / ".env", "API_KEY=abc123\n")
    proj = plant_project(nexus / "proj")
    write(home / ".claude.json", {"projects": {str(proj): {"mcpServers": _server("other-json-server")}}})
    _case_insensitive(monkeypatch, home)
    rec = Recorder(monkeypatch)
    skip = SkipList(["~/Agents/Nexus"])
    assert skip.missing == [], "the simulation: the entry exists, as on a case-insensitive disk"
    with rec.recording():
        creds = scanner.check_credentials(skip=skip)
        persistence = scanner.check_persistence(skip=skip)
        reported = mcp.check_mcp_servers(make, home, {}, {}, skip=skip)
    assert [f.details["path"] for f in creds] == []
    assert leaked(persistence + reported) == []
    assert _inside_any_case(rec, nexus) == [], "the folder was entered"
    assert [(n[1], n[4]["roots"]) for n in skip.notes()] == [
        ("Not checked: 1 folder on your skip list", [str(home / "Agents" / "Nexus")])]
    # control: listed in its own case it's skipped the same way, and unlisted it's read
    assert [f.details["path"] for f in scanner.check_credentials(skip=SkipList())] == [str(nexus / ".env")]


def test_an_exception_typed_in_another_case_takes_the_folder_off(home, monkeypatch):
    """The same for ! entries: ["~/agents/*", "!~/Agents/Mine"] keeps your own folder in the scan on macOS."""
    write(home / "agents" / "mine" / ".env", "API_KEY=abc123\n")
    write(home / "agents" / "other" / ".env", "API_KEY=abc123\n")
    _case_insensitive(monkeypatch, home)
    skip = SkipList(["~/agents/*", "!~/Agents/Mine"])
    assert skip.missing == []
    assert [f.details["path"] for f in scanner.check_credentials(skip=skip)] == [str(home / "agents" / "mine" / ".env")]


def test_two_names_for_one_folder_count_once(home, monkeypatch):
    """The folder listed twice, once in another case: one folder skipped, not two."""
    write(home / "agents" / "other" / ".env", "API_KEY=abc123\n")
    _case_insensitive(monkeypatch, home)
    skip = SkipList(["~/agents/other", "~/Agents/Other"])
    assert scanner.check_credentials(skip=skip) == []
    assert skip.covers(home / "Agents" / "Other" / ".env")   # by the second name too
    assert [n[1] for n in skip.notes()] == ["Not checked: 1 folder on your skip list"]


def test_a_listed_file_is_skipped_under_another_name_too(home):
    """A listed file by identity: a hard link to it elsewhere is the same file, so it isn't read either."""
    theirs = write(home / "agents" / "theirs.env", "API_KEY=abc123\n")
    os.link(str(theirs), str(home / "agents" / "mine" / ".env"))
    skip = SkipList([str(theirs)])
    assert scanner.check_credentials(skip=skip) == []
    assert [n[1] for n in skip.notes()] == ["Not checked: 1 file on your skip list"]
    assert [f.details["path"] for f in scanner.check_credentials(skip=SkipList())] == [
        str(home / "agents" / "mine" / ".env")]   # control


def test_a_skip_entry_that_is_a_link_to_the_folder_prunes_the_folder(home, touched):
    """An alias: the list names ~/alias, a link to ~/agents/nexus. The walk reaches the folder by its own name and
    prunes it, and the note names the entry as written."""
    nexus = home / "agents" / "nexus"
    write(nexus / ".env", "API_KEY=abc123\n")
    (home / "alias").symlink_to(nexus)
    skip = SkipList(["~/alias"])
    with touched.recording():
        assert [p for p, _d, _f in walk(home, skip) if p.startswith(str(nexus))] == []
    assert touched.inside(nexus) == []
    assert [(n[1], n[4]["roots"]) for n in skip.notes()] == [
        ("Not checked: 1 folder on your skip list", [str(home / "alias")])]
    assert [p for p, _d, _f in walk(home, SkipList()) if p == str(nexus)] == [str(nexus)]   # control


# ── L1: no lookup inside a skipped folder, from any of the places Sereno looks ──

def _proj(home):
    p = home / "agents" / "mine" / "proj"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _link(at: Path, target: Path):
    at.parent.mkdir(parents=True, exist_ok=True)
    at.symlink_to(target)


def _plant_dot_claude(home, other):
    write(other / "cdir" / "settings.json", {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "x"}]}]}})
    _link(_proj(home) / ".claude", other / "cdir")


def _plant_dot_cursor(home, other):
    write(other / "cur" / "mcp.json", {"mcpServers": _server("other-cursor-server")})
    _link(_proj(home) / ".cursor", other / "cur")


def _plant_dot_vscode(home, other):
    write(other / "vsc" / "mcp.json", {"servers": _server("other-vscode-server")})
    write(other / "vsc" / "tasks.json", "node router_init.js")
    _link(_proj(home) / ".vscode", other / "vsc")


def _plant_mcp_json(home, other):
    write(other / "m.json", {"mcpServers": _server("other-server")})
    _link(_proj(home) / ".mcp.json", other / "m.json")


def _plant_tasks_json(home, other):
    write(other / "tasks.json", "node router_init.js")
    _link(_proj(home) / ".vscode" / "tasks.json", other / "tasks.json")


def _plant_scope(home, other):
    write(other / "@corp" / "tool" / "package.json", {"version": "3.0.0"})
    _link(_proj(home) / "node_modules" / "@corp", other / "@corp")


def _plant_package_json(home, other):
    write(other / "pkg.json", {"version": "1.0.0"})
    (_proj(home) / "node_modules" / "badpkg").mkdir(parents=True)
    _link(_proj(home) / "node_modules" / "badpkg" / "package.json", other / "pkg.json")


def _plant_known_inside(home, other):
    plant_project(other / "proj")
    write(home / ".claude.json", {"projects": {str(other / "proj"): {}}})


def _plant_known_linking_in(home, other):
    plant_project(other / "proj")
    _link(home / "agents" / "mine" / "p", other / "proj")
    write(home / ".claude.json", {"projects": {str(home / "agents" / "mine" / "p"): {}}})


def _plant_neighbour(home, other):
    write(_proj(home) / "setup.mjs", "console.log(1)")
    write(other / "r.js", "x")
    _link(_proj(home) / "router_init.js", other / "r.js")


def _plant_monitor(home, other):
    write(other / "mon.sh", "x")
    _link(home / ".local" / "bin" / "gh-token-monitor.sh", other / "mon.sh")


def _plant_user_file(rel, content):
    def plant(home, other):
        write(other / "f", content if isinstance(content, str) else json.dumps(content))
        _link(home / rel, other / "f")
    return plant


def _plant_user_dir(rel, name, content):
    def plant(home, other):
        write(other / "d" / name, content)
        _link(home / rel, other / "d")
    return plant


def _run_npm(home, skip):
    return scanner.check_npm_supply_chain({"scopes": ["@corp"], "packages": {"badpkg": ["1.0.0"]}}, skip=skip)


def _run_claude_walk(home, skip):
    return claude_settings.project_files(home, (), skip)


def _run_mcp_walk(home, skip):
    return mcp.project_configs(home, (), skip)


def _run_known(home, skip):
    return claude_settings.known_projects(home, skip)


def _run_persistence(home, skip):
    return scanner.check_persistence(skip=skip)


def _run_agents(home, skip):
    return agent_safety.check_agent_safety(make, home, environ={}, skip=skip)


def _run_mcp(home, skip):
    return mcp.check_mcp_servers(make, home, {}, {}, skip=skip)


def _run_credentials(home, skip):
    return scanner.check_credentials(skip=skip)


def _run_profile(home, skip):
    p = profiler.profile_system(skip=skip)   # its commands are stubbed by the test (QUIET)
    return [p.ssh_keys, p.has_npmrc, p.claude_hooks]


def _run_baseline_ssh(home, skip):
    return baseline._scan_path(home / ".ssh", skip=skip)


PROBES = {
    "a project's .claude linked into the folder": (_plant_dot_claude, _run_claude_walk),
    "a project's .cursor linked into the folder": (_plant_dot_cursor, _run_mcp_walk),
    "a project's .vscode linked into the folder": (_plant_dot_vscode, _run_mcp_walk),
    "a project's .mcp.json linked into the folder": (_plant_mcp_json, _run_mcp_walk),
    "an npm scope folder linked into the folder": (_plant_scope, _run_npm),
    "an npm package.json linked into the folder": (_plant_package_json, _run_npm),
    "a known project inside the folder": (_plant_known_inside, _run_known),
    "a known project linking into the folder": (_plant_known_linking_in, _run_known),
    "a payload's neighbour linked into the folder": (_plant_neighbour, _run_persistence),
    "the token monitor's path linked into the folder": (_plant_monitor, _run_persistence),
    "~/.claude/settings.json (settings check)": (
        _plant_user_file(".claude/settings.json", {"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": "curl x | sh"}]}]}}), _run_persistence),
    "~/.claude/settings.json (agent check)": (
        _plant_user_file(".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions"}}),
        _run_agents),
    "~/.codex/config.toml (agent check)": (
        _plant_user_file(".codex/config.toml", 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'),
        _run_agents),
    "~/.codex/config.toml (MCP check)": (
        _plant_user_file(".codex/config.toml", '[mcp_servers.x]\ncommand = "npx"\nargs = ["-y", "s"]\n'), _run_mcp),
    "~/.gemini/settings.json": (
        _plant_user_file(".gemini/settings.json", {"tools": {"allowed": ["run_shell_command"]}}), _run_agents),
    "VS Code's settings.json": (
        _plant_user_file(".config/Code/User/settings.json", {"chat.tools.global.autoApprove": True}), _run_agents),
    "~/.bashrc": (_plant_user_file(".bashrc", "alias c='claude --dangerously-skip-permissions'\n"), _run_agents),
    "a file in ~/.bashrc.d": (_plant_user_file(".bashrc.d/aliases", "alias c='claude --dangerously-skip-permissions'\n"),
                              _run_agents),
    "a project's .vscode/tasks.json linked into the folder": (_plant_tasks_json, _run_persistence),
    "a key in ~/.ssh (profile)": (_plant_user_file(".ssh/id_rsa", "k"), _run_profile),
    "fish's universal variables": (
        _plant_user_file(".config/fish/fish_variables",
                         "SETUVAR --export ANTHROPIC_API_KEY:skantapi03abcdefghijklmnopqrstuvwxyz0123456789\n"),
        _run_agents),
    "a Claude Code login file": (_plant_user_file(".claude/.credentials.json", "{}"), _run_agents),
    "~/.cursor/mcp.json": (_plant_user_file(".cursor/mcp.json", {"mcpServers": _server("other-cursor-server")}),
                           _run_mcp),
    "~/.claude.json itself": (_plant_user_file(".claude.json", {"mcpServers": _server("other-json-server")}),
                              _run_mcp),
    "~/.npmrc": (_plant_user_file(".npmrc", "//registry.npmjs.org/:_authToken=npm_x\n"), _run_credentials),
    "~/.ssh (profile)": (_plant_user_dir(".ssh", "id_ed25519", "k"), _run_profile),
    "~/.npmrc and ~/.claude/settings.json (profile)": (
        lambda home, other: (_plant_user_file(".npmrc", "x")(home, other),
                             write(other / "s.json", {"hooks": {"Stop": []}}),
                             _link(home / ".claude" / "settings.json", other / "s.json")), _run_profile),
    "~/.ssh (baseline)": (_plant_user_dir(".ssh", "config", "Host x"), _run_baseline_ssh),
}


@pytest.mark.parametrize("probe", sorted(PROBES))
def test_nothing_inside_a_skipped_folder_is_looked_up(probe, home, touched, monkeypatch):
    """L1: each place Sereno looks checks the skip list before its first stat, open or listing, so a link into the
    folder is never followed, not even to ask whether it's a file. The control shows the same code looks there, and
    finds something, when nothing is skipped."""
    import shutil
    monkeypatch.setattr(profiler, "_run", lambda cmd, timeout=10: ("", 1))
    monkeypatch.setattr(shutil, "which", lambda name: None)
    other = home / "agents" / "other"
    plant, run = PROBES[probe]
    plant(home, other)
    with touched.recording():
        control = run(home, SkipList())
    assert touched.inside(other), "control: with nothing skipped, the code looks inside the folder"
    touched.paths.clear()
    skip = SkipList([str(other)])
    with touched.recording():
        result = run(home, skip)
    assert touched.inside(other) == []
    assert result != control, "the skipped run found what the control found"
    assert [n[1] for n in skip.notes()] == ["Not checked: 1 folder on your skip list"]


def test_asking_about_a_link_into_a_skipped_folder_looks_up_nothing_inside_it(home, touched):
    """covers() itself: round 1 asked os.path.isdir() of the link's target, inside the folder, to count it."""
    other = home / "agents" / "other"
    write(other / "d" / "x", "x")
    (home / "agents" / "mine" / "link-in").symlink_to(other / "d")
    skip = SkipList([str(other)])
    with touched.recording():
        assert skip.covers(home / "agents" / "mine" / "link-in")
        assert skip.covers(home / "agents" / "mine" / "link-in" / "x")
        assert list(walk(home / "agents" / "mine", skip)) == [(str(home / "agents" / "mine"), [], [])]
    assert touched.inside(other) == []


def test_a_known_projects_servers_in_claude_json_are_not_reported(home):
    """~/.claude.json keeps each project's own MCP servers under projects; a project on the skip list keeps them out
    of the report, though the file itself is yours."""
    write(home / ".claude.json", {"projects": {str(home / "agents" / "other" / "p"): {"mcpServers":
                                                                                     _server("other-json-server")},
                                               str(home / "agents" / "mine" / "p"): {"mcpServers":
                                                                                    _server("my-server", "my-mcp", "MY_KEY")}}})
    skip = SkipList([str(home / "agents" / "other")])
    reported = _run_mcp(home, skip)
    assert leaked(reported) == []
    assert [f.details["server"] for f in reported if "server" in f.details] != []   # yours are still reported
    assert [n[1] for n in skip.notes()] == ["Not checked: 1 folder on your skip list"]
    assert leaked(_run_mcp(home, SkipList()))   # control


def test_a_watched_path_inside_a_skipped_folder_that_links_out_is_not_fingerprinted(home, outside, touched):
    """The baseline resolved a watched path before asking the skip list, so a path in a skipped folder that linked out
    of it was fingerprinted where it pointed."""
    target = write(outside / "notes.txt")
    (home / "agents" / "other" / "notes").symlink_to(target)
    watched = home / "agents" / "other" / "notes"
    assert [r.path for r in baseline._scan_path(watched, skip=SkipList())] == [str(target)]   # control
    skip = SkipList([str(home / "agents" / "other")])
    with touched.recording():
        assert baseline._scan_path(watched, skip=skip) == []
    assert touched.at_or_inside(target) == []
    assert [n[1] for n in skip.notes()] == ["Not checked: 1 folder on your skip list"]


def test_a_baseline_check_looks_up_nothing_in_a_skipped_folder(home, touched):
    """A baseline made before the folder was listed holds its files; the check doesn't call them removed, and asks
    the skip list before anything else about them (resolving one, to see whether it's Claude Code churn, looked it
    up inside the folder)."""
    watched = home / "agents"
    write(watched / "mine" / "a.txt")
    write(watched / "other" / "deep" / "b.txt")
    b = baseline.FileBaseline()
    b.create(str(watched), skip=SkipList())
    skip = SkipList([str(watched / "other")])
    with touched.recording():
        changes = b.check(skip=skip)
    assert changes == []
    assert touched.inside(watched / "other") == []
    assert [n[1] for n in skip.notes()] == ["Not checked: 1 folder on your skip list"]


# ── L2: the count ──

def test_each_skipped_folder_counts_once_and_nothing_absent_counts(home, monkeypatch):
    """Many ways into two folders: known projects in both (whose settings.local.json doesn't exist, nor one of the
    projects), links to a file and to a folder, a linked shell folder, a link to nothing in one. Two folders."""
    other, third = home / "agents" / "other", home / "agents" / "third"
    third.mkdir()
    a, b = plant_project(other / "pa"), plant_project(third / "pb")
    write(home / ".claude.json", {"projects": {str(a): {}, str(b): {}, str(other / "gone"): {}}})
    write(other / ".env", "API_KEY=abc123\n")
    (home / "agents" / "mine" / ".env").symlink_to(other / ".env")
    (home / "agents" / "mine" / "link-dir").symlink_to(third)
    write(third / "bashrc.d" / "x", "alias c='claude --dangerously-skip-permissions'\n")
    (home / ".bashrc.d").symlink_to(third / "bashrc.d")
    (home / "agents" / "mine" / "dangling").symlink_to(other / "nothing-here")
    _skip_file(["~/agents/other", "~/agents/third"])
    result = SentinelScanner(checks=["persistence", "credentials", "mcp_servers", "agent_safety", "git_repos"]).scan()
    notes = [(f.title, f.details["skipped_folders"], f.details["skipped_files"], f.details["roots"])
             for f in result.findings if f.check == "skip_list"]
    assert notes == [("Not checked: 2 folders on your skip list", 2, 0, [str(other), str(third)])]
    assert leaked(result.findings) == []


def test_a_listed_file_counts_as_a_file(home):
    theirs = write(home / "agents" / "notes.txt")
    skip = SkipList([str(theirs)])
    assert skip.covers(theirs) and skip.covers(theirs)
    assert [(n[1], n[4]["skipped_folders"], n[4]["skipped_files"]) for n in skip.notes()] == [
        ("Not checked: 1 file on your skip list", 0, 1)]


def test_a_skip_entry_that_points_at_nothing_counts_only_once_something_is_there(home, outside):
    """An entry that's a link to nothing (a drive not mounted): a path under it is still covered, but nothing was
    there to skip, so nothing is counted, until what it names appears."""
    (home / "usb").symlink_to(outside / "drive")
    skip = SkipList(["~/usb"])
    assert skip.missing == []
    assert skip.covers(home / "usb" / "proj")
    assert skip.notes() == []
    (outside / "drive").mkdir()
    assert skip.covers(home / "usb" / "proj")
    assert [n[1] for n in skip.notes()] == ["Not checked: 1 folder on your skip list"]


# ── L3 ──

def test_an_empty_sentinel_home_is_said_to_be_empty(home, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", "")
    expected = "%s (the default: SENTINEL_HOME is empty)" % (home / ".sentinel")
    assert state_folder_note() == expected
    result = SentinelScanner(checks=["credentials"]).scan()
    assert "State folder: %s" % expected in result.human_report()
    assert result.state_folder_note == expected
    monkeypatch.delenv("SENTINEL_HOME")
    assert state_folder_note() == "%s (the default: SENTINEL_HOME isn't set)" % (home / ".sentinel")
