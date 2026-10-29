"""One skip list for every walk under home (2026-10-28, from Ember's guardian install on a shared home).

On a machine where several AI agents keep folders under one account's home (~/agents/<name>/), Sereno's searches
entered the other agents' folders. Every walk now goes through sentinel.paths.walk, which prunes the skip list's
folders before it would enter them. For each walk: a file planted in a skipped folder, which that walk reports when
nothing is skipped, isn't reported, and the folder isn't even entered (os.scandir is watched). A scan that skipped
anything says so in one note; an entry that matches nothing is reported once; a skip list that can't be read closes
the walks rather than letting them in anywhere.
"""
import json
import os
import sys
import types
from pathlib import Path

import pytest

from sentinel import __main__ as cli
from sentinel import agent_safety, baseline, claude_settings, mcp, paths, profiler, scanner, skills
from sentinel.paths import SkipList, load_skip_list, walk
from sentinel.scanner import Finding, SentinelScanner


def make(severity, title, description, remediation, details):
    return Finding(check="t", severity=severity, title=title, description=description, remediation=remediation,
                   details=details)


def write(path: Path, data="x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


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
def visits(monkeypatch):
    """Every folder os.scandir or os.listdir opened, resolved: the walk's only way into a folder is os.scandir. Before
    3.11, pathlib's glob and iterdir bound these at import, so only the walk is watched there (LISTING_WATCHED)."""
    seen = []
    for name in ("scandir", "listdir"):
        real = getattr(os, name)

        def watched(path=".", _real=real):
            if isinstance(path, (str, bytes, os.PathLike)):
                seen.append(os.path.realpath(os.fspath(path)))
            return _real(path)
        monkeypatch.setattr(os, name, watched)
    return seen


LISTING_WATCHED = sys.version_info >= (3, 11)


def entered(visits, folder: Path) -> list:
    root = os.path.realpath(str(folder))
    return [v for v in visits if v == root or v.startswith(root + os.sep)]


def skip_other(home):
    return SkipList([str(home / "agents" / "other")])


# ── Each walk: (what to plant in the skipped folder, run the walk and return what it reported) ──

def _npm(home, skip):
    known = {"scopes": [], "packages": {"badpkg": ["1.0.0"]}}
    return [f.details["path"] for f in scanner.check_npm_supply_chain(known, skip=skip)]


def _plant_npm(other):
    return write(other / "proj" / "node_modules" / "badpkg" / "package.json", {"version": "1.0.0"}).parent


def _persistence(home, skip):
    return [f.details["path"] for f in scanner.check_persistence(skip=skip)]


def _plant_payload(other):
    return write(other / "router_init.js")


def _plant_tasks(other):
    return write(other / "proj" / ".vscode" / "tasks.json", '{"tasks": [{"command": "node router_init.js"}]}')


def _plant_pth(other):
    return write(other / "venv" / "lib" / "python3.11" / "site-packages" / "evil.pth", "import os; exec('x')\n")


def _plant_hook(other):
    return write(other / "proj" / ".claude" / "settings.json",
                 {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}})


def _credentials(home, skip):
    return [f.details["path"] for f in scanner.check_credentials(skip=skip)]


def _plant_env(other):
    return write(other / ".env", "API_KEY=abc123\n")


def _git(home, skip):
    return [f.details["repo"] for f in scanner.check_git_repos(skip=skip)]


def _plant_git(other):
    (other / "repo" / ".git").mkdir(parents=True)
    return other / "repo"


def _mcp(home, skip):
    return [f.details["path"] for f in mcp.check_mcp_servers(make, home, {}, {}, skip=skip)]


def _plant_mcp(other):
    return write(other / "proj" / ".mcp.json", {"mcpServers": {"s": {"command": "npx", "args": ["-y", "some-server"]}}})


def _agents(home, skip):
    return [f.details["path"] for f in agent_safety.check_agent_safety(make, home, environ={}, skip=skip)]


def _plant_bypass(other):
    return write(other / "proj" / ".claude" / "settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})


def _baseline(home, skip):
    return [r.path for r in baseline._scan_path(home, skip=skip)]


def _plant_watched(other):
    return write(other / "notes.txt").resolve()


def _quiet_profiler(monkeypatch):
    import shutil
    monkeypatch.setattr(profiler, "_run", lambda cmd, timeout=10, env=None: ("", 1))
    monkeypatch.setattr(shutil, "which", lambda name: None)


def _profile_nm(home, skip):
    return ["counted"] * profiler.profile_system(skip=skip).node_modules_dirs


def _plant_nm(other):
    (other / "proj" / "node_modules").mkdir(parents=True)
    return "counted"


def _profile_env(home, skip):
    return ["counted"] * profiler.profile_system(skip=skip).has_env_files


def _plant_env_count(other):
    write(other / ".env", "X=1\n")
    return "counted"


WALKS = {
    "scanner npm node_modules": (_plant_npm, _npm),
    "scanner persistence payloads": (_plant_payload, _persistence),
    "scanner persistence vscode tasks": (_plant_tasks, _persistence),
    "scanner startup files": (_plant_pth, _persistence),
    "claude_settings project walk": (_plant_hook, _persistence),
    "scanner credentials .env": (_plant_env, _credentials),
    "scanner git repos": (_plant_git, _git),
    "mcp project configs": (_plant_mcp, _mcp),
    "agent_safety project settings": (_plant_bypass, _agents),
    "baseline": (_plant_watched, _baseline),
    "profiler node_modules": (_plant_nm, _profile_nm),
    "profiler .env": (_plant_env_count, _profile_env),
}


@pytest.fixture
def git_says_dune(monkeypatch):
    monkeypatch.setattr(scanner, "_run", lambda cmd, timeout=30: ("* main\n  shai-hulud", 0))


@pytest.mark.parametrize("walk_name", sorted(WALKS))
def test_each_walk_reports_the_planted_file_when_nothing_is_skipped(walk_name, home, monkeypatch, git_says_dune):
    """The control: each plant is something its walk reports, so its absence below means the skip worked."""
    _quiet_profiler(monkeypatch)
    plant, run = WALKS[walk_name]
    planted = plant(home / "agents" / "other")
    assert str(planted) in [str(p) for p in run(home, SkipList())]


@pytest.mark.parametrize("walk_name", sorted(WALKS))
def test_each_walk_leaves_a_skipped_folder_unentered(walk_name, home, monkeypatch, git_says_dune, visits):
    _quiet_profiler(monkeypatch)
    plant, run = WALKS[walk_name]
    planted = plant(home / "agents" / "other")
    skip = skip_other(home)
    reported = [str(p) for p in run(home, skip)]
    assert str(planted) not in reported
    assert entered(visits, home / "agents" / "other") == [], "the walk opened a folder on the skip list"
    assert visits, "the walk didn't run at all"
    notes = skip.notes()
    assert [n[1] for n in notes] == ["Not checked: 1 folder on your skip list"]


def test_the_walk_still_enters_the_folders_not_listed(home, visits):
    write(home / "agents" / "mine" / ".env", "API_KEY=abc123\n")
    write(home / "agents" / "other" / ".env", "API_KEY=abc123\n")
    found = _credentials(home, skip_other(home))
    assert found == [str(home / "agents" / "mine" / ".env")]
    assert entered(visits, home / "agents" / "mine")


# ── Links into a skipped folder ──

def test_a_link_to_a_file_in_a_skipped_folder_is_not_read(home, visits):
    target = write(home / "agents" / "other" / ".env", "API_KEY=abc123\n")
    (home / "agents" / "mine" / ".env").symlink_to(target)
    skip = skip_other(home)
    assert _credentials(home, skip) == []
    assert _credentials(home, SkipList()) != []   # control: the link is read when nothing is skipped
    # counted as the folder it leads into, once (2026-10-29: each link into a root counted as a thing of its own)
    assert (skip.notes()[0][4]["skipped_folders"], skip.notes()[0][4]["skipped_files"]) == (1, 0)


def test_a_linked_node_modules_in_a_skipped_folder_is_not_scanned(home, visits):
    nm = home / "agents" / "other" / "node_modules"
    write(nm / "badpkg" / "package.json", {"version": "1.0.0"})
    (home / "agents" / "mine" / "proj").mkdir()
    (home / "agents" / "mine" / "proj" / "node_modules").symlink_to(nm)
    assert _npm(home, skip_other(home)) == []
    assert entered(visits, nm) == []
    assert _npm(home, SkipList()) != []


def test_a_linked_package_inside_your_node_modules_is_not_read(home):
    """npm link and pnpm leave a package in your node_modules that's a link into someone else's folder."""
    pkg = write(home / "agents" / "other" / "badpkg" / "package.json", {"version": "1.0.0"}).parent
    nm = home / "agents" / "mine" / "proj" / "node_modules"
    nm.mkdir(parents=True)
    (nm / "badpkg").symlink_to(pkg)
    assert _npm(home, skip_other(home)) == []
    assert _npm(home, SkipList()) == [str(nm / "badpkg")]


def test_a_linked_scope_folder_in_your_node_modules_is_not_listed(home, visits):
    scope = home / "agents" / "other" / "@corp"
    write(scope / "tool" / "package.json", {"version": "3.0.0"})
    nm = home / "agents" / "mine" / "proj" / "node_modules"
    nm.mkdir(parents=True)
    (nm / "@corp").symlink_to(scope)
    known = {"scopes": ["@corp"], "packages": {}}
    assert scanner.check_npm_supply_chain(known, skip=skip_other(home)) == []
    if LISTING_WATCHED:
        assert entered(visits, scope) == [], "the scope folder was listed"
    assert [f.details["path"] for f in scanner.check_npm_supply_chain(known, skip=SkipList())] == \
        [str(nm / "@corp" / "tool")]


def test_a_single_path_is_a_one_entry_list(home):
    assert paths.skip_list(str(home / "agents" / "other")).notes() == [] and \
        paths.skip_list(str(home / "agents" / "other")).covers(home / "agents" / "other" / "x")


def test_a_linked_tasks_json_in_a_skipped_folder_is_not_read(home):
    target = write(home / "agents" / "other" / "tasks.json", "router_init")
    vscode = home / "agents" / "mine" / "proj" / ".vscode"
    vscode.mkdir(parents=True)
    (vscode / "tasks.json").symlink_to(target)
    assert str(vscode / "tasks.json") not in _persistence(home, skip_other(home))
    assert str(vscode / "tasks.json") in _persistence(home, SkipList())


def test_a_skip_entry_that_is_a_link_skips_where_it_points(home, visits):
    (home / "alias").symlink_to(home / "agents" / "other")
    write(home / "agents" / "other" / ".env", "API_KEY=abc123\n")
    skip = SkipList(["~/alias"])
    assert _credentials(home, skip) == []
    assert entered(visits, home / "agents" / "other") == []


def test_a_walk_started_inside_a_skipped_folder_doesnt_start(home, visits):
    write(home / "agents" / "other" / "deep" / "x.txt")
    skip = skip_other(home)
    assert list(walk(home / "agents" / "other" / "deep", skip)) == []
    assert entered(visits, home / "agents" / "other") == []
    assert skip.notes()[0][1] == "Not checked: 1 folder on your skip list"


def test_a_known_project_in_a_skipped_folder_is_not_read(home):
    """~/.claude.json on a shared account lists every agent's Claude Code projects. A project too deep (or hidden) for
    the walk is read only through that list, which must follow the skip list too."""
    proj = home / "agents" / "other" / ".hidden" / "proj"
    hook = _plant_hook(proj.parent).parent.parent   # .hidden/proj/.claude/settings.json
    assert hook == proj
    _plant_mcp(proj.parent)
    _plant_bypass(proj.parent)
    write(home / ".claude.json", {"projects": {str(proj): {}}})
    skip = skip_other(home)
    assert [f for f in claude_settings.project_files(home, claude_settings.known_projects(home), skip)] == []
    assert mcp.project_configs(home, [str(proj)], skip) == []
    assert _agents(home, skip) == []
    assert _mcp(home, skip) == []
    # control: without the skip list, the known project is read
    assert claude_settings.project_files(home, claude_settings.known_projects(home), SkipList()) != []
    assert mcp.project_configs(home, [str(proj)], SkipList()) != []


def test_a_shell_startup_folder_linked_into_a_skipped_folder_is_not_read(home, visits):
    target = home / "agents" / "other" / "bashrc.d"
    write(target / "aliases", "alias c='claude --dangerously-skip-permissions'\n")
    (home / ".bashrc.d").symlink_to(target)
    assert [p for p in _agents(home, skip_other(home)) if "bashrc.d" in p] == []
    if LISTING_WATCHED:
        assert entered(visits, target) == [], "the folder was listed"
    assert [p for p in _agents(home, SkipList()) if "bashrc.d" in p] != []


def test_a_project_settings_file_linked_into_a_skipped_folder_is_not_read(home):
    """The project folder is yours, but its settings file is a link into someone else's folder."""
    other = home / "agents" / "other"
    hook = _plant_hook(other / "theirs")
    mcp_json = _plant_mcp(other / "theirs")
    proj = home / "agents" / "mine" / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".claude" / "settings.json").symlink_to(hook)
    (proj / ".mcp.json").symlink_to(mcp_json)
    mine = [str(proj / ".claude" / "settings.json"), str(proj / ".mcp.json")]
    skip = skip_other(home)
    found = [str(p) for p, _ in claude_settings.project_files(home, (), skip)] + \
        [str(p) for p, _k, _t in mcp.project_configs(home, (), skip)]
    assert [p for p in found if p in mine] == []
    found = [str(p) for p, _ in claude_settings.project_files(home, (), SkipList())] + \
        [str(p) for p, _k, _t in mcp.project_configs(home, (), SkipList())]
    assert sorted(p for p in found if p in mine) == sorted(mine)


def test_a_watched_file_in_a_skipped_folder_is_not_fingerprinted(home):
    theirs = write(home / "agents" / "other" / "notes.txt")
    assert baseline._scan_path(theirs, skip=skip_other(home)) == []
    assert [r.path for r in baseline._scan_path(theirs, skip=SkipList())] == [str(theirs.resolve())]


def test_a_shell_file_linked_into_a_skipped_folder_is_not_read(home):
    target = write(home / "agents" / "other" / "aliases", "alias c='claude --dangerously-skip-permissions'\n")
    (home / ".bashrc.d").mkdir()
    (home / ".bashrc.d" / "aliases").symlink_to(target)
    assert [p for p in _agents(home, skip_other(home)) if "bashrc.d" in p] == []
    assert [p for p in _agents(home, SkipList()) if "bashrc.d" in p] == [str(home / ".bashrc.d" / "aliases")]


def test_baseline_create_says_what_it_skipped(home, capsys):
    write(home / ".claude" / "settings.json", "{}")
    write(home / ".ssh" / "config", "Host x")
    assert cli.cmd_baseline(types.SimpleNamespace(action="create", skip=[str(home / ".claude")])) == 0
    out = capsys.readouterr().out
    assert "Not checked: 1 folder on your skip list" in out
    saved = json.loads((paths.sentinel_home() / "baseline.json").read_text())
    assert [p for p in saved["records"] if "/.claude/" in p] == []
    assert [p for p in saved["records"] if p.endswith("/.ssh/config")] != []


@pytest.mark.parametrize("skip_json,line,code", [
    (None, "No changes detected. ", 0),
    (["~/.ssh/agents"], "No changes detected outside the folders on your skip list", 0),
    ("{broken", "File integrity not checked: the skip list couldn't be read", 1),
])
def test_a_baseline_check_says_clean_only_where_it_looked(home, capsys, skip_json, line, code):
    write(home / ".ssh" / "config", "Host x")
    write(home / ".ssh" / "agents" / "theirs", "x")
    b = baseline.FileBaseline()
    b.create(str(home / ".ssh"), skip=SkipList())
    b.save()
    if skip_json is not None:
        _skip_file(skip_json)
    assert cli.cmd_baseline(types.SimpleNamespace(action="check")) == code
    out = capsys.readouterr().out
    assert line in out
    if skip_json is not None:
        assert "files unchanged" not in out


@pytest.mark.parametrize("action", ["create", "update"])
def test_an_unreadable_skip_list_doesnt_save_an_empty_baseline(home, capsys, action):
    write(home / ".ssh" / "config", "Host x")
    b = baseline.FileBaseline()
    b.create(str(home / ".ssh"), skip=SkipList())
    b.save()
    before = (paths.sentinel_home() / "baseline.json").read_text()
    _skip_file("{broken")
    assert cli.cmd_baseline(types.SimpleNamespace(action=action)) == 1
    assert (paths.sentinel_home() / "baseline.json").read_text() == before
    assert "Baseline not saved" in capsys.readouterr().out


def test_a_baseline_check_doesnt_call_a_skipped_file_removed(home):
    watched = home / "watched"
    write(watched / "mine.txt")
    write(watched / "other" / "theirs.txt")
    b = baseline.FileBaseline()
    b.create(str(watched), skip=SkipList())
    skip = SkipList([str(watched / "other")])
    changes = b.check(skip=skip)
    assert [c.path for c in changes if "theirs" in c.path] == []
    assert [n[1] for n in b.last_skip.notes()] == ["Not checked: 1 folder on your skip list"]
    # control: a file that really went away is still reported
    (watched / "mine.txt").unlink()
    assert [c.change_type for c in b.check(skip=skip) if c.path.endswith("mine.txt")] == ["removed"]


def test_the_guardian_reports_what_the_baseline_skipped(home, monkeypatch):
    watched = home / "watched"
    write(watched / "other" / "theirs.txt")
    state = Path(os.environ["SENTINEL_HOME"])
    write(state / "skip.json", [str(watched / "other")])
    b = baseline.FileBaseline()
    b.create(str(watched), skip=SkipList())
    monkeypatch.setattr(baseline.FileBaseline, "load", classmethod(lambda cls, *a, **k: b))
    result = skills._check_baseline()
    assert ("info", "Not checked: 1 folder on your skip list") in [(a.severity, a.title) for a in result.assessments]


def test_the_profile_says_its_counts_leave_skipped_folders_out(home, monkeypatch):
    _quiet_profiler(monkeypatch)
    _plant_nm(home / "agents" / "other")
    p = profiler.profile_system(skip=skip_other(home))
    assert p.node_modules_dirs == 0
    assert "Not checked: 1 folder on your skip list" in p.summary()


# ── The scan's note, the file, the command line ──

def _skip_file(entries):
    path = paths.sentinel_home() / "skip.json"
    write(path, entries if not isinstance(entries, str) else entries)
    return path


def _plant_two(home):
    for name in ("other", "third"):
        write(home / "agents" / name / ".env", "API_KEY=abc123\n")
        (home / "agents" / name / "repo" / ".git").mkdir(parents=True)


def test_a_scan_that_skipped_says_so_once(home, git_says_dune):
    _plant_two(home)
    _skip_file(["~/agents/other", "~/agents/third"])
    result = SentinelScanner(checks=["credentials", "git_repos", "persistence"]).scan()
    notes = [f for f in result.findings if f.check == "skip_list"]
    assert [(f.severity, f.title) for f in notes] == [("info", "Not checked: 2 folders on your skip list")]
    assert notes[0].details["roots"] == [str(home / "agents" / "other"), str(home / "agents" / "third")]
    assert notes[0].details["skipped_folders"] == 2
    assert "this scan says nothing about them" in notes[0].description
    assert [f for f in result.findings if f.check != "skip_list"] == []
    assert "Not checked: 2 folders on your skip list" in result.human_report()
    assert "looks clean" not in result.human_report()


def test_a_scan_that_skipped_nothing_has_no_note(home):
    write(home / "agents" / "mine" / ".env", "API_KEY=abc123\n")
    result = SentinelScanner(checks=["credentials"]).scan()
    assert [f.check for f in result.findings] == ["credentials"]


def test_an_entry_that_matches_nothing_is_reported_once(home):
    _skip_file(["~/agents/gone", "~/agents/other"])
    result = SentinelScanner(checks=["credentials", "git_repos", "persistence"]).scan()
    notes = [(f.severity, f.title) for f in result.findings if f.check == "skip_list"]
    assert notes == [("info", "Not checked: 1 folder on your skip list"),
                     ("info", "Skip list entry not found: ~/agents/gone")]


def test_an_exception_takes_your_own_folder_back_off_the_list(home):
    write(home / "agents" / "mine" / ".env", "API_KEY=abc123\n")
    write(home / "agents" / "other" / ".env", "API_KEY=abc123\n")
    _skip_file(["~/agents/*", "!~/agents/mine"])
    result = SentinelScanner(checks=["credentials"]).scan()
    assert [f.details["path"] for f in result.findings if f.check == "credentials"] == \
        [str(home / "agents" / "mine" / ".env")]
    assert [f.title for f in result.findings if f.check == "skip_list"] == ["Not checked: 1 folder on your skip list"]


def test_an_exception_that_takes_nothing_off_is_reported(home):
    skip = SkipList(["~/agents/other", "!~/agents/nobody"])
    assert skip.missing == ["!~/agents/nobody"]


@pytest.mark.parametrize("content,why", [("{not json", "JSONDecodeError"), ('{"skip": ["~/agents/other"]}',
                                                                              "not a list of paths"),
                                         ('["~/agents/other", 3]', "not a list of paths"), ('[""]', "not a list of paths")])
def test_a_skip_file_that_cant_be_read_closes_every_walk(home, visits, content, why, git_says_dune):
    """A broken skip list can't promise to keep Sereno out of anyone's folder, so no folder under home is searched,
    and the scan says so as an issue."""
    write(home / "agents" / "mine" / ".env", "API_KEY=abc123\n")
    (home / "agents" / "mine" / "repo" / ".git").mkdir(parents=True)
    _skip_file(content)
    result = SentinelScanner(checks=["credentials", "git_repos", "persistence", "npm_supply_chain",
                                     "mcp_servers", "agent_safety"]).scan()
    notes = [f for f in result.findings if f.check == "skip_list"]
    assert [f.severity for f in notes] == ["high"]
    assert notes[0].title.startswith("Skip list unreadable, so Sereno didn't search your folders")
    assert notes[0].details["error"] == why
    assert [f for f in result.findings if f.check in ("credentials", "git_repos")] == []
    assert entered(visits, home) == []
    assert "looks clean" not in result.human_report()


def test_no_skip_file_skips_nothing(home):
    skip = load_skip_list()
    assert not skip and skip.notes() == []


def test_the_command_line_and_the_file_merge(home, monkeypatch, capsys, git_says_dune):
    _plant_two(home)
    _skip_file(["~/agents/other"])
    monkeypatch.chdir(str(home / "agents"))
    out = home.parent / "result.json"
    monkeypatch.setattr(sys, "argv", ["sentinel", "scan", "--json", "-o", str(out), "--checks", "credentials,git_repos",
                                      "--skip", "third", "--skip", "!mine"])
    with pytest.raises(SystemExit):
        cli.main()
    data = json.loads(out.read_text())
    assert [f for f in data["findings"] if f["check"] != "skip_list"] == []
    notes = [f for f in data["findings"] if f["check"] == "skip_list"]
    assert [n["title"] for n in notes] == ["Not checked: 2 folders on your skip list",
                                          "Skip list entry not found: !" + str(home / "agents" / "mine")]
    assert notes[0]["details"]["roots"] == [str(home / "agents" / "other"), str(home / "agents" / "third")]
    assert str(paths.sentinel_home() / "skip.json") + " and --skip" in notes[0]["description"]


def test_cmd_scan_passes_skip_paths_to_the_scanner(home, monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, checks=None, skip=()):
            seen["skip"] = list(skip)

        def scan(self):
            return scanner.ScanResult(hostname="h", platform="p", scan_time="t", duration_ms=0)
    monkeypatch.setattr(cli, "SentinelScanner", Fake)
    monkeypatch.chdir(str(home))
    args = types.SimpleNamespace(checks="", cron=True, log="", discord="", json=False, output="",
                                 skip=["agents/other", "~/x"])
    cli.cmd_scan(args)
    assert seen["skip"] == [str(home / "agents" / "other"), "~/x"]


# ── The walk itself ──

def test_with_nothing_skipped_the_walk_is_os_walk(home):
    """Same folders, same order, same names, links listed and not followed, as os.walk(top)."""
    write(home / "a" / "b" / "c.txt")
    write(home / "a" / ".hidden" / "d.txt")
    (home / "a" / "link-dir").symlink_to(home / "agents")
    (home / "a" / "link-file").symlink_to(home / "a" / "b" / "c.txt")
    (home / "a" / "dangling").symlink_to(home / "nowhere")
    assert list(walk(home, SkipList())) == list(os.walk(str(home)))


def test_a_folder_that_cant_be_read_is_passed_over(home):
    locked = home / "locked"
    write(locked / "x.txt")
    os.chmod(str(locked), 0)
    try:
        if os.access(str(locked), os.R_OK):
            pytest.skip("running as root: permissions don't stop the walk")
        assert [p for p, _d, _f in walk(home, SkipList())] == [p for p, _d, _f in os.walk(str(home))]
    finally:
        os.chmod(str(locked), 0o755)
