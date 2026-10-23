"""Baseline fixes (2026-10-23): Claude Code's churn isn't watched, setuid bits and owner changes are."""
import json
import os
from pathlib import Path

import pytest

from sentinel import baseline as B
from sentinel.baseline import FileBaseline, FileChange, escalates


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "state"))
    return h


def touch(path: Path, text: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def claude_tree(home: Path) -> Path:
    c = home / ".claude"
    for kept in ("settings.json", "settings.local.json", "CLAUDE.md", "hooks/pre.sh", "commands/x.md",
                 "agents/a.md", "skills/s/SKILL.md", "plugins/installed_plugins.json",
                 "plugins/known_marketplaces.json"):
        touch(c / kept)
    for churn in ("projects/p/session.jsonl", "file-history/f", "todos/t.json", "shell-snapshots/s.sh",
                  "plugins/cache/x/plugin.js", "plugins/marketplaces/m/README.md", "history.jsonl"):
        touch(c / churn)
    return c


def rels(records, root: Path):
    return sorted(Path(r.path).relative_to(root.resolve()).as_posix() for r in records)


def test_only_what_changes_claude_codes_behaviour_is_watched(home):
    c = claude_tree(home)
    assert rels(B._scan_path(c), c) == ["CLAUDE.md", "agents/a.md", "commands/x.md", "hooks/pre.sh",
                                        "plugins/installed_plugins.json", "plugins/known_marketplaces.json",
                                        "settings.json", "settings.local.json", "skills/s/SKILL.md"]


def test_a_new_transcript_raises_nothing_but_a_new_hook_does(home):
    c = claude_tree(home)
    b = FileBaseline()
    b.create(str(c))
    touch(c / "projects" / "p" / "session2.jsonl")
    touch(c / "projects" / "p" / "session.jsonl", "changed")
    assert b.check() == []
    touch(c / "hooks" / "new.sh")
    assert [(x.change_type, Path(x.path).name) for x in b.check()] == [("added", "new.sh")]


def test_an_old_baseline_with_transcripts_in_it_doesnt_report_them_gone(home):
    c = claude_tree(home)
    old = c / "projects" / "p" / "session.jsonl"
    b = FileBaseline()
    b.create(str(c))
    b._records[str(old.resolve())] = B.FileRecord(path=str(old.resolve()), sha256="a", size=1, mtime=0,
                                                  permissions="644")  # what a pre-fix baseline held
    old.unlink()
    assert b.check() == []


def test_the_rule_applies_only_under_claude(home):
    elsewhere = touch(home / "projects" / "p" / "notes.txt")
    assert B._should_skip(elsewhere) is False
    assert B._should_skip(home / ".claude") is False


def test_setuid_bits_are_kept_in_the_permission_string(home):
    f = touch(home / "tool")
    os.chmod(f, 0o755)
    assert B._file_permissions(f) == "755"  # unchanged for ordinary files, so old baselines still compare
    os.chmod(f, 0o4755)
    assert B._file_permissions(f) == "4755"


def test_a_setuid_bit_added_is_seen_and_escalates(home):
    f = touch(home / ".ssh" / "helper")
    os.chmod(f, 0o755)
    b = FileBaseline()
    b.create(str(home / ".ssh"))
    os.chmod(f, 0o4755)
    changes = b.check()
    assert [(x.change_type, x.old_permissions, x.new_permissions) for x in changes] == [
        ("permissions_changed", "755", "4755")]
    assert escalates(changes[0])


@pytest.mark.parametrize("old,new,up", [("755", "4755", True), ("755", "2755", True), ("4755", "4755", False),
                                        ("4755", "755", False), ("644", "600", False), ("755", "1755", False),
                                        ("???", "4755", False)])
def test_escalates_only_when_setuid_or_setgid_is_added(old, new, up):
    assert escalates(FileChange(path="p", change_type="permissions_changed", old_permissions=old,
                                new_permissions=new)) is up


def test_an_owner_change_is_reported_and_escalates(home):
    f = touch(home / ".ssh" / "authorized_keys")
    b = FileBaseline()
    b.create(str(home / ".ssh"))
    rec = b._records[str(f.resolve())]
    rec.uid += 1  # as if the file had belonged to someone else when the baseline was made
    changes = b.check()
    assert [x.change_type for x in changes] == ["owner_changed"] and escalates(changes[0])
    assert changes[0].old_owner == "%d:%d" % (rec.uid, rec.gid) and "OWNER" in changes[0].human_readable()


def test_a_baseline_saved_without_owners_doesnt_flag_every_file(home, tmp_path):
    f = touch(home / ".ssh" / "config")
    b = FileBaseline()
    b.create(str(home / ".ssh"))
    saved = tmp_path / "old_baseline.json"
    b.save(str(saved))
    data = json.loads(saved.read_text())
    for rec in data["records"].values():
        del rec["uid"], rec["gid"], rec["owner_known"]
    saved.write_text(json.dumps(data))
    loaded = FileBaseline.load(str(saved))
    assert loaded._records[str(f.resolve())].owner_known is False
    assert loaded.check() == []


def test_a_saved_and_loaded_baseline_still_compares_owners(home, tmp_path):
    f = touch(home / ".ssh" / "config")
    b = FileBaseline()
    b.create(str(home / ".ssh"))
    saved = tmp_path / "b.json"
    b.save(str(saved))
    loaded = FileBaseline.load(str(saved))
    loaded._records[str(f.resolve())].gid += 1
    assert [x.change_type for x in loaded.check()] == ["owner_changed"]


def test_the_guardian_rates_an_escalation_high(home, monkeypatch):
    from sentinel import skills
    change = FileChange(path="/x", change_type="permissions_changed", old_permissions="755", new_permissions="4755")
    plain = FileChange(path="/y", change_type="permissions_changed", old_permissions="644", new_permissions="600")

    class Fake:
        _records = {"/x": 1}

        def check(self):
            return [change, plain]
    monkeypatch.setattr(FileBaseline, "load", classmethod(lambda cls, *a, **k: Fake()))
    result = skills._check_baseline()
    assert [(a.severity, a.details) for a in result.assessments] == [("high", "/x"), ("medium", "/y")]
