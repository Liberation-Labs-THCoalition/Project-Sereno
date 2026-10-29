"""Every scan names its state folder (2026-10-28). sentinel_home() falls back to ~/.sentinel when SENTINEL_HOME isn't
set, and Ember's own scans read the wrong folder for days because SENTINEL_HOME was set only on the cron line. Each
scan's header and JSON say which folder it used, and when it's the default because SENTINEL_HOME wasn't set."""
import json
import sys
import types

import pytest

from sentinel import __main__ as cli
from sentinel import guardian
from sentinel.paths import state_folder, state_folder_note
from sentinel.scanner import SentinelScanner


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setattr("sentinel.scanner._home", lambda: h)
    return h


def test_the_default_says_it_is_the_default(home, monkeypatch):
    monkeypatch.delenv("SENTINEL_HOME", raising=False)
    result = SentinelScanner(checks=["credentials"]).scan()
    assert (result.state_folder, result.state_folder_default) == (str(home / ".sentinel"), True)
    assert ("State folder: %s (the default: SENTINEL_HOME isn't set)" % (home / ".sentinel")) in result.human_report()


def test_an_empty_sentinel_home_is_the_default_too(home, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", "")
    assert state_folder() == (home / ".sentinel", True)


def test_sentinel_home_says_where_it_came_from(home, monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "ember"))
    result = SentinelScanner(checks=["credentials"]).scan()
    assert (result.state_folder, result.state_folder_default) == (str(tmp_path / "ember"), False)
    assert ("State folder: %s (from SENTINEL_HOME)" % (tmp_path / "ember")) in result.human_report()


def test_the_json_names_the_state_folder(home, monkeypatch, capsys):
    monkeypatch.delenv("SENTINEL_HOME", raising=False)
    args = types.SimpleNamespace(checks="credentials", cron=False, log="", discord="", json=True, output="", skip=[])
    cli.cmd_scan(args)
    data = json.loads(capsys.readouterr().out)
    assert (data["state_folder"], data["state_folder_default"]) == (str(home / ".sentinel"), True)


def test_the_guardian_names_its_state_folder(home, monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("SENTINEL_HOME", raising=False)
    monkeypatch.setattr(sys, "argv", ["guardian"])
    monkeypatch.setattr(guardian, "run_guardian", lambda **kw: [])
    guardian.main()
    assert "State folder: %s (the default: SENTINEL_HOME isn't set)" % (home / ".sentinel") in capsys.readouterr().out


def test_the_guardian_run_record_names_its_state_folder(home, monkeypatch, tmp_path):
    from sentinel.skills import BDIEngine, SkillRegistry, Skill, SkillResult
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "state"))
    bdi = BDIEngine(str(tmp_path / "state" / "bdi.json"))
    bdi.add_intention("d", ["s"], trigger="periodic", interval=60)
    reg = SkillRegistry()
    reg.register(Skill("s", "sensor", "", lambda **kw: SkillResult(skill="s", success=True)))
    guardian.run_guardian(registry=reg, bdi=bdi, alert_bus=guardian.AlertBus([types.SimpleNamespace(
        send=lambda *a, **k: None)]))
    record = json.loads(next((tmp_path / "state" / "guardian_runs").glob("run_*.json")).read_text())
    assert (record.get("state_folder"), record.get("state_folder_default")) == (str(tmp_path / "state"), False)


def test_baseline_check_without_a_baseline_says_where_it_looked(home, monkeypatch, capsys):
    monkeypatch.delenv("SENTINEL_HOME", raising=False)
    assert cli.cmd_baseline(types.SimpleNamespace(action="check")) == 1
    out = capsys.readouterr().out
    assert "No baseline found" in out and state_folder_note() in out
    assert "(the default: SENTINEL_HOME isn't set)" in out
