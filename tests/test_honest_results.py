"""Honest results (2026-10-23): what Sereno says matches what it checked.

The docs review before the community release found five ways a result could
read cleaner or worse than the truth:
  * a check that crashed was only logged, and the scan still said "looks clean";
  * a misspelled --checks name ran nothing and reported a clean machine;
  * the guardian printed "All clear" after a skill had failed, and when nothing was due;
  * info notes (a loopback listener) counted as "issues found", and woke --cron;
  * common file names (setup.mjs, sysmon.py) were called critical malware with nothing else pointing to the worm.
"""
import json
import sys
import types

import pytest

import sentinel.__main__ as cli
import sentinel.guardian as guardian
import sentinel.scanner as scanner
from sentinel.alerts import AlertBus
from sentinel.scanner import Finding, ScanResult, SentinelScanner, check_persistence
from sentinel.skills import Assessment, SkillResult


def _result(*severities):
    return ScanResult(hostname="h", platform="p", scan_time="t", duration_ms=0.0, checks_run=1,
                      findings=[Finding(check="network", severity=s, title=f"{s} thing", description="d")
                                for s in severities])


class _Recorder:
    def __init__(self):
        self.sent = []

    def send(self, message, severity="info"):
        self.sent.append((severity, message))
        return True


# ── Worm payload names ──

class TestPayloadNames:
    def _scan(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sentinel.scanner._home", lambda: tmp_path)
        return [f for f in check_persistence() if "payload" in f.title.lower()]

    def test_common_name_alone_is_a_note(self, tmp_path, monkeypatch):
        (tmp_path / "site").mkdir()
        (tmp_path / "site" / "setup.mjs").write_text("export default {}")
        findings = self._scan(tmp_path, monkeypatch)
        assert [f.severity for f in findings] == ["info"]
        assert "setup.mjs" in findings[0].title

    def test_common_name_beside_a_distinctive_one_is_critical(self, tmp_path, monkeypatch):
        (tmp_path / "setup.mjs").write_text("x")
        (tmp_path / "router_runtime.js").write_text("x")
        by_title = {f.title: f.severity for f in self._scan(tmp_path, monkeypatch)}
        assert by_title.get("Malware payload found: setup.mjs") == "critical"
        assert by_title.get("Malware payload found: router_runtime.js") == "critical"

    def test_common_name_naming_the_worm_is_critical(self, tmp_path, monkeypatch):
        (tmp_path / ".local").mkdir()
        (tmp_path / ".local" / "sysmon.py").write_text("import os\nos.system('gh-token-monitor &')\n")
        findings = self._scan(tmp_path, monkeypatch)
        assert [(f.severity, f.title) for f in findings] == [("critical", "Malware payload found: sysmon.py")]

    def test_skips_are_per_name_as_on_main(self, tmp_path, monkeypatch):
        # setup.mjs is skipped in node_modules; sysmon.py isn't (main never skipped it there)
        for rel in ("node_modules/pkg/setup.mjs", "node_modules/pkg/sysmon.py",
                    "lib/python3/site-packages/x/sysmon.py", "tools/psutil/sysmon.py"):
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x")
        findings = self._scan(tmp_path, monkeypatch)
        assert [f.details["path"] for f in findings] == [str(tmp_path / "node_modules/pkg/sysmon.py")]


# ── Checks that crash, and check names that don't exist ──

class TestCheckFailures:
    def test_a_crashed_check_is_a_high_finding(self, monkeypatch):
        def boom():
            raise RuntimeError("ss went missing")
        monkeypatch.setattr(scanner, "check_network", boom)
        result = SentinelScanner(checks=["network"]).scan()
        assert [(f.severity, f.title) for f in result.findings] == [("high", "Check couldn't run: network")]
        assert "ss went missing" in result.findings[0].description
        assert result.checks_clean == 0
        assert "looks clean" not in result.human_report()

    def test_an_unknown_check_name_is_refused(self):
        with pytest.raises(ValueError, match="netwrok.*the checks are: npm_supply_chain"):
            SentinelScanner(checks=["network", "netwrok"])

    def test_the_cli_exits_2_on_an_unknown_name(self, monkeypatch, capsys):
        monkeypatch.setattr(SentinelScanner, "scan", lambda self: pytest.fail("scanned with a bad name"))
        args = types.SimpleNamespace(checks="netwrok", cron=False, log="", discord="", json=False, output="")
        assert cli.cmd_scan(args) == 2
        assert "unknown check name(s): netwrok" in capsys.readouterr().err

    def test_the_cli_strips_spaces_around_names(self, monkeypatch):
        seen = []
        monkeypatch.setattr(SentinelScanner, "scan", lambda self: seen.append(self._checks) or _result())
        args = types.SimpleNamespace(checks=" network , credentials ", cron=False, log="", discord="", json=False,
                                     output="")
        cli.cmd_scan(args)
        assert seen == [["network", "credentials"]]


# ── Notes are not issues ──

class TestNotesAreNotIssues:
    def test_report_with_only_notes_says_no_issues(self):
        report = _result("info").human_report()
        assert "No issues found. 1 note below, for your information:" in report
        assert "looks clean" not in report

    def test_the_notes_below_are_printed(self):
        """2026-10-24: "7 notes below" was followed by nothing, because only the issues branch printed findings."""
        report = _result("info", "info").human_report()
        assert report.count("[.] info thing") == 2
        assert report.index("2 notes below") < report.index("[.] info thing")

    def test_report_counts_issues_and_notes_apart(self):
        assert "1 issue found, and 2 notes:" in _result("high", "info", "info").human_report()
        assert "2 issues found:" in _result("critical", "medium").human_report()

    def test_cron_is_quiet_on_notes_alone(self, monkeypatch, capsys):
        alerted = []
        monkeypatch.setattr(AlertBus, "alert_findings", lambda self, r: alerted.append(r))
        monkeypatch.setattr(SentinelScanner, "scan", lambda self: _result("info"))
        for as_json in (False, True):
            args = types.SimpleNamespace(checks="", cron=True, log="", discord="", json=as_json, output="")
            assert cli.cmd_scan(args) == 0
        assert capsys.readouterr().out == ""
        assert alerted == []

    def test_cron_speaks_for_an_issue(self, monkeypatch, capsys):
        alerted = []
        monkeypatch.setattr(AlertBus, "alert_findings", lambda self, r: alerted.append(r))
        monkeypatch.setattr(SentinelScanner, "scan", lambda self: _result("medium"))
        args = types.SimpleNamespace(checks="", cron=True, log="", discord="", json=False, output="")
        cli.cmd_scan(args)
        assert "1 issue found:" in capsys.readouterr().out
        assert len(alerted) == 1

    @pytest.mark.parametrize("severities,expected", [(("info",), "info"), (("medium", "info"), "medium"),
                                                     (("critical",), "high")])
    def test_summary_alert_severity(self, severities, expected):
        rec = _Recorder()
        AlertBus([rec]).alert_findings(_result(*severities))
        assert rec.sent[-1][0] == expected


# ── The guardian's last line ──

def _skill(name, success=True, *severities):
    return SkillResult(skill=name, success=success, raw="Traceback..." if not success else "",
                       assessments=[Assessment(severity=s, title=s) for s in severities])


class TestGuardianSummary:
    def test_nothing_due_is_not_all_clear(self):
        line = guardian.summary_line([])
        assert line.startswith("Nothing was due, so no skills ran.")
        assert "All clear" not in line

    def test_a_failed_skill_is_never_all_clear(self):
        line = guardian.summary_line([_skill("scan"), _skill("baseline_check", False)])
        assert line == ("1 of 2 skills failed to run (baseline_check). Their checks didn't happen, so this run "
                        "can't say the machine is clean.")

    def test_findings_and_notes_counted_apart(self):
        line = guardian.summary_line([_skill("scan", True, "high", "info"), _skill("harden", True, "info")])
        assert line == "1 finding from 2 skills, and 2 notes."

    def test_failure_and_findings_both_reported(self):
        line = guardian.summary_line([_skill("scan", True, "critical"), _skill("harden", False)])
        assert "failed to run (harden)" in line and "1 finding from 2 skills." in line

    def test_all_clear_only_when_everything_ran(self):
        assert guardian.summary_line([_skill("scan"), _skill("harden")]) == \
            "All clear: 2 skills ran and found nothing that needs action."
        assert guardian.summary_line([_skill("scan", True, "info")]) == \
            "All clear: 1 skill ran and found nothing that needs action (1 note in the log)."

    @pytest.mark.parametrize("results,code", [([_skill("scan")], 0), ([_skill("scan"), _skill("x", False)], 1)])
    def test_main_exits_1_when_a_skill_failed(self, results, code, monkeypatch, tmp_path, capsys):
        monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
        monkeypatch.setattr(sys, "argv", ["guardian"])
        monkeypatch.setattr(guardian, "run_guardian", lambda **kw: results)
        assert guardian.main() == code
        assert guardian.summary_line(results) in capsys.readouterr().out


# ── The CLI's own words ──

class TestCliWords:
    def test_profile_and_baseline_print_the_real_state_dir(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "state"))
        monkeypatch.setattr(cli, "profile_system", lambda: types.SimpleNamespace(summary=lambda: "profile"))
        monkeypatch.setattr(cli, "save_profile", lambda p: None)

        class FakeBaseline:
            def create(self):
                return 3

            def save(self):
                pass
        monkeypatch.setattr(cli, "FileBaseline", FakeBaseline)
        cli.cmd_profile(None)
        cli.cmd_baseline(types.SimpleNamespace(action="create"))
        out = capsys.readouterr().out
        assert f"Profile saved to {tmp_path / 'state' / 'profile.json'}" in out
        assert f"Saved to {tmp_path / 'state' / 'baseline.json'}" in out
        assert "~/.sentinel" not in out

    def test_full_assessment_banner_and_closing(self, monkeypatch, tmp_path, capsys):
        import advisor.hardening
        monkeypatch.setattr(cli, "profile_system", lambda: types.SimpleNamespace(summary=lambda: "profile"))
        monkeypatch.setattr(cli, "save_profile", lambda p: None)
        monkeypatch.setattr(SentinelScanner, "scan", lambda self: _result("info"))
        monkeypatch.setattr(advisor.hardening, "HardeningAdvisor", lambda: types.SimpleNamespace(report=lambda: "r"))
        monkeypatch.setattr(cli.FileBaseline, "load", classmethod(
            lambda cls: types.SimpleNamespace(file_count=2, check=lambda: [])))
        assert cli.cmd_all(None) == 0
        out = capsys.readouterr().out
        assert "SERENO — FULL ASSESSMENT" in out
        assert "COMMUNITY DEFENDER" not in out
        assert "No issues found. Stay safe out there." in out
