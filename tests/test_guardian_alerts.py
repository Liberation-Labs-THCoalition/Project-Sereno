"""S2 (rollout spec 2026-10-16, Sereno): "findings become alerts".

The defect: the sensor skills in sentinel/skills.py return only observations
(they shell out and count findings), and the guardian (sentinel/guardian.py)
alerts only on assessments at critical or high. So the guardian has never
alerted on a compromised package.

These tests demand that phase 2 makes the skills return Assessments:
  * _scan_packages / _scan_persistence / _scan_network run
    SentinelScanner(checks=[...]).scan() in-process and return one
    Assessment(severity=f.severity, title=f.title, details=f.description,
    grounded_in=[f.check]) per Finding.
  * _check_baseline loads FileBaseline.load(); an empty baseline (no records)
    gives ONE assessment at "medium" titled "No file-integrity baseline
    exists"; otherwise one assessment per FileChange from baseline.check():
    "high" for modified or removed, "medium" for anything else.
  * _get_hardening(bdi=None, **kwargs) maps severities
    critical->critical, important->high, suggested->medium,
    informational->info, anything else->high, and emits assessments only when
    the sorted list of recommendation titles differs from the last run's,
    kept as the belief "last_hardening" in the BDIEngine passed as bdi.
  * _profile_system runs profile_system() in-process.
  * The guardian passes its BDIEngine to the skills:
    run_chain(intention.skills, bdi=bdi).

They are written first; phase 2 changes the code to make them pass.
"""
import types
from pathlib import Path

import pytest

import sentinel.guardian
import sentinel.skills
from sentinel.alerts import AlertBus
from sentinel.baseline import FileBaseline, FileChange, FileRecord
from sentinel.profiler import SystemProfile
from sentinel.scanner import Finding, ScanResult
from sentinel.skills import BDIEngine, create_default_bdi
from sentinel.guardian import run_guardian
from advisor.hardening import Recommendation


# ── Recorder transport ──

class Recorder:
    """An alert transport that records (message, severity) pairs."""

    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []

    def send(self, message: str, severity: str = "info") -> bool:
        self.messages.append((message, severity))
        return True


# ── Helpers ──

def _default_baseline() -> FileBaseline:
    """A baseline with one record whose check() reports no changes."""
    b = FileBaseline()
    b._records["/etc/hosts"] = FileRecord(
        path="/etc/hosts",
        sha256="abc123",
        size=10,
        mtime=1.0,
        permissions="644",
    )
    b.check = lambda: []
    return b


def _changed_baseline() -> FileBaseline:
    """A baseline whose check() reports one modified file."""
    b = FileBaseline()
    b._records["/etc/x"] = FileRecord(
        path="/etc/x",
        sha256="abc123",
        size=10,
        mtime=1.0,
        permissions="644",
    )
    b.check = lambda: [FileChange(path="/etc/x", change_type="modified")]
    return b


def _setup_env(tmp_path: Path, monkeypatch) -> None:
    """Point state at tmp_path and stub every real scan to the defaults.

    The defaults:
      * SentinelScanner.scan -> ScanResult(hostname="h", platform="p",
        scan_time="t", duration_ms=0.0, findings=[])
      * FileBaseline.load -> a baseline with one record, check() -> []
      * profile_system -> SystemProfile(hostname="h")
      * HardeningAdvisor.assess -> []
    """
    home = tmp_path / "h"
    home.mkdir()

    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(home))

    # The four in-process entry points phase 2 will use.
    monkeypatch.setattr(
        "sentinel.scanner.SentinelScanner.scan",
        lambda self: ScanResult(
            hostname="h", platform="p", scan_time="t", duration_ms=0.0, findings=[]
        ),
    )
    monkeypatch.setattr(
        "sentinel.baseline.FileBaseline.load",
        staticmethod(lambda *a, **k: _default_baseline()),
    )
    monkeypatch.setattr(
        "sentinel.profiler.profile_system",
        lambda: SystemProfile(hostname="h"),
    )
    monkeypatch.setattr(
        "advisor.hardening.HardeningAdvisor.assess",
        lambda self: [],
    )

    # Safety net for the current subprocess-based skills: nothing real is
    # scanned, and the run stays fast and deterministic.
    monkeypatch.setattr(
        "sentinel.skills.subprocess.run",
        lambda *a, **k: types.SimpleNamespace(
            stdout='{"findings": []}', stderr="", returncode=0
        ),
    )


# ── Tests ──

def test_a_critical_finding_reaches_the_alert_transport(tmp_path, monkeypatch):
    """A critical Finding from a scan must surface as a critical alert."""
    _setup_env(tmp_path, monkeypatch)

    # Override the scan to return one critical finding.
    monkeypatch.setattr(
        "sentinel.scanner.SentinelScanner.scan",
        lambda self: ScanResult(
            hostname="h",
            platform="p",
            scan_time="t",
            duration_ms=0.0,
            findings=[
                Finding(
                    check="npm_supply_chain",
                    severity="critical",
                    title="Compromised package evil-pkg",
                    description="d",
                )
            ],
        ),
    )

    recorder = Recorder()
    run_guardian(
        bdi=create_default_bdi(),
        force="all",
        alert_bus=AlertBus([recorder]),
    )

    assert any(
        "Compromised package evil-pkg" in msg and sev == "critical"
        for msg, sev in recorder.messages
    ), f"no critical alert for the compromised package; got {recorder.messages}"


def test_a_clean_scan_sends_nothing(tmp_path, monkeypatch):
    """With all defaults (no findings, no changes, no recommendations),
    the guardian must not send a single message."""
    _setup_env(tmp_path, monkeypatch)

    recorder = Recorder()
    run_guardian(
        bdi=create_default_bdi(),
        force="all",
        alert_bus=AlertBus([recorder]),
    )

    assert recorder.messages == [], f"clean scan produced messages: {recorder.messages}"


def test_high_alerts_and_medium_does_not(tmp_path, monkeypatch):
    """A high Finding alerts; a medium Finding does not."""
    _setup_env(tmp_path, monkeypatch)

    monkeypatch.setattr(
        "sentinel.scanner.SentinelScanner.scan",
        lambda self: ScanResult(
            hostname="h",
            platform="p",
            scan_time="t",
            duration_ms=0.0,
            findings=[
                Finding(
                    check="persistence",
                    severity="high",
                    title="High thing",
                    description="d",
                ),
                Finding(
                    check="network",
                    severity="medium",
                    title="Medium thing",
                    description="d",
                ),
            ],
        ),
    )

    recorder = Recorder()
    run_guardian(
        bdi=create_default_bdi(),
        force="all",
        alert_bus=AlertBus([recorder]),
    )

    assert any("High thing" in msg for msg, _ in recorder.messages), (
        f"no alert for the high finding; got {recorder.messages}"
    )
    assert not any("Medium thing" in msg for msg, _ in recorder.messages), (
        f"medium finding produced an alert; got {recorder.messages}"
    )


def test_an_empty_baseline_is_not_clean(tmp_path, monkeypatch):
    """An empty baseline (no records) is itself a finding: one medium
    assessment titled 'No file-integrity baseline exists'."""
    _setup_env(tmp_path, monkeypatch)

    # load returns a baseline with no records.
    monkeypatch.setattr(
        "sentinel.baseline.FileBaseline.load",
        staticmethod(lambda *a, **k: FileBaseline()),
    )

    result = sentinel.skills._check_baseline()

    assert len(result.assessments) == 1, (
        f"empty baseline should yield exactly one assessment; got {result.assessments}"
    )
    assert result.assessments[0].severity == "medium", (
        f"empty baseline assessment should be medium; got {result.assessments[0].severity}"
    )
    assert "No file-integrity baseline" in result.assessments[0].title, (
        f"empty baseline assessment title wrong; got {result.assessments[0].title!r}"
    )


def test_a_changed_baseline_file_is_high(tmp_path, monkeypatch):
    """A modified (or removed) baseline file yields a high assessment."""
    _setup_env(tmp_path, monkeypatch)

    # load returns a baseline whose check() reports one modified file.
    monkeypatch.setattr(
        "sentinel.baseline.FileBaseline.load",
        staticmethod(lambda *a, **k: _changed_baseline()),
    )

    result = sentinel.skills._check_baseline()

    assert len(result.assessments) == 1, (
        f"one changed file should yield exactly one assessment; got {result.assessments}"
    )
    assert result.assessments[0].severity == "high", (
        f"modified baseline file should be high; got {result.assessments[0].severity}"
    )


def test_hardening_alerts_only_when_the_set_changes(tmp_path, monkeypatch):
    """_get_hardening emits assessments only when the set of recommendation
    titles changes from the last run (stored as belief 'last_hardening')."""
    _setup_env(tmp_path, monkeypatch)

    bdi = BDIEngine(state_file=str(tmp_path / "bdi.json"))

    rec_a = Recommendation(
        category="auth",
        severity="important",
        title="A",
        what="w",
        why="y",
        fix="f",
        difficulty="easy",
    )
    monkeypatch.setattr(
        "advisor.hardening.HardeningAdvisor.assess",
        lambda self: [rec_a],
    )

    # First run: no prior 'last_hardening' belief -> counts as changed.
    r1 = sentinel.skills._get_hardening(bdi=bdi)
    assert len(r1.assessments) == 1, (
        f"first hardening run should emit one assessment; got {r1.assessments}"
    )
    assert r1.assessments[0].severity == "high", (
        f"important severity should map to high; got {r1.assessments[0].severity}"
    )

    # Second run, same recommendations -> no change -> no assessments.
    r2 = sentinel.skills._get_hardening(bdi=bdi)
    assert r2.assessments == [], (
        f"unchanged hardening set should emit nothing; got {r2.assessments}"
    )

    # Third run, a second recommendation added -> changed -> two assessments.
    rec_b = Recommendation(
        category="auth",
        severity="important",
        title="B",
        what="w",
        why="y",
        fix="f",
        difficulty="easy",
    )
    monkeypatch.setattr(
        "advisor.hardening.HardeningAdvisor.assess",
        lambda self: [rec_a, rec_b],
    )
    r3 = sentinel.skills._get_hardening(bdi=bdi)
    assert len(r3.assessments) == 2, (
        f"changed hardening set should emit two assessments; got {r3.assessments}"
    )


def test_an_unknown_hardening_severity_is_high(tmp_path, monkeypatch):
    """A recommendation with an unrecognized severity maps to 'high'."""
    _setup_env(tmp_path, monkeypatch)

    bdi = BDIEngine(state_file=str(tmp_path / "bdi.json"))

    rec = Recommendation(
        category="auth",
        severity="weird",
        title="X",
        what="w",
        why="y",
        fix="f",
        difficulty="easy",
    )
    monkeypatch.setattr(
        "advisor.hardening.HardeningAdvisor.assess",
        lambda self: [rec],
    )

    result = sentinel.skills._get_hardening(bdi=bdi)

    assert len(result.assessments) == 1, (
        f"one recommendation should yield one assessment; got {result.assessments}"
    )
    assert result.assessments[0].severity == "high", (
        f"unknown severity should map to high; got {result.assessments[0].severity}"
    )


def test_the_guardian_remembers_hardening_between_runs(tmp_path, monkeypatch):
    """The guardian passes its BDIEngine to the skills, so hardening alerts
    fire on the first run but not again when the set is unchanged."""
    _setup_env(tmp_path, monkeypatch)

    rec_a = Recommendation(
        category="auth",
        severity="important",
        title="A",
        what="w",
        why="y",
        fix="f",
        difficulty="easy",
    )
    monkeypatch.setattr(
        "advisor.hardening.HardeningAdvisor.assess",
        lambda self: [rec_a],
    )

    # One bdi object, shared across both runs.
    bdi = create_default_bdi()
    recorder = Recorder()

    # First run.
    run_guardian(bdi=bdi, force="all", alert_bus=AlertBus([recorder]))
    after_first = [m for m, sev in recorder.messages if "A" in m and sev == "high"]
    assert after_first, (
        f"expected a 'A' high alert after the first run; got {recorder.messages}"
    )

    # Second run, same bdi, same recommendations.
    run_guardian(bdi=bdi, force="all", alert_bus=AlertBus([recorder]))
    after_second = [m for m, sev in recorder.messages if "A" in m and sev == "high"]
    assert len(after_second) == len(after_first), (
        f"no new 'A' high alert should appear on the second run; "
        f"first={len(after_first)} second={len(after_second)}"
    )
