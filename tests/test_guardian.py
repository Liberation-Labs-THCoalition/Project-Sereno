"""S1 (rollout spec 2026-10-16, Sereno): Sereno keeps all its state in ONE
directory, $SENTINEL_HOME (default ~/.sentinel), read at call time.

These tests demand that:
  * importing sentinel.guardian creates no directory,
  * a guardian run writes only under sentinel_home(),
  * the baseline and profile default to sentinel_home(),
  * no file under sentinel/ or advisor/ mentions ".ember" any more.

They are written first; phase 2 changes the code to make them pass.
"""
import os
import subprocess
from pathlib import Path

import pytest

import sentinel.guardian
import sentinel.skills
from sentinel.alerts import AlertBus
from sentinel.baseline import FileBaseline
from sentinel.profiler import SystemProfile, save_profile, load_profile


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_importing_the_guardian_creates_no_directory(tmp_path):
    """Importing the guardian must not create any directory on disk."""
    home = tmp_path / "h"
    home.mkdir()
    state = tmp_path / "state"

    env = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": str(_repo_root()),
        "HOME": str(home),
        "SENTINEL_HOME": str(state),
    }

    result = subprocess.run(
        ["python3", "-c", "import sentinel.guardian"],
        cwd=str(_repo_root()),
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert not state.exists(), "importing the guardian created $SENTINEL_HOME"
    assert not (home / ".sentinel").exists(), "importing the guardian created ~/.sentinel"
    assert not (home / ".ember").exists(), "importing the guardian created ~/.ember"


def test_a_guardian_run_writes_only_under_sentinel_home(tmp_path, monkeypatch):
    """A guardian run must write its run files and BDI state under sentinel_home()."""
    home = tmp_path / "h"
    home.mkdir()
    state = tmp_path / "state"

    monkeypatch.setenv("SENTINEL_HOME", str(state))
    monkeypatch.setenv("HOME", str(home))

    # Replace the sensors so nothing real is scanned. Since S2 they run in-process, so the four entry points are
    # patched (a subprocess patch would no longer stop anything: CC's review of S2, 2026-10-17).
    from sentinel.baseline import FileBaseline
    from sentinel.profiler import SystemProfile
    from sentinel.scanner import ScanResult
    monkeypatch.setattr("sentinel.scanner.SentinelScanner.scan",
                        lambda self: ScanResult(hostname="h", platform="p", scan_time="t", duration_ms=0.0))
    monkeypatch.setattr("sentinel.baseline.FileBaseline.load", staticmethod(lambda *a, **k: FileBaseline()))
    monkeypatch.setattr("sentinel.profiler.profile_system", lambda: SystemProfile(hostname="h"))
    monkeypatch.setattr("advisor.hardening.HardeningAdvisor.assess", lambda self: [])

    class Recorder:
        def __init__(self):
            self.messages = []

        def send(self, message, severity="info"):
            self.messages.append((message, severity))
            return True

    recorder = Recorder()

    sentinel.guardian.run_guardian(
        force="all",
        alert_bus=AlertBus([recorder]),
    )

    run_files = list((state / "guardian_runs").glob("run_*.json"))
    assert run_files, "no run_*.json written under sentinel_home()/guardian_runs"
    assert (state / "bdi_state.json").exists(), "bdi_state.json not written under sentinel_home()"
    assert not (home / ".ember").exists(), "guardian run wrote to ~/.ember instead of sentinel_home()"


def test_baseline_and_profile_default_to_sentinel_home(tmp_path, monkeypatch):
    """Baseline and profile with no explicit path default to sentinel_home()."""
    home = tmp_path / "h"
    home.mkdir()

    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(home))

    # Baseline: save with no path, then load it back.
    FileBaseline().save()
    assert (tmp_path / "baseline.json").exists(), "baseline did not default to sentinel_home()/baseline.json"
    loaded = FileBaseline.load()
    assert loaded is not None

    # Profile: save with no path, then load it back.
    save_profile(SystemProfile(hostname="test-host"))
    assert (tmp_path / "profile.json").exists(), "profile did not default to sentinel_home()/profile.json"
    profile = load_profile()
    assert profile is not None
    assert profile.hostname == "test-host"


def test_no_file_mentions_dot_ember():
    """No file under sentinel/ or advisor/ may mention '.ember' any more."""
    root = _repo_root()
    offenders = []
    for pkg in ("sentinel", "advisor"):
        for py in (root / pkg).rglob("*.py"):
            text = py.read_text()
            if ".ember" in text:
                offenders.append(str(py))
    assert not offenders, f"files still mention '.ember': {offenders}"
