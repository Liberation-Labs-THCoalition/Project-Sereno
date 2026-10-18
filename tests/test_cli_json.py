"""Packet S4, phase 1: "--json scans once".

cmd_scan(args) runs scanner.scan() once, then under --json calls
scanner.scan_to_json(), which scans AGAIN. The JSON printed can then
disagree with the result that chose the alerts and the exit code.

These tests pin the desired behaviour: a single scan, and the printed
JSON (and any output file) must be the same result that drove the
alerts and the exit code.
"""
import json
import types

import sentinel.alerts
from sentinel.scanner import SentinelScanner, ScanResult, Finding
from sentinel.__main__ import cmd_scan


def _make_args(output=""):
    """Build the args namespace cmd_scan expects for a --json scan."""
    return types.SimpleNamespace(
        checks="",
        cron=False,
        log="",
        discord="",
        json=True,
        output=output,
    )


def _install_scan(monkeypatch, calls):
    """Replace SentinelScanner.scan with a counting stub and silence alerts.

    The stub appends to `calls` on every invocation so a test can assert
    how many times a scan actually ran, and returns a fixed ScanResult
    with a single medium-severity finding (no critical -> exit code 0).
    """
    def fake_scan(self):
        calls.append(1)
        return ScanResult(
            hostname="h",
            platform="p",
            scan_time="t",
            duration_ms=0.0,
            findings=[
                Finding(
                    check="network",
                    severity="medium",
                    title="Unexpected listening port: 5555",
                    description="d",
                )
            ],
        )

    # Patch the class attribute; the same class object is referenced from
    # sentinel.__main__ (imported via `from .scanner import SentinelScanner`).
    monkeypatch.setattr(SentinelScanner, "scan", fake_scan)
    # Nothing should actually be sent anywhere.
    monkeypatch.setattr(
        sentinel.alerts.AlertBus, "alert_findings", lambda self, result: None
    )


def test_json_scans_exactly_once(monkeypatch):
    """Under --json the scan must run exactly once, not twice."""
    calls = []
    _install_scan(monkeypatch, calls)

    args = _make_args()
    cmd_scan(args)

    assert len(calls) == 1, (
        f"expected exactly one scan, got {len(calls)}: "
        "cmd_scan scans once, then scan_to_json scans again"
    )


def test_the_printed_json_is_the_result_that_chose_the_exit_code(
    monkeypatch, capsys
):
    """The JSON on stdout must be the result that drove the exit code."""
    calls = []
    _install_scan(monkeypatch, calls)

    args = _make_args()
    rc = cmd_scan(args)

    out = capsys.readouterr().out
    data = json.loads(out)

    # The printed finding is the one the stub produced.
    assert data["findings"][0]["title"] == "Unexpected listening port: 5555"
    # No critical finding -> exit code 0, matching the result that was scanned.
    assert rc == 0


def test_output_file_holds_the_same_json(monkeypatch, capsys, tmp_path):
    """With -o, the file must hold the same JSON that was printed."""
    calls = []
    _install_scan(monkeypatch, calls)

    out_path = tmp_path / "scan.json"
    args = _make_args(output=str(out_path))
    cmd_scan(args)

    out = capsys.readouterr().out

    assert out_path.exists(), "output file was not written"

    file_data = json.loads(out_path.read_text())
    printed_data = json.loads(out)

    # File and stdout must be the same serialised result.
    assert file_data == printed_data
    # And still only one scan.
    assert len(calls) == 1, (
        f"expected exactly one scan, got {len(calls)}"
    )
