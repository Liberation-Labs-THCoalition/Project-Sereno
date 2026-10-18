"""Tests for operator-declared expected listening ports (Packet S3, phase 1).

Phase 2 will shrink the hard-coded ``known_safe_ports`` in
``sentinel.scanner.check_network`` to ``{"22", "80", "443"}`` and instead let
each operator list the ports they run on purpose in
``sentinel_home() / "expected.json"`` as ``{"ports": [4444, "11434", ...]}``.

A listening port above 1024 that the operator listed is STILL reported, but as an
``info`` finding whose title contains "expected by operator" (never dropped).
Any other port above 1024 is a ``medium`` "Unexpected listening port: N" finding,
as today. A malformed expected.json must never crash the check: it adds one
``medium`` finding titled "expected.json unreadable" and no port is treated as
expected.

These tests are written against the phase-2 contract, so they are expected to
FAIL against today's code (which silently drops lab-specific ports and ignores
expected.json entirely).
"""
import json

import pytest

from sentinel.scanner import check_network


# ── Helpers ────────────────────────────────────────────────────────────────

def _ss_output(ports):
    """Build a fake ``ss -tlnp`` listing: a header line, then one line per port.

    Each port line mirrors the real format, e.g.::

        LISTEN 0 4096 0.0.0.0:4444 0.0.0.0:* users:(("x",pid=1,fd=3))
    """
    lines = ["State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"]
    for p in ports:
        lines.append(
            f'LISTEN 0 4096 0.0.0.0:{p} 0.0.0.0:* users:(("x",pid=1,fd=3))'
        )
    return "\n".join(lines)


def _setup(monkeypatch, tmp_path, ports):
    """Point SENTINEL_HOME at tmp_path and stub the platform / command layer.

    - ``SENTINEL_HOME`` -> tmp_path (so expected.json lives there)
    - ``_is_linux`` -> True, ``_is_macos`` -> False (force the ``ss`` branch)
    - ``_run`` -> returns (fake ss output, 0)
    """
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    monkeypatch.setattr("sentinel.scanner._is_linux", lambda: True)
    monkeypatch.setattr("sentinel.scanner._is_macos", lambda: False)
    output = _ss_output(ports)
    monkeypatch.setattr("sentinel.scanner._run", lambda *a, **k: (output, 0))


def _find_for_port(findings, port):
    """Return the finding associated with a given port, or None.

    Matches by the port number appearing in the title first, then by the
    ``port`` detail, so it works whether or not the title embeds the number.
    """
    port = str(port)
    for f in findings:
        if port in f.title:
            return f
    for f in findings:
        if str(f.details.get("port", "")) == port:
            return f
    return None


# ── Tests ──────────────────────────────────────────────────────────────────

def test_an_expected_port_is_reported_as_info(tmp_path, monkeypatch):
    """An operator-listed port is reported as info, not dropped; others stay medium."""
    _setup(monkeypatch, tmp_path, [4444, 5555])
    (tmp_path / "expected.json").write_text(json.dumps({"ports": [4444]}))

    findings = check_network()

    f4444 = _find_for_port(findings, 4444)
    assert f4444 is not None, "expected port 4444 must still be reported, not dropped"
    assert f4444.severity == "info"
    assert "expected by operator" in f4444.title

    f5555 = _find_for_port(findings, 5555)
    assert f5555 is not None
    assert f5555.severity == "medium"


def test_the_file_changes_severity_not_the_count(tmp_path, monkeypatch):
    """expected.json reclassifies a port's severity but does not change the count."""
    _setup(monkeypatch, tmp_path, [4444, 5555])

    findings_without = check_network()

    (tmp_path / "expected.json").write_text(json.dumps({"ports": [4444]}))
    findings_with = check_network()

    # Both ports are reported in either case; only 4444's severity changes.
    assert len(findings_without) == len(findings_with)
    assert len(findings_with) == 2


def test_a_lab_port_is_no_longer_suppressed(tmp_path, monkeypatch):
    """A former hard-coded lab port (4222) is reported as medium when not expected."""
    _setup(monkeypatch, tmp_path, [4222])
    # No expected.json at all.

    findings = check_network()

    f4222 = _find_for_port(findings, 4222)
    assert f4222 is not None, "4222 must no longer be silently suppressed"
    assert f4222.severity == "medium"
    assert len(findings) == 1


def test_ports_compare_as_strings(tmp_path, monkeypatch):
    """Ports in expected.json may be strings; comparison is string-based."""
    _setup(monkeypatch, tmp_path, [4444])
    (tmp_path / "expected.json").write_text(json.dumps({"ports": ["4444"]}))

    findings = check_network()

    f4444 = _find_for_port(findings, 4444)
    assert f4444 is not None
    assert f4444.severity == "info"
    assert "expected by operator" in f4444.title


def test_a_malformed_file_never_crashes(tmp_path, monkeypatch):
    """A malformed expected.json adds one medium 'unreadable' finding and drops no port."""
    _setup(monkeypatch, tmp_path, [4444])
    (tmp_path / "expected.json").write_text("{not json")

    # Must return normally (no exception).
    findings = check_network()

    unreadable = [f for f in findings if "expected.json unreadable" in f.title]
    assert len(unreadable) == 1
    assert unreadable[0].severity == "medium"

    # With no port treated as expected, 4444 is a plain medium finding, not info.
    f4444 = _find_for_port(findings, 4444)
    assert f4444 is not None
    assert f4444.severity == "medium"
    assert f4444.severity != "info"
