"""The network check (2026-10-23): low TCP ports aren't skipped, local-only listeners are info, low UDP services count."""
import pytest

from sentinel import scanner
from sentinel.scanner import check_network


def ss(lines):
    return "\n".join(["State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"] + lines)


def setup(monkeypatch, tmp_path, tcp, udp, mac=False):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    monkeypatch.setattr(scanner, "_is_linux", lambda: not mac)
    monkeypatch.setattr(scanner, "_is_macos", lambda: mac)

    def run(cmd, timeout=30):
        is_udp = "-ulnp" in cmd or "-iUDP" in cmd
        return (udp if is_udp else tcp), 0
    monkeypatch.setattr(scanner, "_run", run)


def found(findings):
    return sorted((f.severity, f.details.get("proto"), f.details["port"]) for f in findings)


def test_linux_listeners(monkeypatch, tmp_path):
    tcp = ss(['LISTEN 0 4096 0.0.0.0:444 0.0.0.0:* users:(("sh",pid=9,fd=3))',     # a low port: was skipped
              'LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*',
              'LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*',
              'LISTEN 0 4096 [::1]:5432 [::]:*',
              'LISTEN 0 4096 [::]:22 [::]:*',
              'LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*',
              'LISTEN 0 4096 *:3389 *:*',
              'LISTEN 0 4096 *:3389 *:*'])                                       # the same twice: once
    udp = ss(['UNCONN 0 0 0.0.0.0:69 0.0.0.0:*',
              'UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*',
              'UNCONN 0 0 0.0.0.0:68 0.0.0.0:*',
              'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*',
              'UNCONN 0 0 0.0.0.0:41641 0.0.0.0:*'])
    setup(monkeypatch, tmp_path, tcp, udp)
    # 3389 with its owner hidden was medium until 2026-10-24; it's now named by its port as likely remote desktop, high
    assert found(check_network()) == [("high", "TCP", "3389"), ("info", "TCP", "53"), ("info", "TCP", "5432"),
                                      ("info", "TCP", "631"), ("medium", "TCP", "444"), ("medium", "UDP", "69")]


def test_wording_says_who_can_reach_it(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path, ss(['LISTEN 0 1 127.0.0.1:631 0.0.0.0:*', 'LISTEN 0 1 0.0.0.0:444 0.0.0.0:*']),
          ss(['UNCONN 0 0 0.0.0.0:69 0.0.0.0:*']))
    by = {(f.details["proto"], f.details["port"]): f for f in check_network()}
    assert by[("TCP", "631")].title.endswith("(this machine only)")
    assert "this machine only" in by[("TCP", "631")].description
    assert "other machines" in by[("TCP", "444")].description
    assert by[("UDP", "69")].title == "Unexpected listening port: 69 (UDP)"


def test_an_expected_low_port_is_info(monkeypatch, tmp_path):
    (tmp_path / "expected.json").write_text('{"ports": [444]}')
    setup(monkeypatch, tmp_path, ss(['LISTEN 0 1 0.0.0.0:444 0.0.0.0:*']), ss([]))
    f = check_network()
    assert len(f) == 1 and f[0].severity == "info" and f[0].details["expected"] is True


def test_macos_lsof_format(monkeypatch, tmp_path):
    hdr = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME"
    tcp = "\n".join([hdr, "ollama 1 m 3u IPv4 0x1 0t0 TCP 127.0.0.1:11434 (LISTEN)",
                     "srv 2 m 4u IPv6 0x2 0t0 TCP *:7000 (LISTEN)", "sshd 3 m 5u IPv4 0x3 0t0 TCP *:22 (LISTEN)"])
    udp = "\n".join([hdr, "netbiosd 4 root 5u IPv4 0x4 0t0 UDP *:137", "tftpd 5 root 6u IPv4 0x5 0t0 UDP *:69",
                     "mDNSResp 6 root 7u IPv4 0x6 0t0 UDP *:5353"])
    setup(monkeypatch, tmp_path, tcp, udp, mac=True)
    assert found(check_network()) == [("info", "TCP", "11434"), ("medium", "TCP", "7000"), ("medium", "UDP", "69")]


@pytest.mark.parametrize("host,local", [("127.0.0.1", True), ("127.0.0.53%lo", True), ("[::1]", True),
                                        ("::ffff:127.0.0.1", True), ("0.0.0.0", False), ("*", False),
                                        ("[::]", False), ("100.80.54.90", False), ("192.168.1.5", False),
                                        # bound to the loopback device: only this machine reaches it (2026-10-24)
                                        ("0.0.0.0%lo", True), ("fe80::1%lo0", True), ("[fe80::1]%lo", True),
                                        ("[::]%lo", True), ("0.0.0.0%eth0", False), ("fe80::1%en0", False),
                                        ("0.0.0.0%lo1", False)])
def test_loopback(host, local):
    from sentinel.listeners import loopback
    assert loopback(host) is local


def test_a_failed_listing_is_not_checked_never_clean(monkeypatch, tmp_path):
    """Until 2026-10-24 a protocol ss couldn't list was skipped in silence, so the scan read clean. Now /proc/net is
    tried, and when that can't be read either, the protocol is reported as not checked."""
    from sentinel import listeners
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    monkeypatch.setattr(listeners, "PROC", tmp_path / "no-proc")
    monkeypatch.setattr(scanner, "_is_linux", lambda: True)
    monkeypatch.setattr(scanner, "_is_macos", lambda: False)
    monkeypatch.setattr(scanner, "_run", lambda cmd, timeout=30: ("", 1) if "-ulnp" in cmd
                        else (ss(['LISTEN 0 1 0.0.0.0:444 0.0.0.0:*']), 0))
    findings = check_network()
    assert sorted((f.severity, f.details["proto"], f.details.get("port")) for f in findings) == [
        ("medium", "TCP", "444"), ("medium", "UDP", None)]
    assert [f.title for f in findings if f.details.get("not_checked")] == ["Listening ports not checked (UDP)"]
