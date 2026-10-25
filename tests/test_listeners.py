"""Listening ports, named (2026-10-24): every TCP and UDP listener tied to its program and binary where visible, known
services named, remote control high whatever the port, Tailscale's own listeners recognised. All command output is
planted; nothing here reads the real machine's sockets or /proc."""
import json
import os

import pytest

from sentinel import listeners, scanner
from sentinel.scanner import check_network

SS_HDR = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
LSOF_HDR = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME"
NETSTAT_HDR = "Active Internet connections (including servers)\nProto Recv-Q Send-Q Local Address Foreign Address (state)"
TS_JSON = json.dumps({"BackendState": "Running", "Self": {
    "TailscaleIPs": ["100.80.54.90", "fd7a:115c:a1e0::c636:365a"],
    "PeerAPIURL": ["http://100.80.54.90:56893", "http://[fd7a:115c:a1e0::c636:365a]:59823"]}})


def _key(cmd):
    if cmd[0] == "ss":
        return "ss-udp" if "-ulnp" in cmd else "ss-tcp"
    if cmd[0] == "lsof":
        return "lsof-udp" if "-iUDP" in cmd else "lsof-tcp"
    if cmd[0] == "netstat":
        return "netstat-" + cmd[-1]
    if cmd[0] == "tailscale":
        return "tailscale"
    if cmd[0].endswith("/Tailscale"):
        return "tailscale-app"
    return cmd[0]


def env(monkeypatch, tmp_path, mac=False, euid=1000, expected=None, **outputs):
    """Plant command output by key (ss_tcp, ss_udp, lsof_tcp, lsof_udp, netstat_tcp, netstat_udp, tailscale,
    tailscale_app, ps): a string is (text, 0), a tuple is (text, rc); None, or a missing key, is a command that isn't
    there. On Linux both ss listings default to an empty table. Returns the list of (command, timeout) calls."""
    if not mac:
        outputs.setdefault("ss_tcp", SS_HDR)
        outputs.setdefault("ss_udp", SS_HDR)
    home = tmp_path / "sentinel"
    home.mkdir(exist_ok=True)
    if expected is not None:
        (home / "expected.json").write_text(json.dumps({"ports": expected}))
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    monkeypatch.setattr(listeners, "PROC", tmp_path / "proc")
    monkeypatch.setattr(listeners, "_euid", lambda: euid)
    monkeypatch.setattr(scanner, "_is_linux", lambda: not mac)
    monkeypatch.setattr(scanner, "_is_macos", lambda: mac)
    calls = []

    def run(cmd, timeout=30):
        calls.append((cmd, timeout))
        out = outputs.get(_key(cmd).replace("-", "_"))
        if out is None:
            return "", -1
        return out if isinstance(out, tuple) else (out, 0)
    monkeypatch.setattr(scanner, "_run", run)
    return calls


def ss(*lines):
    return "\n".join((SS_HDR,) + lines)


class Found(dict):
    """Findings by (protocol, port); asking for one that isn't there fails the test as an assertion."""
    def __missing__(self, key):
        raise AssertionError("no finding for %s; found %s" % (key, sorted(self)))


def by_port(findings):
    return Found(((f.details["proto"], f.details["port"]), f) for f in findings if "port" in f.details)


def one(findings):
    assert len(findings) == 1, [(f.severity, f.title) for f in findings]
    return findings[0]


def plant_proc(tmp_path, pid, comm=None, exe=None, fds=None, cmdline=None):
    d = tmp_path / "proc" / str(pid)
    d.mkdir(parents=True)
    if comm is not None:
        (d / "comm").write_text(comm + "\n")
    if exe is not None:
        os.symlink(exe, str(d / "exe"))
    if fds is not None:
        (d / "fd").mkdir()
        for fd, target in fds.items():
            os.symlink(target, str(d / "fd" / str(fd)))
    if cmdline is not None:
        (d / "cmdline").write_text(cmdline)


# ── The brief's cases ──

def test_rdp_by_program_on_a_nonstandard_port_is_high(monkeypatch, tmp_path):
    plant_proc(tmp_path, 4242, exe="/usr/libexec/gnome-remote-desktop-daemon",
               cmdline="gnome-remote-desktop-daemon\0--password\0hunter2")
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 50 *:3390 *:* users:(("gnome-remote-de",pid=4242,fd=12)) uid:1000 ino:555 sk:1 '
        'cgroup:/user.slice/user-1000.slice/user@1000.service/app.slice/gnome-remote-desktop.service <->'))
    f = one(check_network())
    assert f.severity == "high"
    assert f.title == "Remote desktop (gnome-remote-desktop) on port 3390"
    assert f.details["identified_by"] == "program"
    assert f.details["exe"] == "/usr/libexec/gnome-remote-desktop-daemon"
    assert f.details["owner_visible"] is True
    assert "Program: gnome-remote-de (pid 4242, /usr/libexec/gnome-remote-desktop-daemon), user " in f.description
    assert "reachable from other machines" in f.description
    assert "Port 3390 is the usual port for remote desktop (RDP)." in f.description
    assert "`grdctl rdp disable`" in f.remediation and "undo: `grdctl rdp enable`" in f.remediation
    assert "systemctl --user disable --now gnome-remote-desktop" in f.remediation
    assert "sudo grdctl --system rdp disable" in f.remediation
    assert "add 3390 to expected.json" in f.remediation
    # The privacy claim: a command line is never read, so a password in one never reaches a finding
    assert "hunter2" not in json.dumps([f.title, f.description, f.remediation, f.details])


def test_vnc_by_port_with_the_owner_hidden_is_high(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 5 0.0.0.0:5901 0.0.0.0:* ino:777 sk:2 <->'))
    f = one(check_network())
    assert f.severity == "high"
    assert f.title == "Likely remote desktop (VNC) on port 5901"
    assert "owner not visible without sudo" in f.description
    assert "The system shows it belongs to user root." in f.description
    assert "likely guess, not a fact" in f.description
    assert f.details["identified_by"] == "port" and f.details["owner_visible"] is False
    assert f.remediation.startswith("To see which program it is: `sudo ss -ltnup 'sport = :5901'`. ")
    assert "`vncserver -kill :1`" in f.remediation and "`grdctl vnc disable`" in f.remediation


def test_tailscale_peer_api_from_its_status_json_is_info(monkeypatch, tmp_path):
    calls = env(monkeypatch, tmp_path, tailscale=TS_JSON, ss_tcp=ss(
        'LISTEN 0 4096 100.80.54.90%tailscale0:56893 0.0.0.0:*',          # bound to the device: ss adds the zone
        'LISTEN 0 4096 [fd7a:115c:a1e0::c636:365a]:59823 [::]:*'))
    found = by_port(check_network())
    for port, host in (("56893", "100.80.54.90"), ("59823", "fd7a:115c:a1e0::c636:365a")):
        f = found[("TCP", port)]
        assert f.severity == "info", port
        assert f.title == "Tailscale peer API (tailscaled) on port %s" % port
        assert f.details["identified_by"] == "tailscale status"
        assert "lists %s port %s as this machine's peer API" % (host, port) in f.description
        assert "reachable from machines on your Tailscale network" in f.description
        assert f.remediation.startswith("Nothing to do")
    assert [c for c in calls if c[0][0] == "tailscale"] == [(["tailscale", "status", "--json"], 5)]


def test_an_unknown_root_owned_port_is_medium_owner_not_visible(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 128 0.0.0.0:7777 0.0.0.0:* ino:4242 sk:3 '
                                         'cgroup:/system.slice/mystery.service <->'))
    f = one(check_network())
    assert f.severity == "medium"
    assert f.title == "Unexpected listening port: 7777"
    assert ("Sereno can't see which program this is: owner not visible without sudo. The system shows it belongs to "
            "user root and systemd unit mystery.service.") in f.description
    assert f.details["uid"] == 0 and f.details["unit"] == "mystery.service"
    assert f.remediation == ("To see which program it is: `sudo ss -ltnup 'sport = :7777'`. Check what's using port "
                             "7777. If you don't recognize it, investigate. If you run it on purpose, add 7777 to "
                             "expected.json.")


def test_loopback_only_stays_info_even_for_remote_control(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 5 127.0.0.1:5900 0.0.0.0:* users:(("x11vnc",pid=50,fd=4)) uid:1000 ino:9 sk:4 <->',
        'LISTEN 0 5 [::1]:5900 [::]:* users:(("x11vnc",pid=50,fd=5)) uid:1000 ino:10 sk:5 <->',
        'LISTEN 0 5 127.0.0.1:8000 0.0.0.0:* users:(("python3",pid=51,fd=3)) uid:1000 ino:11 sk:6 <->'))
    found = by_port(check_network())
    vnc, web = found[("TCP", "5900")], found[("TCP", "8000")]
    assert (vnc.severity, web.severity) == ("info", "info")
    assert vnc.title == "Remote desktop (x11vnc) on port 5900 (this machine only)"
    assert vnc.details["hosts"] == ["127.0.0.1", "[::1]"]
    assert vnc.remediation.startswith("Only this machine can reach it (an SSH tunnel is the usual way in). If you "
                                      "didn't set that up: Stop it with `pkill -x x11vnc`")
    assert web.title == "Unexpected listening port: 8000 (this machine only)"
    assert "reachable from this machine only" in web.description


def test_an_expected_port_stays_info_even_for_remote_control(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, expected=[3389, "69"],
        ss_tcp=ss('LISTEN 0 2 *:3389 *:* users:(("xrdp",pid=7,fd=11)) uid:115 ino:12 sk:7 <->'),
        ss_udp=ss('UNCONN 0 0 0.0.0.0:69 0.0.0.0:* ino:13 sk:8 <->'))
    found = by_port(check_network())
    rdp, tftp = found[("TCP", "3389")], found[("UDP", "69")]
    assert (rdp.severity, tftp.severity) == ("info", "info")
    assert rdp.title == "Remote desktop (xrdp) on port 3389 (expected by operator)"
    assert tftp.title == "Listening port 69 (UDP) (expected by operator)"
    assert rdp.details["expected"] is True and rdp.remediation == ""
    assert "Port 3389 is listed in expected.json." in rdp.description


def test_macos_lsof_netstat_and_ps(monkeypatch, tmp_path):
    lsof_tcp = "\n".join([LSOF_HDR,
                          "sshd 3 root 5u IPv4 0x3 0t0 TCP *:22 (LISTEN)",
                          "rustdesk 812 m 9u IPv4 0x4 0t0 TCP *:21118 (LISTEN)",
                          "ollama 1 m 3u IPv4 0x1 0t0 TCP 127.0.0.1:11434 (LISTEN)"])
    lsof_udp = "\n".join([LSOF_HDR,
                          "Google\\x20Chrome 900 m 30u IPv4 0x9 0t0 UDP 192.168.1.5:61234->142.250.1.1:443",
                          "rustdesk 812 m 10u IPv4 0x5 0t0 UDP *:21116"])
    netstat_tcp = "\n".join([NETSTAT_HDR,
                             "tcp4 0 0 *.5900 *.* LISTEN",
                             "tcp4 0 0 127.0.0.1.11434 *.* LISTEN",
                             "tcp4 0 0 192.168.1.5.50000 17.1.1.1.443 ESTABLISHED",
                             "tcp6 0 0 ::1.7070 *.* LISTEN"])
    netstat_udp = "\n".join([NETSTAT_HDR, "udp4 0 0 *.5353 *.*", "udp4 0 0 *.21116 *.*",
                             "udp4 0 0 192.168.1.5.123 17.253.1.1.123", "udp4 0 0 *.137 *.*", "udp4 0 0 *.161 *.*"])
    calls = env(monkeypatch, tmp_path, mac=True, lsof_tcp=lsof_tcp, lsof_udp=lsof_udp, netstat_tcp=netstat_tcp,
                netstat_udp=netstat_udp,
                ps="  812 /Applications/RustDesk.app/Contents/MacOS/rustdesk\n    1 /usr/local/bin/ollama")
    findings = check_network()
    found = by_port(findings)
    assert sorted((f.severity, p, port) for (p, port), f in found.items()) == [
        ("high", "TCP", "21118"), ("high", "TCP", "5900"), ("high", "UDP", "21116"), ("info", "TCP", "11434"),
        ("info", "TCP", "7070"), ("medium", "UDP", "161")]
    desk = found[("TCP", "21118")]
    assert desk.title == "Remote desktop (RustDesk) on port 21118"
    assert desk.details["exe"] == "/Applications/RustDesk.app/Contents/MacOS/rustdesk"
    assert "sudo systemctl disable --now rustdesk" in desk.remediation
    assert found[("UDP", "21116")].title == "Remote desktop (RustDesk) on port 21116 (UDP)"
    sharing = found[("TCP", "5900")]
    assert sharing.title == "Likely remote desktop (VNC) on port 5900"
    assert "owner not visible without sudo" in sharing.description
    assert sharing.remediation.startswith("To see which program it is: `sudo lsof -nP -i :5900`. Switch it off: "
                                          "System Settings > General > Sharing")
    assert found[("TCP", "11434")].title == "Ollama on port 11434 (this machine only)"
    assert len([f for f in findings if f.details.get("port") == "11434"]) == 1  # lsof and netstat: one socket
    assert found[("TCP", "11434")].details["owner_visible"] is True
    assert found[("TCP", "7070")].details["hosts"] == ["::1"]
    assert ("UDP", "443") not in found  # a connected QUIC socket isn't a listener
    assert (["ps", "-o", "pid=,comm=", "-p", "1,3,812"], 30) in calls


def test_macos_not_checked_when_lsof_and_netstat_both_fail(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, mac=True, lsof_tcp="\n".join([LSOF_HDR, "x 1 m 3u IPv4 0x1 0t0 TCP *:7000 (LISTEN)"]),
        netstat_tcp=("", 1))
    findings = check_network()
    assert [(f.severity, f.title) for f in findings] == [
        ("medium", "Listening ports not checked (UDP)"), ("medium", "Listening ports partly checked (TCP)"),
        ("medium", "Unexpected listening port: 7000")]
    assert "lsof and netstat didn't work" in findings[0].description
    assert "Make sure netstat is available" in findings[0].remediation


def test_macos_lsof_finding_nothing_still_lists_netstat_sockets(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, mac=True, lsof_tcp=("", 1), lsof_udp=("", 1),
        netstat_tcp="\n".join([NETSTAT_HDR, "tcp46 0 0 *.8080 *.* LISTEN"]), netstat_udp="")
    f = one(check_network())
    assert (f.severity, f.title) == ("medium", "Unexpected listening port: 8080")
    assert "owner not visible without sudo" in f.description


# ── Linux sources ──

def test_ss_columns_and_owner_fields():
    rows = listeners.parse_ss("\n".join([
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
        'udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* uid:108 ino:14646 sk:3018 cgroup:/system.slice/avahi-daemon.service <->',
        'tcp LISTEN 0 4096 [::]:8080 [::]:* users:(("nginx",pid=20,fd=6),("nginx",pid=19,fd=6)) ino:5 sk:9 <->',
        'tcp LISTEN 0 4096 0.0.0.0:9000 0.0.0.0:*',
        'garbage', 'tcp LISTEN 0 4096 nonsense 0.0.0.0:*']), "TCP")
    assert [(r["proto"], r["host"], r["port"], r["uid"]) for r in rows] == [
        ("UDP", "0.0.0.0", "5353", 108), ("TCP", "[::]", "8080", 0), ("TCP", "0.0.0.0", "9000", None)]
    assert rows[0]["cgroup"] == "/system.slice/avahi-daemon.service" and rows[0]["programs"] == []
    assert rows[1]["programs"] == ["nginx", "nginx"] and rows[1]["pid"] == "20"


def test_proc_net_addresses():
    assert listeners._hex_host("0100007F") == "127.0.0.1"
    assert listeners._hex_host("00000000") == "0.0.0.0"
    assert listeners._hex_host("00000000000000000000000001000000") == "[::1]"
    assert listeners._hex_host("00000000000000000000000000000000") == "[::]"
    assert listeners._hex_host("0000C0FD00000000000000006A3536C6") == "[fdc0::c636:356a]"


PROC_TCP_HDR = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"


def plant_proc_net(tmp_path, tcp=(), tcp6=(), udp=(), udp6=()):
    net = tmp_path / "proc" / "net"
    net.mkdir(parents=True, exist_ok=True)
    for name, rows in (("tcp", tcp), ("tcp6", tcp6), ("udp", udp), ("udp6", udp6)):
        if rows is not None:
            (net / name).write_text("\n".join([PROC_TCP_HDR] + list(rows)) + "\n")


def row(local, remote, state, uid, inode):
    return "   0: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 %s 1 0000000000000000 100 0 0 10 0" % (
        local, remote, state, uid, inode)


def test_without_ss_proc_net_gives_the_sockets_and_their_programs(monkeypatch, tmp_path):
    plant_proc_net(tmp_path,
                   tcp=[row("00000000:0D3D", "00000000:0000", "0A", 115, "555"),     # *:3389, xrdp's
                        row("00000000:1E61", "00000000:0000", "0A", 0, "556"),       # *:7777, root's
                        row("0100007F:1F90", "0100007F:A2A9", "01", 1000, "557"),    # an established connection
                        "short line"],
                   tcp6=[row("00000000000000000000000001000000:1F41", "00000000000000000000000000000000:0000", "0A",
                             1000, "558")],                                         # [::1]:8001
                   udp=[row("00000000:0045", "00000000:0000", "07", 0, "559"),      # *:69, unconnected
                        row("00000000:00A1", "0100007F:0035", "07", 0, "560"),      # bound but connected
                        row("00000000:00A2", "00000000:0000", "01", 0, "561")],     # connected
                   udp6=None)
    plant_proc(tmp_path, 300, comm="xrdp", exe="/usr/sbin/xrdp",
               fds={0: "/dev/null", 3: "pipe:[77]", 4: "socket:[555]", 5: "socket:[999]"})
    plant_proc(tmp_path, 301, comm="other")                       # no fd folder: another user's process
    plant_proc(tmp_path, 302, fds={3: "socket:[558]"})            # no comm file
    env(monkeypatch, tmp_path, ss_tcp=None, ss_udp=None)          # ss isn't there
    found = by_port(check_network())
    assert sorted((f.severity, p, port) for (p, port), f in found.items()) == [
        ("high", "TCP", "3389"), ("info", "TCP", "8001"), ("medium", "TCP", "7777"), ("medium", "UDP", "69")]
    rdp = found[("TCP", "3389")]
    assert rdp.title == "Remote desktop (xrdp) on port 3389"
    assert rdp.details["pid"] == "300" and rdp.details["exe"] == "/usr/sbin/xrdp" and rdp.details["uid"] == 115
    assert found[("TCP", "8001")].details["programs"] == ["?"]
    assert "belongs to user root" in found[("TCP", "7777")].description


def test_proc_net_half_readable_still_counts(monkeypatch, tmp_path):
    plant_proc_net(tmp_path, tcp=None, tcp6=[row("00000000000000000000000000000000:1E62", "0" * 32 + ":0000", "0A",
                                                  0, "600")], udp=None, udp6=None)
    env(monkeypatch, tmp_path, ss_tcp=None, ss_udp=None)
    findings = check_network()
    assert sorted((f.severity, f.title) for f in findings) == [
        ("medium", "Listening ports not checked (UDP)"), ("medium", "Unexpected listening port: 7778")]
    assert "ss and /proc/net didn't work" in [f for f in findings if f.details.get("not_checked")][0].description


def test_no_proc_folder_at_all(monkeypatch, tmp_path):
    plant_proc_net(tmp_path, tcp=[row("00000000:1E61", "00000000:0000", "0A", 0, "556")], udp=None, tcp6=None,
                   udp6=None)
    monkeypatch.setattr(listeners.os, "listdir", lambda p: (_ for _ in ()).throw(OSError("no")))
    assert listeners._inode_owners({"556"}) == {}


def test_a_deleted_binary_still_names_its_program(monkeypatch, tmp_path):
    plant_proc(tmp_path, 60, exe="/usr/sbin/xrdp (deleted)")
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 2 *:3389 *:* users:(("x",pid=60,fd=11)) uid:115 ino:12 sk:7 <->'))
    f = one(check_network())
    assert (f.severity, f.title, f.details["identified_by"]) == ("high", "Remote desktop (xrdp) on port 3389",
                                                                  "program")
    assert f.details["exe"] == "/usr/sbin/xrdp (deleted)"


# ── Naming ──

def test_long_names_cut_to_15_characters_still_match():
    assert listeners._lookup(listeners.REMOTE_PROGRAMS, ["vncserver-x11-c"])[1] == "RealVNC"
    assert listeners._lookup(listeners.REMOTE_PROGRAMS, ["vncserver-x11-"]) is None   # 14: not a cut name
    assert listeners._lookup(listeners.REMOTE_PROGRAMS, ["TeamViewer"])[1] == "TeamViewer"
    assert listeners._lookup(listeners.SERVICE_PROGRAMS, ["sshd"]) is None
    assert listeners._lookup(listeners.REMOTE_PROGRAMS, ["sshd-session"]) is None


@pytest.mark.parametrize("cgroup,label,how", [
    ("/system.slice/xrdp.service", "remote desktop (xrdp)", "unit"),
    ("/system.slice/system-vncserver.slice/vncserver@:1.service", "remote desktop (Xvnc)", "unit"),
    ("/system.slice/ssh.socket", "SSH server (sshd)", "unit"),
    ("/system.slice/cups.service", "printing (CUPS)", "unit"),
    ("/system.slice/docker.service", "Docker", "unit"),
    ("/system.slice/postgresql@16-main.service", "PostgreSQL", "unit"),
    ("/system.slice/mystery.service", "", ""),
    ("/system.slice/xrdp.slice", "", ""),
])
def test_named_by_systemd_unit(cgroup, label, how):
    s = listeners._sock("TCP", "0.0.0.0", "7000", "l", uid=0, cgroup=cgroup)
    ident = listeners.identify([s], "TCP", "7000", set(), set())
    assert (ident["label"], ident["how"]) == (label, how)


def test_unit_parts():
    assert listeners._unit("/system.slice/cups.service") == "cups.service"
    assert listeners._unit("/system.slice/ssh.socket/") == "ssh.socket"
    assert listeners._unit("/system.slice/docker-0123.scope") == "docker-0123.scope"
    assert listeners._unit("/user.slice") == ""
    assert listeners._unit("") == ""


def test_service_naming_and_port_hints(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 1 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=70,fd=5)) uid:120 ino:1 sk:1 <->',
        'LISTEN 0 1 127.0.0.1:5434 0.0.0.0:* ino:2 sk:2 cgroup:/system.slice/docker.service <->',
        'LISTEN 0 1 127.0.0.1:5433 0.0.0.0:* ino:3 sk:3 <->',
        'LISTEN 0 1 127.0.0.1:4222 0.0.0.0:* users:(("ssh",pid=71,fd=4)) uid:1000 ino:4 sk:4 <->',
        'LISTEN 0 1 0.0.0.0:3389 0.0.0.0:* users:(("python3",pid=72,fd=3)) uid:1000 ino:5 sk:5 <->',
        'LISTEN 0 1 0.0.0.0:9999 0.0.0.0:* users:(("python3",pid=73,fd=3)) uid:1000 ino:6 sk:6 <->',
        'LISTEN 0 1 0.0.0.0:6379 0.0.0.0:* users:(("python3",pid=74,fd=3)) uid:1000 ino:9 sk:9 <->',
        'LISTEN 0 1 127.0.0.1:631 0.0.0.0:* ino:7 sk:7 cgroup:/system.slice/cups.service <->',
        'LISTEN 0 1 127.0.0.53%lo:53 0.0.0.0:* uid:991 ino:8 sk:8 cgroup:/system.slice/systemd-resolved.service <->'))
    found = by_port(no_crash(check_network))   # visible programs Sereno can't name (9999) mustn't stop the check
    dns = found[("TCP", "53")]
    assert dns.title == "DNS resolver (systemd-resolved) on port 53 (this machine only)"
    assert "usual port" not in dns.description
    pg = found[("TCP", "5432")]
    assert (pg.severity, pg.title) == ("medium", "PostgreSQL on port 5432")
    assert "Named by its program." in pg.description and "usual port" not in pg.description
    assert pg.remediation.startswith("If you know PostgreSQL and run it on purpose, add 5432 to expected.json.")
    docker = found[("TCP", "5434")]
    assert (docker.severity, docker.title) == ("info", "Docker on port 5434 (this machine only)")
    assert "Named by its systemd unit. Port 5434 is the usual port for PostgreSQL." in docker.description
    guess = found[("TCP", "5433")]
    assert guess.title == "Likely PostgreSQL on port 5433 (this machine only)"
    assert guess.remediation.startswith("To see which program it is: `sudo ss -ltnup 'sport = :5433'`.")
    tunnel = found[("TCP", "4222")]
    assert tunnel.title == "SSH port forward (ssh) on port 4222 (this machine only)"
    assert "Port 4222 is the usual port for NATS." in tunnel.description
    py = found[("TCP", "3389")]
    assert (py.severity, py.title) == ("medium", "Unexpected listening port: 3389")
    assert "Port 3389 is the usual port for remote desktop (RDP)." in py.description
    assert found[("TCP", "9999")].description.count("Port 9999") == 0
    assert found[("TCP", "9999")].remediation.startswith("Check what's using port 9999.")   # the program is visible
    redis = found[("TCP", "6379")]
    assert (redis.severity, redis.title) == ("medium", "Unexpected listening port: 6379")
    assert "Port 6379 is the usual port for Redis." in redis.description
    cups = found[("TCP", "631")]
    assert cups.title == "Printing (CUPS) on port 631 (this machine only)"
    assert "To see which program" not in cups.remediation
    assert "usual port" not in cups.description               # the name already says it


def test_a_launcher_holding_the_socket_is_named_by_port(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss(
        'LISTEN 0 1 *:3389 *:* users:(("systemd",pid=1,fd=50)) ino:8 sk:8 cgroup:/system.slice/rdp.socket <->'))
    f = one(check_network())
    assert (f.severity, f.title) == ("high", "Likely remote desktop (RDP) on port 3389")
    assert "Program: systemd (pid 1), user root." in f.description
    assert "`sudo systemctl disable --now xrdp`" in f.remediation and "grdctl --system rdp disable" in f.remediation


# ── Tailscale ──

def test_tailscale_needs_both_the_address_and_the_listed_port(monkeypatch, tmp_path):
    other = json.dumps({"Self": {"TailscaleIPs": ["100.80.54.90"], "PeerAPIURL": ["http://100.80.54.90:1"]}})
    unlisted_ip = json.dumps({"Self": {"TailscaleIPs": ["100.99.0.1"],
                                       "PeerAPIURL": ["http://100.80.54.90:56893"]}})
    for planted, where in ((other, "machines on your Tailscale network"), (unlisted_ip, "other machines")):
        env(monkeypatch, tmp_path, tailscale=planted, ss_tcp=ss('LISTEN 0 4096 100.80.54.90:56893 0.0.0.0:*'))
        f = one(check_network())
        assert (f.severity, f.title) == ("medium", "Unexpected listening port: 56893"), planted
        assert "reachable from %s" % where in f.description


def test_without_tailscale_the_rule_is_skipped_quietly(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 4096 100.80.54.90:56893 0.0.0.0:*'))
    f = one(check_network())
    assert (f.severity, f.title) == ("medium", "Unexpected listening port: 56893")
    assert "reachable from other machines" in f.description


def test_tailscale_is_asked_only_when_a_socket_is_on_a_tailscale_address(monkeypatch, tmp_path):
    calls = env(monkeypatch, tmp_path, tailscale=TS_JSON, ss_tcp=ss('LISTEN 0 1 0.0.0.0:7000 0.0.0.0:*',
                                                                    'LISTEN 0 1 100.128.0.1:7001 0.0.0.0:*',
                                                                    'LISTEN 0 1 *:7002 *:*'))
    check_network()
    assert not [c for c in calls if c[0][0] == "tailscale"]
    calls = env(monkeypatch, tmp_path, tailscale=TS_JSON, ss_tcp=ss('LISTEN 0 1 [fd7a:115c:a1e0::1]:7000 [::]:*'))
    check_network()
    assert len([c for c in calls if c[0][0] == "tailscale"]) == 1


def test_tailscaled_by_unit_or_program_needs_root(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 1 100.80.54.90:41000 0.0.0.0:* ino:1 sk:1 cgroup:/system.slice/tailscaled.service <->',
        'LISTEN 0 1 0.0.0.0:1055 0.0.0.0:* ino:2 sk:2 cgroup:/system.slice/tailscaled.service <->',
        'LISTEN 0 1 100.80.54.90:41001 0.0.0.0:* uid:1000 ino:3 sk:3 '
        'cgroup:/user.slice/user-1000.slice/user@1000.service/app.slice/tailscaled.service <->',
        'LISTEN 0 1 100.80.54.90:41002 0.0.0.0:* users:(("tailscaled",pid=80,fd=3)) uid:1000 ino:4 sk:4 <->',
        'LISTEN 0 1 100.80.54.90:41003 0.0.0.0:* uid:5 ino:5 sk:5 cgroup:/system.slice/tailscaled.service <->'))
    found = by_port(check_network())
    own = found[("TCP", "41000")]
    assert (own.severity, own.title) == ("info", "Tailscale (tailscaled) on port 41000")
    assert "Identified by its systemd unit, tailscaled.service, running as root." in own.description
    assert "reachable from machines on your Tailscale network" in own.description
    proxy = found[("TCP", "1055")]
    assert (proxy.severity, proxy.title) == ("medium", "Tailscale (tailscaled) on port 1055")
    assert "--socks5-server" in proxy.remediation and "add 1055 to expected.json" in proxy.remediation
    assert found[("TCP", "41001")].severity == "medium"   # a user's own unit named tailscaled
    fake = found[("TCP", "41002")]                          # a user's own program named tailscaled
    assert (fake.severity, fake.details["identified_by"]) == ("medium", "program")
    assert found[("TCP", "41003")].severity == "medium"   # tailscaled's unit, but not root


def test_tailscaled_by_program_as_root(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss(
        'LISTEN 0 1 100.80.54.90:41000 0.0.0.0:* users:(("tailscaled",pid=80,fd=3)) ino:4 sk:4 <->'))
    f = one(check_network())
    assert (f.severity, f.title) == ("info", "Tailscale (tailscaled) on port 41000")
    assert "Identified by its program, tailscaled, running as root." in f.description


def test_tailscale_status_parsing(monkeypatch):
    seen = []

    def run(cmd, timeout=30):
        seen.append(cmd[0])
        if cmd[0] == "tailscale":
            return "", -1
        return json.dumps({"Self": {"TailscaleIPs": ["100.1.2.3", "FD7A:115C:A1E0::0001"],
                                    "PeerAPIURL": ["http://100.1.2.3:4000", "http://[fd7a:115c:a1e0::1]:4001",
                                                   "garbage", "http://100.1.2.3:notaport"]}}), 0
    ips, api = listeners.tailnet(run, macos=True)
    assert ips == {"100.1.2.3", "fd7a:115c:a1e0::1"}
    assert api == {("100.1.2.3", "4000"), ("fd7a:115c:a1e0::1", "4001")}
    assert seen == ["tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"]
    assert listeners.tailnet(lambda cmd, timeout=30: ("not json", 0), macos=False) == (set(), set())
    assert listeners.tailnet(lambda cmd, timeout=30: ('{"Self": null}', 0), macos=False) == (set(), set())
    assert listeners.tailnet(lambda cmd, timeout=30: ("[1]", 0), macos=False) == (set(), set())


# ── What's reported ──

def test_common_ports_and_ssh(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 1 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=90,fd=3)) uid:1000 ino:1 sk:1 <->',
        'LISTEN 0 1 0.0.0.0:80 0.0.0.0:* ino:2 sk:2 <->',
        'LISTEN 0 1 [::]:22 [::]:* ino:3 sk:3 cgroup:/system.slice/ssh.socket <->',
        'LISTEN 0 1 0.0.0.0:443 0.0.0.0:* users:(("xrdp",pid=91,fd=3)) uid:115 ino:4 sk:4 <->',
        'LISTEN 0 1 0.0.0.0:2222 0.0.0.0:* users:(("dropbear",pid=92,fd=3)) uid:1000 ino:5 sk:5 <->',
        'LISTEN 0 1 0.0.0.0:2223 0.0.0.0:* users:(("sshd-session",pid=93,fd=3)) uid:1000 ino:6 sk:6 <->'))
    found = by_port(check_network())
    assert sorted(found) == [("TCP", "2222"), ("TCP", "2223"), ("TCP", "443")]
    assert found[("TCP", "443")].severity == "high"       # a remote desktop on 443 isn't a web server
    ssh = found[("TCP", "2222")]
    assert (ssh.severity, ssh.title) == ("high", "SSH server (dropbear) on port 2222")
    assert ssh.remediation.startswith("SSH on port 22 isn't reported. If you moved SSH to port 2222 on purpose, "
                                      "add 2222 to expected.json.")
    assert "it stays listed, as info" not in ssh.remediation
    assert "`sudo ss -ltnp 'sport = :2222'`" in ssh.remediation
    tunnel = found[("TCP", "2223")]
    assert (tunnel.severity, tunnel.title) == ("medium", "SSH reverse tunnel (sshd-session) on port 2223")


@pytest.mark.parametrize("line,reported", [
    ('UNCONN 0 0 0.0.0.0:3389 0.0.0.0:* ino:1 sk:1 <->', ("high", "Likely remote desktop (RDP) on port 3389 (UDP)")),
    ('UNCONN 0 0 0.0.0.0:3390 0.0.0.0:* ino:1 sk:1 <->', None),                 # RDP's UDP port is 3389 only
    ('UNCONN 0 0 0.0.0.0:21116 0.0.0.0:* users:(("rustdesk",pid=5,fd=9)) uid:1000 ino:1 sk:1 <->',
     ("high", "Remote desktop (RustDesk) on port 21116 (UDP)")),
    ('UNCONN 0 0 0.0.0.0:40000 0.0.0.0:* users:(("rustdesk",pid=5,fd=9)) uid:1000 ino:1 sk:1 <->', None),
    ('UNCONN 0 0 127.0.0.1:3389 0.0.0.0:* ino:1 sk:1 <->', None),               # UDP this machine only
    ('UNCONN 0 0 0.0.0.0:41641 0.0.0.0:* ino:1 sk:1 <->', None),
    ('UNCONN 0 0 0.0.0.0:123 0.0.0.0:* ino:1 sk:1 <->', None),
    ('UNCONN 0 0 0.0.0.0:1024 0.0.0.0:* ino:1 sk:1 <->', ("medium", "Unexpected listening port: 1024 (UDP)")),
    ('UNCONN 0 0 0.0.0.0:1025 0.0.0.0:* ino:1 sk:1 <->', None),
    ('UNCONN 0 0 0.0.0.0:53 0.0.0.0:* ino:1 sk:1 <->', ("medium", "Likely DNS on port 53 (UDP)")),
])
def test_udp_rules(monkeypatch, tmp_path, line, reported):
    env(monkeypatch, tmp_path, ss_udp=ss(line))
    findings = check_network()
    assert [(f.severity, f.title) for f in findings] == ([reported] if reported else [])


@pytest.mark.parametrize("port,title", [
    ("3388", "Unexpected listening port: 3388"), ("3389", "Likely remote desktop (RDP) on port 3389"),
    ("3390", "Likely remote desktop (RDP) on port 3390"), ("3391", "Unexpected listening port: 3391"),
    ("5899", "Unexpected listening port: 5899"), ("5900", "Likely remote desktop (VNC) on port 5900"),
    ("5910", "Likely remote desktop (VNC) on port 5910"), ("5911", "Unexpected listening port: 5911"),
    ("4000", "Likely remote desktop (NoMachine) on port 4000"), ("5938", "Likely remote desktop (TeamViewer) on port 5938"),
    ("21115", "Likely remote desktop (RustDesk) on port 21115"),
    ("21119", "Likely remote desktop (RustDesk) on port 21119"), ("21120", "Unexpected listening port: 21120"),
    ("3283", "Likely remote management (Apple Remote Desktop) on port 3283"),
])
def test_remote_ports_by_range(monkeypatch, tmp_path, port, title):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 1 0.0.0.0:%s 0.0.0.0:* ino:1 sk:1 <->' % port))
    f = one(check_network())
    assert f.title == title
    assert f.severity == ("high" if title.startswith("Likely") else "medium")


def test_grouping_one_finding_per_port(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 1 0.0.0.0:7000 0.0.0.0:*', 'LISTEN 0 1 [::]:7000 [::]:*',
                                         'LISTEN 0 1 127.0.0.1:7001 0.0.0.0:*', 'LISTEN 0 1 192.168.1.5:7001 0.0.0.0:*'),
        ss_udp=ss('UNCONN 0 0 0.0.0.0:7000 0.0.0.0:*'))
    findings = check_network()
    assert [(f.details["port"], f.severity) for f in findings] == [("7000", "medium"), ("7001", "medium")]
    assert findings[0].details["hosts"] == ["0.0.0.0", "[::]"]
    assert "(bound to 127.0.0.1, 192.168.1.5)" in findings[1].description


def test_who_owns_what(monkeypatch, tmp_path):
    lines = ('LISTEN 0 1 0.0.0.0:7000 0.0.0.0:* uid:33 ino:2 sk:2 <->',
             'LISTEN 0 1 127.0.0.1:7000 0.0.0.0:* users:(("node",pid=5,fd=3)) uid:1000 ino:1 sk:1 <->')
    env(monkeypatch, tmp_path, ss_tcp=ss(*lines))
    f = one(check_network())
    assert "Program: node (pid 5), user " in f.description
    assert "Another socket on this port: owner not visible without sudo." in f.description
    assert f.details["owner_visible"] is False and f.details["programs"] == ["node"]
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss(*lines))
    f = one(check_network())
    assert "No program Sereno can see holds one socket on this port, even running as root: it may be the kernel's" \
        in f.description
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss('LISTEN 0 1 0.0.0.0:7002 0.0.0.0:* ino:2 sk:2 <->'))
    f = one(check_network())
    # Root sees every program, but not from inside a container or a user namespace: no flat "it's the kernel's"
    assert ("No program Sereno can see holds it, even running as root: it may be the kernel's (WireGuard and NFS work "
            "this way), or a program outside the container or namespace Sereno runs in. The system shows it belongs "
            "to user root.") in f.description
    assert "it's the kernel's" not in f.description
    assert f.remediation.startswith("If Sereno ran inside a container or a user namespace, run "
                                    "`sudo ss -ltnup 'sport = :7002'` on the host to see the program. Check what's "
                                    "using port 7002.")
    assert f.details["owner_visible"] is False
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 1 0.0.0.0:7003 0.0.0.0:*'))
    f = one(check_network())
    assert f.description.split(" Line:")[0].endswith("Sereno can't see which program this is: owner not visible "
                                                     "without sudo.")


def test_users_and_uids():
    assert listeners._user(0) == "root"
    assert listeners._user(3999999999) == "uid 3999999999"
    assert listeners._uid_of("root") == 0
    assert listeners._uid_of("501") == 501
    assert listeners._uid_of("no-such-user-here") is None


def test_the_line_is_clipped_with_a_mark():
    assert listeners._clip("a   b") == "a b"
    long = "x" * 200
    assert listeners._clip(long) == "x" * 157 + "..."
    assert listeners._clip("y" * 160) == "y" * 160


def test_remediation_fills_display_and_mode(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 1 0.0.0.0:5905 0.0.0.0:* users:(("gnome-remote-de",pid=5,fd=3)) uid:1000 ino:1 sk:1 <->',
        'LISTEN 0 1 0.0.0.0:6001 0.0.0.0:* users:(("Xtigervnc",pid=6,fd=3)) uid:1000 ino:2 sk:2 <->',
        'LISTEN 0 1 0.0.0.0:5999 0.0.0.0:* users:(("Xvnc",pid=7,fd=3)) uid:1000 ino:3 sk:3 <->'))
    found = by_port(check_network())
    assert "`grdctl vnc disable`" in found[("TCP", "5905")].remediation
    assert "`vncserver -kill :N`" in found[("TCP", "6001")].remediation
    assert "`vncserver -kill :99`" in found[("TCP", "5999")].remediation
    assert all(f.severity == "high" for f in found.values())


def test_a_windows_machine_says_nothing_as_documented(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 1 0.0.0.0:7000 0.0.0.0:*'))
    monkeypatch.setattr(scanner, "_is_linux", lambda: False)
    assert check_network() == []


def test_a_visible_program_outranks_its_unit(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 1 0.0.0.0:7000 0.0.0.0:* users:(("python3",pid=5,fd=3)) uid:1000 ino:1 sk:1 '
        'cgroup:/system.slice/xrdp.service <->',
        'LISTEN 0 1 0.0.0.0:7001 0.0.0.0:* users:(("python3",pid=6,fd=3)) uid:1000 ino:2 sk:2 '
        'cgroup:/system.slice/cups.service <->'))
    found = by_port(check_network())
    assert [(f.severity, f.title) for f in found.values()] == [("medium", "Unexpected listening port: 7000"),
                                                               ("medium", "Unexpected listening port: 7001")]


# ── Malformed input, spoofing and the edges mutation testing found ──

def no_crash(fn, *args):
    """A guard against bad input has one job, not raising; this says so as an assertion."""
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001
        pytest.fail("%s raised on malformed input: %r" % (fn.__name__, e))


def test_malformed_lines_are_skipped_not_fatal(monkeypatch, tmp_path):
    plant_proc_net(tmp_path, tcp=["short line", row("00000000:1E61", "00000000:0000", "0A", 0, "556")],
                   tcp6=None, udp=None, udp6=None)
    monkeypatch.setattr(listeners, "PROC", tmp_path / "proc")
    rows = no_crash(listeners.proc_sockets, "TCP")
    assert [(r["host"], r["port"], r["uid"]) for r in rows] == [("0.0.0.0", "7777", 0)]
    lsof = "\n".join([LSOF_HDR, "weird TCP", "TCP *:1", "x 1 m 3u IPv4 0x1 0t0 TCP *:7000 (LISTEN)"])
    assert [(r["host"], r["port"]) for r in no_crash(listeners.parse_lsof, lsof, "TCP")] == [("*", "7000")]


def test_proc_owners_map_only_our_sockets_and_the_parent_wins(monkeypatch, tmp_path):
    plant_proc(tmp_path, 300, comm="nginx", fds={3: "socket:[555]", 4: "socket:[999]", 5: "/tmp/x/socket:[556]"})
    plant_proc(tmp_path, 1200, comm="nginx-worker", fds={3: "socket:[555]"})
    plant_proc(tmp_path, 41, comm="decoy", fds={7: "/home/me/socket:[556]"})
    monkeypatch.setattr(listeners, "PROC", tmp_path / "proc")
    real = os.listdir
    # The directory's own order is the filesystem's (ext4 hashes names); hand it over child first, as it may come
    monkeypatch.setattr(listeners.os, "listdir",
                        lambda p: ["1200", "net", "41", "300"] if p == str(tmp_path / "proc") else real(p))
    assert listeners._inode_owners({"555", "556"}) == {"555": ("300", "nginx")}


def test_a_readable_but_empty_proc_listing_is_checked(monkeypatch, tmp_path):
    plant_proc_net(tmp_path, tcp=[row("0100007F:1F90", "0100007F:A2A9", "01", 1000, "557")], tcp6=[], udp=[],
                   udp6=[])
    env(monkeypatch, tmp_path, ss_tcp=None, ss_udp=None)
    assert check_network() == []


def test_a_failed_tailscale_answer_is_not_trusted(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, tailscale=(TS_JSON, 1), ss_tcp=ss('LISTEN 0 4096 100.80.54.90:56893 0.0.0.0:*'))
    f = one(check_network())
    assert (f.severity, f.title) == ("medium", "Unexpected listening port: 56893")


def test_peer_api_urls_are_normalised():
    out = json.dumps({"Self": {"TailscaleIPs": ["fd7a:115c:a1e0::1"],
                               "PeerAPIURL": ["http://[fd7a:115c:a1e0:0:0:0:0:1]:4001"]}})
    assert listeners.tailnet(lambda cmd, timeout=30: (out, 0), macos=False) == (
        {"fd7a:115c:a1e0::1"}, {("fd7a:115c:a1e0::1", "4001")})


def test_a_port_guess_never_unskips_80_or_443(monkeypatch, tmp_path):
    monkeypatch.setattr(listeners, "REMOTE_PORTS",
                        listeners.REMOTE_PORTS + (("TCP", 443, 443, "remote desktop", "Guess", "rdp"),))
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 1 0.0.0.0:443 0.0.0.0:* ino:1 sk:1 <->'))
    assert check_network() == []


def test_shared_sockets_name_each_program_once(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 1 0.0.0.0:8080 0.0.0.0:* users:(("nginx",pid=20,fd=6),("nginx",pid=19,fd=6)) uid:33 ino:5 sk:9 <->'))
    f = one(check_network())
    assert "Program: nginx (pid 20), user " in f.description
    assert f.check == "network"


def test_netstat_reads_only_its_own_protocol_and_real_addresses():
    mixed = "\n".join([NETSTAT_HDR, "tcp4 0 0 *.22 *.* LISTEN", "udp4 0 0 *.5353 *.*", "udp4 0 0 5354 *.*",
                       "udp4 0 0 192.168.1.5.500 1.2.3.4.500"])
    assert [(r["proto"], r["host"], r["port"]) for r in listeners.parse_netstat(mixed, "UDP")] == [
        ("UDP", "*", "5353")]
    assert [(r["proto"], r["port"]) for r in listeners.parse_netstat(mixed, "TCP")] == [("TCP", "22")]


def test_macos_names_with_spaces_and_root_tailscaled(monkeypatch, tmp_path):
    lsof_tcp = "\n".join([LSOF_HDR, "Google\\x20Chrome 900 m 30u IPv4 0x9 0t0 TCP 127.0.0.1:9222 (LISTEN)",
                          "tailscaled 77 root 5u IPv4 0x7 0t0 TCP 100.80.54.90:41000 (LISTEN)"])
    env(monkeypatch, tmp_path, mac=True, euid=0, lsof_tcp=lsof_tcp, lsof_udp=("", 1), netstat_tcp="",
        netstat_udp="")
    found = by_port(check_network())
    assert found[("TCP", "9222")].details["programs"] == ["Google Chrome"]
    ts = found[("TCP", "41000")]
    assert (ts.severity, ts.title, ts.details["uid"]) == ("info", "Tailscale (tailscaled) on port 41000", 0)
    # Without root, lsof lists only your own programs: a root "tailscaled" it shows can't be the real one
    env(monkeypatch, tmp_path, mac=True, lsof_tcp=lsof_tcp, lsof_udp=("", 1), netstat_tcp="", netstat_udp="")
    ts = by_port(check_network())[("TCP", "41000")]
    assert (ts.severity, ts.title) == ("medium", "Tailscale (tailscaled) on port 41000")
    assert "running as root" not in ts.description


def test_a_remote_desktop_named_by_its_unit(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 2 *:3389 *:* uid:115 ino:12 sk:7 cgroup:/system.slice/xrdp.service <->'))
    f = one(check_network())
    assert (f.severity, f.title, f.details["identified_by"]) == ("high", "Remote desktop (xrdp) on port 3389", "unit")
    assert f.remediation.startswith("Switch it off: `sudo systemctl disable --now xrdp xrdp-sesman`")


def test_only_the_machines_own_tailscaled_unit_counts(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 1 100.80.54.90:41000 0.0.0.0:* ino:1 sk:1 '
        'cgroup:/system.slice/docker-1.scope/system.slice/tailscaled.service <->'))
    f = one(check_network())   # a container's unit is named by whoever runs it: shown, but it names nothing
    assert (f.severity, f.title) == ("medium", "Unexpected listening port: 41000")
    assert "a systemd unit its owner named tailscaled.service" in f.description
    assert "running as root" not in f.description


def test_a_port_is_tailscales_only_if_every_socket_on_it_is(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, tailscale=TS_JSON, ss_tcp=ss('LISTEN 0 4096 100.80.54.90:56893 0.0.0.0:*',
                                                            'LISTEN 0 4096 192.168.1.5:56893 0.0.0.0:*'))
    f = one(check_network())
    assert (f.severity, f.title) == ("medium", "Unexpected listening port: 56893")
    assert "reachable from other machines" in f.description


# ── Review fixes, 2026-10-24: each test fails on an assertion without its fix ──

TS_ONLY_PEER = json.dumps({"Self": {"TailscaleIPs": ["100.80.54.90"], "PeerAPIURL": ["http://100.80.54.90:56893"]}})


@pytest.mark.parametrize("users", [
    '(("uid:0",pid=11,fd=3),("tailscaled",pid=12,fd=3))',     # a helper named "uid:0" shares the socket
    '(("tailscaled",pid=12,fd=3),("x uid:0 ",pid=11,fd=3))',   # a name with spaces makes "uid:0" its own word
    '(("ino:1 sk:1 ",pid=11,fd=3),("tailscaled",pid=12,fd=3))',
])
def test_a_program_name_cannot_pose_as_the_sockets_owner(monkeypatch, tmp_path, users):
    line = ('LISTEN 0 128 100.80.54.90:47123 0.0.0.0:* users:%s uid:1000 ino:34931130 sk:1 '
            'cgroup:/user.slice/user-1000.slice/session-2.scope <->' % users)
    s = one(listeners.parse_ss(line, "TCP"))
    assert s["uid"] == 1000 and s["cgroup"] == "/user.slice/user-1000.slice/session-2.scope"
    # Even run as root, where every program shows, the listener stays the user's, not root's tailscaled
    env(monkeypatch, tmp_path, euid=0, tailscale=TS_ONLY_PEER, ss_tcp=ss(line))
    f = one(check_network())
    assert f.severity == "medium" and f.details["uid"] == 1000
    assert "user root" not in f.description and "Nothing to do" not in f.remediation


def test_the_users_block_is_read_by_its_structure():
    rows = listeners.parse_ss("\n".join([
        # a name holding a fake pid: the real one is the last that ends within 15 characters
        'LISTEN 0 1 127.0.0.1:47124 0.0.0.0:* users:(("a",pid=1,x",pid=1176229,fd=3)) uid:1000 ino:2 sk:2 <->',
        # a 15-character name, `",pid=1,fd=2)),`, made of a fake entry and a fake end of the block
        'LISTEN 0 1 127.0.0.1:47125 0.0.0.0:* users:(("",pid=1,fd=2)),",pid=77,fd=3)) uid:1000 ino:3 sk:3 <->',
        # a cgroup folder (users may name their own) holding fake fields comes after the real ones
        'LISTEN 0 1 0.0.0.0:47126 0.0.0.0:* uid:1000 ino:4 sk:4 fwmark:0x1 cgroup:/user.slice/x uid:0 <->',
        # root's socket (no uid:) with the netid column first
        'tcp LISTEN 0 1 0.0.0.0:47127 0.0.0.0:* users:(("nginx",pid=20,fd=6),("nginx",pid=19,fd=6)) ino:5 sk:5 <->',
        # no -e fields after the block: owner unknown
        'LISTEN 0 1 0.0.0.0:47128 0.0.0.0:* users:(("srv",pid=30,fd=3))',
        # an empty name, then a name that starts like an entry's end: 16 characters on, it isn't the first's end
        'LISTEN 0 1 0.0.0.0:47130 0.0.0.0:* users:(("",pid=9,fd=3),("",pid=5,fd=5),(",pid=7,fd=4)) uid:1000 ino:6 '
        'sk:6 <->',
        # a cgroup folder named to hold a second cgroup: field
        'LISTEN 0 1 0.0.0.0:47131 0.0.0.0:* uid:1000 ino:7 sk:7 cgroup:/user.slice/x cgroup:/system.slice/a.service <->',
    ]), "TCP")
    assert [(r["port"], r["programs"], r["pid"], r["uid"], r["cgroup"]) for r in rows] == [
        ("47124", ['a",pid=1,x'], "1176229", 1000, ""),
        ("47125", ['",pid=1,fd=2)),'], "77", 1000, ""),
        ("47126", [], "", 1000, "/user.slice/x"),
        ("47127", ["nginx", "nginx"], "20", 0, ""),
        ("47128", ["srv"], "30", None, ""),
        ("47130", ["", '",pid=5,fd=5),('], "9", 1000, ""),
        ("47131", [], "", 1000, "/user.slice/x")]


@pytest.mark.parametrize("users", [
    '(("x",pid=5,fd=3)',                      # never closed
    '(("x",pid=5,fd=3)("y",pid=6,fd=4))',     # entries not separated
    '(("a name far longer than fifteen",pid=5,fd=3))',
    '(("x",pid=5,fd=3),("a name far longer than fifteen",pid=6,fd=4))',
])
def test_a_users_block_that_does_not_parse_trusts_nothing_after_it(users):
    line = 'LISTEN 0 1 0.0.0.0:47129 0.0.0.0:* users:%s ino:9 sk:9 cgroup:/system.slice/tailscaled.service <->' % users
    s = one(no_crash(listeners.parse_ss, line, "TCP"))
    assert (s["uid"], s["cgroup"], s["pid"]) == (None, "", "")


def test_a_known_system_unit_outranks_the_port_guess(monkeypatch, tmp_path):
    docker = 'LISTEN 0 4096 0.0.0.0:4000 0.0.0.0:* ino:20581 sk:1 cgroup:/system.slice/docker.service <->'
    env(monkeypatch, tmp_path, ss_tcp=ss(docker))
    f = one(check_network())
    assert (f.severity, f.title, f.details["identified_by"]) == ("medium", "Docker on port 4000", "unit")
    assert "Port 4000 is the usual port for remote desktop (NoMachine)." in f.description
    assert "nxserver" not in f.remediation
    # Another hidden socket on the port that no known unit explains: the port speaks for that one
    env(monkeypatch, tmp_path, ss_tcp=ss(docker, 'LISTEN 0 5 [::]:4000 [::]:* ino:7 sk:7 <->'))
    assert one(check_network()).title == "Likely remote desktop (NoMachine) on port 4000"
    # A unit a user named docker.service doesn't explain it either
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 5 0.0.0.0:4000 0.0.0.0:* uid:1001 ino:8 sk:8 '
                                         'cgroup:/user.slice/user-1001.slice/user@1001.service/app.slice/docker.service <->'))
    assert one(check_network()).severity == "high"


def plant_parent(tmp_path, pid, ppid, parent_comm, parent_uid, name="sshd"):
    for p, text in ((pid, "%s (%s) S %s 1 1 0 -1" % (pid, name, ppid)), (ppid, None)):
        d = tmp_path / "proc" / str(p)
        d.mkdir(parents=True, exist_ok=True)
        if text:
            (d / "stat").write_text(text)
    (tmp_path / "proc" / str(ppid) / "comm").write_text(parent_comm + "\n")
    (tmp_path / "proc" / str(ppid) / "status").write_text(
        "Name:\t%s\nPid:\t%s\nUid:\t%d\t%d\t%d\t%d\n" % (parent_comm, ppid, parent_uid, parent_uid, parent_uid,
                                                       parent_uid))


def test_an_sshd_login_holding_a_forwarded_port_is_a_tunnel_not_a_server(monkeypatch, tmp_path):
    plant_parent(tmp_path, 5555, 5000, "sshd", 0)      # forked by the SSH server, running as root
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("sshd",pid=5555,fd=9)) uid:1000 ino:3 sk:3 '
        'cgroup:/user.slice/user-1000.slice/session-7.scope <->',
        'LISTEN 0 128 127.0.0.1:9000 0.0.0.0:* users:(("sshd",pid=5555,fd=10)) uid:1000 ino:4 sk:4 <->'))
    found = by_port(check_network())
    tunnel = found[("TCP", "8080")]
    assert (tunnel.severity, tunnel.title) == ("medium", "SSH reverse tunnel (sshd) on port 8080")
    assert "holds the ports that login forwards with `ssh -R`" in tunnel.description
    assert tunnel.remediation.startswith("It closes when the SSH login that opened it ends")
    assert "a second SSH server" not in tunnel.remediation
    assert found[("TCP", "9000")].title == "SSH reverse tunnel (sshd) on port 9000 (this machine only)"


@pytest.mark.parametrize("parent_comm,parent_uid", [("bash", 1000), ("sshd", 1000), ("systemd", 0)])
def test_an_sshd_someone_started_stays_an_ssh_server(monkeypatch, tmp_path, parent_comm, parent_uid):
    plant_parent(tmp_path, 5555, 5000, parent_comm, parent_uid)
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=5555,fd=3)) '
                                         'uid:1000 ino:3 sk:3 <->'))
    f = one(check_network())
    assert (f.severity, f.title) == ("high", "SSH server (sshd) on port 2222")


def test_a_parent_is_read_from_stat_even_with_a_bracket_in_the_name(tmp_path, monkeypatch):
    monkeypatch.setattr(listeners, "PROC", tmp_path / "proc")
    plant_parent(tmp_path, 60, 50, "sshd", 0, name="a) b")
    assert listeners._parent("60") == ("sshd", 0)
    assert listeners._parent("61") is None             # gone, or not readable


def test_another_users_socket_in_the_ssh_unit_is_not_the_ssh_server(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 5 0.0.0.0:8000 0.0.0.0:* uid:1001 ino:4 sk:4 '
                                         'cgroup:/system.slice/ssh.service <->'))
    f = one(check_network())
    assert (f.severity, f.title) == ("medium", "Unexpected listening port: 8000")
    assert "systemd unit ssh.service" in f.description


@pytest.mark.parametrize("port,has,lacks", [
    ("5911", ["`grdctl vnc disable`", "undo: `grdctl vnc enable`"], ["`grdctl rdp disable`"]),
    ("3390", ["`grdctl rdp disable`"], ["`grdctl vnc disable`"]),
    ("5900", ["`grdctl vnc disable`"], ["`grdctl rdp disable`"]),
    ("5999", ["`grdctl vnc disable`"], ["`grdctl rdp disable`"]),
    ("7000", ["`grdctl rdp disable`, `grdctl vnc disable` (port 7000 doesn't say which of the two it serves)",
              "`grdctl rdp enable` or `grdctl vnc enable`, whichever it was,"], []),
])
def test_gnome_remote_desktop_off_switch_follows_the_port(monkeypatch, tmp_path, port, has, lacks):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 5 0.0.0.0:%s 0.0.0.0:* users:(("gnome-remote-de",pid=5,fd=3)) '
                                         'uid:1000 ino:5 sk:5 <->' % port))
    f = one(check_network())
    assert all(x in f.remediation for x in has), f.remediation
    assert not any(x in f.remediation for x in lacks), f.remediation
    assert "`sudo grdctl --system rdp disable`" in f.remediation   # the login screen's remote login speaks RDP


def test_macos_says_when_only_your_own_ports_were_listed(monkeypatch, tmp_path):
    lsof_tcp = "\n".join([LSOF_HDR, "x 1 m 3u IPv4 0x1 0t0 TCP *:7000 (LISTEN)"])
    env(monkeypatch, tmp_path, mac=True, lsof_tcp=lsof_tcp, lsof_udp=("", 1), netstat_tcp=("", 1), netstat_udp="")
    findings = check_network()
    partial = [f for f in findings if f.details.get("partial")]
    assert [(f.severity, f.title) for f in partial] == [("medium", "Listening ports partly checked (TCP)")]
    assert "only the TCP ports of your own programs" in partial[0].description
    assert partial[0].details["not_checked"] is True
    env(monkeypatch, tmp_path, mac=True, euid=0, lsof_tcp=lsof_tcp, lsof_udp=("", 1), netstat_tcp=("", 1),
        netstat_udp="")
    assert not [f for f in check_network() if f.details.get("not_checked")]   # as root, lsof lists them all


def test_a_socket_bound_to_the_loopback_device_is_this_machine_only(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 5 0.0.0.0%lo:8000 0.0.0.0:* users:(("python3",pid=5,fd=3)) '
                                         'uid:1000 ino:5 sk:5 <->'))
    f = one(check_network())
    assert (f.severity, f.title) == ("info", "Unexpected listening port: 8000 (this machine only)")


@pytest.mark.parametrize("uid,launcher,step", [
    ("uid:1000 ", "systemd", "To see which service it starts: `systemctl --user list-sockets --all`. "),
    ("", "systemd", "To see which service it starts: `systemctl list-sockets --all`. "),
    ("", "inetd", "To see which service it starts, look for port 7100 in inetd's settings. "),
])
def test_a_launchers_socket_is_not_a_known_owner(monkeypatch, tmp_path, uid, launcher, step):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 5 0.0.0.0:7100 0.0.0.0:* users:(("%s",pid=1500,fd=40)) %sino:7 '
                                         'sk:7 <->' % (launcher, uid)))
    f = one(check_network())
    assert f.details["owner_visible"] is False
    assert "%s holds it for a service it starts when a connection comes" % launcher in f.description
    assert f.remediation.startswith(step + "Check what's using port 7100.")
    assert "sudo ss" not in f.remediation


def test_the_details_describe_one_socket(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss(
        'LISTEN 0 5 0.0.0.0:7200 0.0.0.0:* ino:8 sk:8 cgroup:/system.slice/mystery.service <->',
        'LISTEN 0 5 [::]:7200 [::]:* users:(("python3",pid=77,fd=3)) uid:1000 ino:9 sk:9 <->'))
    f = one(check_network())
    d = f.details
    assert (d["programs"], d["pid"], d["uid"], d["unit"], d["host"]) == (["python3"], "77", 1000, "", "[::]")
    assert "python3" in d["line"] and "python3" in f.description.split("Line: ")[1]


def test_proc_owners_stop_when_every_socket_is_found(monkeypatch, tmp_path):
    plant_proc(tmp_path, 300, comm="a", fds={3: "socket:[555]"})
    plant_proc(tmp_path, 400, comm="b", fds={3: "socket:[556]"})
    monkeypatch.setattr(listeners, "PROC", tmp_path / "proc")
    real, listed = os.listdir, []
    monkeypatch.setattr(listeners.os, "listdir", lambda p: listed.append(p) or real(p))
    assert listeners._inode_owners(set()) == {} and listed == []
    assert listeners._inode_owners({"555"}) == {"555": ("300", "a")}
    assert str(tmp_path / "proc" / "400" / "fd") not in listed


@pytest.mark.parametrize("program,port,label,off", [
    ("Xtightvnc", "5901", "Remote desktop (TightVNC)", "`vncserver -kill :1`"),
    ("Xvnc4", "5902", "Remote desktop (Xvnc4)", "`vncserver -kill :2`"),
    ("Xvnc-core", "5903", "Remote desktop (RealVNC virtual desktop)", "`vncserver-virtual -kill :3`"),
    ("vncserver-virtu", "5904", "Remote desktop (RealVNC virtual desktop)", "vncserver-virtuald"),
    ("xpra", "14500", "Remote desktop (xpra)", "`xpra stop :N`"),
    ("sunshine", "47989", "Remote desktop (Sunshine)", "`systemctl --user disable --now sunshine`"),
    ("guacd", "4822", "Remote desktop gateway (Apache Guacamole)", "`sudo systemctl disable --now guacd`"),
])
def test_more_remote_desktops_by_program(monkeypatch, tmp_path, program, port, label, off):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 5 0.0.0.0:%s 0.0.0.0:* users:(("%s",pid=5,fd=3)) uid:1000 ino:10 '
                                         'sk:10 <->' % (port, program)))
    f = one(check_network())
    assert (f.severity, f.title) == ("high", "%s on port %s" % (label, port))
    assert off in f.remediation


def test_a_unit_a_user_named_does_not_name_a_service(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 5 0.0.0.0:7777 0.0.0.0:* uid:33 ino:11 sk:11 '
                                         'cgroup:/user.slice/user-33.slice/user@33.service/app.slice/cups.service <->'))
    f = one(check_network())
    assert (f.severity, f.title) == ("medium", "Unexpected listening port: 7777")
    assert "belongs to user www-data and a systemd unit its owner named cups.service." in f.description
    assert "printing" not in f.remediation
    # A name that raises the alarm may still come from such a unit
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 5 0.0.0.0:7778 0.0.0.0:* uid:33 ino:12 sk:12 '
                                         'cgroup:/user.slice/user-33.slice/user@33.service/app.slice/xrdp.service <->'))
    assert (one(check_network()).severity, one(check_network()).title) == ("high", "Remote desktop (xrdp) on port 7778")


@pytest.mark.parametrize("cgroup,unit", [
    ("/system.slice/cups.service", "cups.service"),
    ("/system.slice/system-postgresql.slice/postgresql@16-main.service", "postgresql@16-main.service"),
    ("/system.slice/docker-1.scope/system.slice/tailscaled.service", ""),
    ("/user.slice/user-33.slice/user@33.service/app.slice/cups.service", ""),
    ("/system.slice", ""), ("", ""), ("/machine.slice/x.service", ""),
])
def test_system_units(cgroup, unit):
    assert listeners._system_unit(cgroup) == unit


def test_macos_lsof_and_netstat_agree_on_ipv6_loopback(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, mac=True,
        lsof_tcp="\n".join([LSOF_HDR, "cupsd 9 m 5u IPv6 0x9 0t0 TCP [::1]:631 (LISTEN)"]), lsof_udp=("", 1),
        netstat_tcp="\n".join([NETSTAT_HDR, "tcp6 0 0 ::1.631 *.* LISTEN"]), netstat_udp="")
    f = one(check_network())
    assert f.details["owner_visible"] is True and "Another socket" not in f.description


def test_an_empty_ss_listing_falls_back_to_proc(monkeypatch, tmp_path):
    plant_proc_net(tmp_path, tcp=[row("00000000:1E61", "00000000:0000", "0A", 0, "556")], tcp6=[], udp=[], udp6=[])
    env(monkeypatch, tmp_path, ss_tcp="", ss_udp="")
    f = one(check_network())
    assert f.title == "Unexpected listening port: 7777"


def test_output_that_is_not_utf8_does_not_stop_the_check():
    import sys
    try:
        out, rc = scanner._run([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'cgroup:/x\\xffy')"])
    except UnicodeDecodeError as e:
        pytest.fail("a byte that isn't UTF-8 stopped the command: %r" % e)
    assert (out, rc) == ("cgroup:/x�y", 0)


def test_the_ssh_off_switch_uses_the_systems_own_tool(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, mac=True, lsof_tcp="\n".join([LSOF_HDR, "dropbear 7 m 3u IPv4 0x1 0t0 TCP *:2222 (LISTEN)"]),
        lsof_udp=("", 1), netstat_tcp="", netstat_udp="")
    f = one(check_network())
    assert "`sudo lsof -nP -i :2222`" in f.remediation and "ss -ltnp" not in f.remediation


def test_a_port_shared_by_a_launcher_and_its_program_is_told_by_the_program(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss(
        'LISTEN 0 1 [::]:3389 [::]:* users:(("systemd",pid=1,fd=50)) ino:8 sk:8 cgroup:/system.slice/xrdp.socket <->',
        'LISTEN 0 1 0.0.0.0:3389 0.0.0.0:* users:(("xrdp",pid=7,fd=11)) uid:115 ino:12 sk:7 <->'))
    f = one(check_network())
    assert (f.details["pid"], f.details["programs"], f.details["uid"]) == ("7", ["xrdp"], 115)
    assert "Program: systemd, xrdp (pid 7), user " in f.description
    assert "systemd holds one socket for a service it starts" in f.description


def test_only_an_ssh_servers_child_is_a_login(monkeypatch, tmp_path):
    plant_parent(tmp_path, 60, 50, "xrdp", 0, name="xrdp")   # xrdp forks per session too: still remote desktop
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 1 0.0.0.0:3390 0.0.0.0:* users:(("xrdp",pid=60,fd=3)) uid:115 '
                                         'ino:3 sk:3 <->'))
    assert (one(check_network()).severity, one(check_network()).title) == ("high", "Remote desktop (xrdp) on port 3390")


def test_the_parents_effective_user_decides_root(tmp_path, monkeypatch):
    monkeypatch.setattr(listeners, "PROC", tmp_path / "proc")
    plant_parent(tmp_path, 60, 50, "sshd", 0)
    (tmp_path / "proc" / "50" / "status").write_text("Name:\tsshd\nUid:\t1000\t0\t0\t0\n")   # real 1000, effective 0
    assert listeners._parent("60") == ("sshd", 0)


# ── Verify round 1 (2026-10-25) ──

def network_scan():
    """The network check as a scan runs it: a crash comes back as "Check couldn't run", which fails here as an
    assertion, not an error."""
    result = scanner.SentinelScanner(checks=["network"]).scan()
    crashed = [f.description for f in result.findings if f.title.startswith("Check couldn't run")]
    assert not crashed, crashed
    return result


def test_a_parent_name_that_is_not_utf8_does_not_stop_the_check(monkeypatch, tmp_path):
    plant_parent(tmp_path, 5555, 5000, "x", 1000)
    (tmp_path / "proc" / "5000" / "comm").write_bytes(b"\xff\xfeparent\n")   # a name set with prctl, any bytes
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=5555,fd=3)) '
                                         'uid:1000 ino:3 sk:3 <->'))
    f = one(network_scan().findings)
    assert (f.severity, f.title) == ("high", "SSH server (sshd) on port 2222")
    assert listeners._parent("5555") == ("��parent", 1000)


def test_a_process_whose_own_name_is_not_utf8_but_whose_binary_is_sshd(monkeypatch, tmp_path):
    plant_parent(tmp_path, 5555, 5000, "bash", 1000)
    (tmp_path / "proc" / "5555" / "stat").write_bytes(b"5555 (\xff) S 5000 1 1 0 -1")
    os.symlink("/usr/sbin/sshd", str(tmp_path / "proc" / "5555" / "exe"))
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("�",pid=5555,fd=3)) '
                                         'uid:1000 ino:3 sk:3 <->'))
    f = one(network_scan().findings)
    assert (f.severity, f.title) == ("high", "SSH server (sshd) on port 2222")


def test_proc_owner_names_that_are_not_utf8_do_not_stop_the_fallback(monkeypatch, tmp_path):
    plant_proc_net(tmp_path, tcp=[row("00000000:1E61", "00000000:0000", "0A", 1000, "556")], tcp6=[], udp=[], udp6=[])
    plant_proc(tmp_path, 300, fds={3: "socket:[556]"})
    (tmp_path / "proc" / "300" / "comm").write_bytes(b"\xffx\n")
    env(monkeypatch, tmp_path, ss_tcp=None, ss_udp=None)
    f = one(network_scan().findings)
    assert (f.details["programs"], f.details["pid"]) == (["�x"], "300")


def test_a_binary_path_that_is_not_utf8_can_be_printed(monkeypatch, tmp_path):
    plant_proc(tmp_path, 4242)
    os.symlink(b"/opt/r\xffd/rustdesk", os.fsencode(str(tmp_path / "proc" / "4242" / "exe")))
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 5 0.0.0.0:21118 0.0.0.0:* users:(("rustdesk",pid=4242,fd=3)) '
                                         'uid:1000 ino:5 sk:5 <->'))
    result = network_scan()
    f = one(result.findings)
    assert f.details["exe"] == "/opt/r�d/rustdesk"
    assert "/opt/r�d/rustdesk" in f.description
    try:
        result.human_report().encode("utf-8")
    except UnicodeEncodeError as e:
        pytest.fail("the report can't be printed: %r" % e)


def plant_chain(tmp_path, chain):
    """A process and its ancestors, each (pid, program, effective user id, session id); each one's parent is the
    next, and the last one's is 0 (none). The process group, the field before the session, is planted as 4321 so a
    reader of the wrong field is caught."""
    for i, (pid, comm, euid, sid) in enumerate(chain):
        ppid = chain[i + 1][0] if i + 1 < len(chain) else 0
        d = tmp_path / "proc" / str(pid)
        d.mkdir(parents=True, exist_ok=True)
        (d / "stat").write_text("%s (%s) S %s 4321 %s 0 -1" % (pid, comm, ppid, sid))
        (d / "comm").write_text(comm + "\n")
        (d / "status").write_text("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\n" % (comm, euid, euid, euid, euid))


# OpenSSH 9.6p1: the listening server (900, under systemd) forks a per-connection process (5000) that leads its own
# session (sshd.c:2109). For a login as another user, that process forks the login's own process (5555, same session;
# sshd.c:551); for a root login it serves the login itself (sshd.c:541). A login's command gets a new session
# (session.c:462).
LISTENER = [(900, "sshd", 0, 900), (1, "systemd", 0, 1)]
ROOT_LOGIN = [(5000, "sshd", 0, 5000)] + LISTENER


def test_a_root_logins_forwarded_port_is_a_tunnel(monkeypatch, tmp_path):
    plant_chain(tmp_path, ROOT_LOGIN)
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss('LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("sshd",pid=5000,fd=9)) '
                                                 'ino:3 sk:3 cgroup:/user.slice/user-0.slice/session-9.scope <->'))
    f = one(network_scan().findings)
    assert (f.severity, f.title) == ("medium", "SSH reverse tunnel (sshd) on port 8080")


@pytest.mark.parametrize("uid,euid", [("", 0), ("uid:1000 ", 1000)])   # `sshd -D`, or `setpriv --reuid 1000 sshd -D`
def test_an_ssh_server_a_root_login_started_is_a_server(monkeypatch, tmp_path, uid, euid):
    plant_chain(tmp_path, [(6000, "sshd", euid, 6000)] + ROOT_LOGIN)
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss('LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=6000,fd=3)) '
                                                 '%sino:3 sk:3 cgroup:/user.slice/user-0.slice/session-9.scope <->'
                                                 % uid))
    f = one(network_scan().findings)
    assert (f.severity, f.title) == ("high", "SSH server (sshd) on port 2222")
    assert "a second SSH server is running" in f.remediation
    assert "It closes when the SSH login" not in f.remediation


def test_a_users_login_process_is_a_tunnel_in_its_parents_session(monkeypatch, tmp_path):
    plant_chain(tmp_path, [(5555, "sshd", 1000, 5000)] + ROOT_LOGIN)
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("sshd",pid=5555,fd=9)) '
                                         'uid:1000 ino:3 sk:3 <->'))
    assert one(network_scan().findings).title == "SSH reverse tunnel (sshd) on port 8080"


@pytest.mark.parametrize("chain,gone", [
    ([(50, "sshd", 0, 50), (1, "sshd", 0, 1)], None),   # sshd is a container's pid 1: its parent, 0, isn't there
    (ROOT_LOGIN, 900),                                   # the listening server's stat is gone (it just exited)
])
def test_a_root_logins_process_with_no_grandparent_to_read_is_a_tunnel(monkeypatch, tmp_path, chain, gone):
    plant_chain(tmp_path, chain)
    if gone:
        (tmp_path / "proc" / str(gone) / "stat").unlink()
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss('LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("sshd",pid=%s,fd=9)) '
                                                 'ino:3 sk:3 <->' % chain[0][0]))
    assert one(network_scan().findings).title == "SSH reverse tunnel (sshd) on port 8080"


def test_long_proc_files_parse_in_linear_time(tmp_path, monkeypatch):
    import time
    monkeypatch.setattr(listeners, "PROC", tmp_path / "proc")
    plant_chain(tmp_path, [(60, "sshd", 1000, 50), (50, "sshd", 0, 50)])
    (tmp_path / "proc" / "60" / "stat").write_bytes(b"60 (" + b") \xff" * 60000 + b") S 50 50 50 0 -1")
    (tmp_path / "proc" / "50" / "status").write_bytes(      # lines that start like Uid: and never finish it
        b"Name:\t\xff\n" + b"Uid:" + b"\t" * 120000 + b"x\n" + (b"Uid:\t1" + b"\t" * 2000 + b"x\n") * 60
        + b"Uid:\t0\t0\t0\t0\n")
    t0 = time.perf_counter()
    assert listeners._stat("60") == ("50", "50")
    assert listeners._parent("60") == ("sshd", 0)
    assert time.perf_counter() - t0 < 1.0   # 0.06 s on Asdf; a parser quadratic in these sizes takes minutes


@pytest.mark.parametrize("names,step", [
    ({1000: "alice"}, "To see which service it starts, run `systemctl --user list-sockets --all` as alice (as root: "
                      "`systemctl --user -M alice@ list-sockets --all`). "),
    ({}, "To see which service it starts, run `systemctl --user list-sockets --all` as uid 1000. "),
])
def test_as_root_a_users_launcher_step_names_that_user(monkeypatch, tmp_path, names, step):
    monkeypatch.setattr(listeners, "_user", lambda uid: names.get(uid, "uid %s" % uid))
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss('LISTEN 0 5 0.0.0.0:7100 0.0.0.0:* users:(("systemd",pid=1500,fd=40)) '
                                                 'uid:1000 ino:7 sk:7 <->'))
    assert one(check_network()).remediation.startswith(step + "Check what's using port 7100.")


@pytest.mark.parametrize("fields,step", [
    ("ino:7 sk:7 ", "To see which service it starts: `systemctl list-sockets --all`. "),   # root's own: the system's
    ("", "To see which service it starts: `systemctl --user list-sockets --all`. "),       # no owner known (old ss)
])
def test_as_root_the_systems_launcher_and_an_unknown_owner(monkeypatch, tmp_path, fields, step):
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss('LISTEN 0 5 0.0.0.0:7100 0.0.0.0:* users:(("systemd",pid=1,fd=40)) '
                                                 '%s<->' % fields))
    assert one(check_network()).remediation.startswith(step + "Check what's using port 7100.")


@pytest.mark.parametrize("stat,status", [
    ("5555", None),                          # no name in ()
    ("5555 (sshd) S 5000", None),            # cut short before the session
    (None, "Name:\tsshd\nPid:\t5000\n"),     # the parent's status has no Uid line
])
def test_proc_files_that_make_no_sense_leave_an_ssh_server(monkeypatch, tmp_path, stat, status):
    plant_chain(tmp_path, [(5555, "sshd", 1000, 5000), (5000, "sshd", 0, 5000)])
    if stat is not None:
        (tmp_path / "proc" / "5555" / "stat").write_text(stat)
    if status is not None:
        (tmp_path / "proc" / "5000" / "status").write_text(status)
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=5555,fd=3)) '
                                         'uid:1000 ino:3 sk:3 <->'))
    f = one(network_scan().findings)
    assert (f.severity, f.title) == ("high", "SSH server (sshd) on port 2222")
