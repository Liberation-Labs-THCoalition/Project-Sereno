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


def by_port(findings):
    return {(f.details["proto"], f.details["port"]): f for f in findings if "port" in f.details}


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
    f, = check_network()
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
    f, = check_network()
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
        'LISTEN 0 4096 100.80.54.90:56893 0.0.0.0:*',
        'LISTEN 0 4096 [fd7a:115c:a1e0::c636:365a]:59823 [::]:*'))
    found = by_port(check_network())
    for port, host in (("56893", "100.80.54.90"), ("59823", "[fd7a:115c:a1e0::c636:365a]")):
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
    f, = check_network()
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
        ("medium", "Listening ports not checked (UDP)"), ("medium", "Unexpected listening port: 7000")]
    assert "lsof and netstat didn't work" in findings[0].description
    assert "Make sure netstat is available" in findings[0].remediation


def test_macos_lsof_finding_nothing_still_lists_netstat_sockets(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, mac=True, lsof_tcp=("", 1), lsof_udp=("", 1),
        netstat_tcp="\n".join([NETSTAT_HDR, "tcp46 0 0 *.8080 *.* LISTEN"]), netstat_udp="")
    f, = check_network()
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
    f, = check_network()
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
        'LISTEN 0 1 127.0.0.1:631 0.0.0.0:* ino:7 sk:7 cgroup:/system.slice/cups.service <->'))
    found = by_port(check_network())
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
    cups = found[("TCP", "631")]
    assert cups.title == "Printing (CUPS) on port 631 (this machine only)"
    assert "To see which program" not in cups.remediation


def test_a_launcher_holding_the_socket_is_named_by_port(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss(
        'LISTEN 0 1 *:3389 *:* users:(("systemd",pid=1,fd=50)) ino:8 sk:8 cgroup:/system.slice/rdp.socket <->'))
    f, = check_network()
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
        f, = check_network()
        assert (f.severity, f.title) == ("medium", "Unexpected listening port: 56893"), planted
        assert "reachable from %s" % where in f.description


def test_without_tailscale_the_rule_is_skipped_quietly(monkeypatch, tmp_path):
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 4096 100.80.54.90:56893 0.0.0.0:*'))
    f, = check_network()
    assert (f.severity, f.title) == ("medium", "Unexpected listening port: 56893")
    assert "reachable from other machines" in f.description


def test_tailscale_is_asked_only_when_a_socket_is_on_a_tailscale_address(monkeypatch, tmp_path):
    calls = env(monkeypatch, tmp_path, tailscale=TS_JSON, ss_tcp=ss('LISTEN 0 1 0.0.0.0:7000 0.0.0.0:*',
                                                                    'LISTEN 0 1 100.128.0.1:7001 0.0.0.0:*'))
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
    f, = check_network()
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
    f, = check_network()
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
    lines = ('LISTEN 0 1 127.0.0.1:7000 0.0.0.0:* users:(("node",pid=5,fd=3)) uid:1000 ino:1 sk:1 <->',
             'LISTEN 0 1 0.0.0.0:7000 0.0.0.0:* uid:33 ino:2 sk:2 <->')
    env(monkeypatch, tmp_path, ss_tcp=ss(*lines))
    f, = check_network()
    assert "Program: node (pid 5), user " in f.description
    assert "Another socket on this port: owner not visible without sudo." in f.description
    assert f.details["owner_visible"] is False and f.details["programs"] == ["node"]
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss(*lines))
    f, = check_network()
    assert "No program holds one socket on this port: it's the kernel's" in f.description
    env(monkeypatch, tmp_path, euid=0, ss_tcp=ss('LISTEN 0 1 0.0.0.0:7002 0.0.0.0:* ino:2 sk:2 <->'))
    f, = check_network()
    assert "No program holds it: it's the kernel's (WireGuard and NFS work this way). The system shows it belongs " \
           "to user root." in f.description
    env(monkeypatch, tmp_path, ss_tcp=ss('LISTEN 0 1 0.0.0.0:7003 0.0.0.0:*'))
    f, = check_network()
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
