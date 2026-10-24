"""Listening ports, named (2026-10-24).

The network check used to say "unexpected listening port 3390". This module ties every listening TCP and UDP socket
to its program and binary where Sereno can see them, and names the services a person should recognise, so the same
socket reads "remote desktop (gnome-remote-desktop) on port 3390".

Where the facts come from (read-only and local):
- Linux: `ss -tlnp -e` and `ss -ulnp -e`. ss names the program only for your own sockets (all of them as root). For
  the rest it still shows the owning user and, on current systems, the systemd unit the socket was opened in. If ss
  is missing, /proc/net/{tcp,tcp6,udp,udp6} list the same sockets with their owners' user ids, and /proc/<pid>/fd
  ties them to the processes Sereno may read. The binary is /proc/<pid>/exe.
- macOS: `lsof` for the programs it may see (your own without sudo), and `netstat -an` for every listening socket, so
  the system's own are listed too. The binary is from `ps -o comm=`.
- Tailscale: `tailscale status --json` (5 s timeout), asked only when a socket is bound to a Tailscale address. If
  tailscale isn't installed, that rule is skipped.

How sure: a name from the program or its systemd unit is a fact; a name from the port alone is a guess, and the
finding says "likely". A socket whose program Sereno can't see is reported with "owner not visible without sudo",
never passed over. Command lines are never read, because they can hold passwords (x11vnc -passwd does).

What's reported (the reachability rules of 0060f82 stand):
- high: remote control that other machines can reach (a remote desktop, or SSH on any port but 22), on any TCP port
  and on remote desktops' own UDP ports;
- medium: any other TCP port other machines can reach, except 22, 80 and 443; UDP services on ports up to 1024,
  beyond the common client ones; a protocol whose ports couldn't be listed at all ("not checked");
- info: what only this machine can reach; Tailscale's own listeners on its tailnet addresses; ports in expected.json.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from pathlib import Path
from urllib.parse import urlsplit

PROC = Path("/proc")

# 22, 80 and 443 are what a machine is usually meant to serve; they aren't reported, unless a remote desktop holds one.
COMMON_TCP = {"22", "80", "443"}
# UDP services a machine runs as a client or for the local network: DHCP, NTP, NetBIOS name and datagram, DHCPv6.
COMMON_UDP = {"67", "68", "123", "137", "138", "546", "547"}

# Remote control, by program: name as ss, lsof or the binary's file name give it -> (what it is, name to show, how
# to switch it off). Linux cuts a program's name to 15 characters (gnome-remote-desktop-daemon shows as
# gnome-remote-de), so a name that long also matches the start of a longer one.
REMOTE_PROGRAMS = {
    "gnome-remote-desktop-daemon": ("remote desktop", "gnome-remote-desktop", "grd"),
    "gnome-remote-desktop": ("remote desktop", "gnome-remote-desktop", "grd"),
    "xrdp": ("remote desktop", "xrdp", "xrdp"),
    "xrdp-sesman": ("remote desktop", "xrdp", "xrdp"),
    "x11vnc": ("remote desktop", "x11vnc", "x11vnc"),
    "vino-server": ("remote desktop", "vino", "vino"),
    "xvnc": ("remote desktop", "Xvnc", "xvnc"),
    "xtigervnc": ("remote desktop", "Xtigervnc", "xvnc"),
    "x0vncserver": ("remote desktop", "x0vncserver", "xvnc"),
    "wayvnc": ("remote desktop", "wayvnc", "wayvnc"),
    "vncserver-x11-core": ("remote desktop", "RealVNC", "realvnc"),
    "vncserver-x11-serviced": ("remote desktop", "RealVNC", "realvnc"),
    "krfb": ("remote desktop", "krfb", "krfb"),
    "rustdesk": ("remote desktop", "RustDesk", "rustdesk"),
    "anydesk": ("remote desktop", "AnyDesk", "anydesk"),
    "teamviewerd": ("remote desktop", "TeamViewer", "teamviewer"),
    "teamviewer": ("remote desktop", "TeamViewer", "teamviewer"),
    "teamviewer_service": ("remote desktop", "TeamViewer", "teamviewer"),
    "nxd": ("remote desktop", "NoMachine", "nomachine"),
    "nxserver.bin": ("remote desktop", "NoMachine", "nomachine"),
    "nxnode.bin": ("remote desktop", "NoMachine", "nomachine"),
    "screensharingd": ("remote desktop", "macOS Screen Sharing", "macos_sharing"),
    "ardagent": ("remote management", "Apple Remote Desktop", "macos_sharing"),
    "sshd": ("SSH server", "sshd", "ssh"),
    "dropbear": ("SSH server", "dropbear", "ssh"),
}

# Remote control, by its usual port, used only when the program can't be seen (or is a launcher that starts services
# on demand): (protocol, first port, last port, what it is, its usual name, how to switch it off).
REMOTE_PORTS = (
    ("TCP", 22, 22, "SSH server", "SSH", "ssh"),
    ("TCP", 3283, 3283, "remote management", "Apple Remote Desktop", "macos_sharing"),
    ("UDP", 3283, 3283, "remote management", "Apple Remote Desktop", "macos_sharing"),
    ("TCP", 3389, 3390, "remote desktop", "RDP", "rdp"),
    ("UDP", 3389, 3389, "remote desktop", "RDP", "rdp"),
    ("TCP", 4000, 4000, "remote desktop", "NoMachine", "nomachine"),
    ("TCP", 5900, 5910, "remote desktop", "VNC", "vnc"),
    ("TCP", 5938, 5938, "remote desktop", "TeamViewer", "teamviewer"),
    ("UDP", 5938, 5938, "remote desktop", "TeamViewer", "teamviewer"),
    ("TCP", 21115, 21119, "remote desktop", "RustDesk", "rustdesk"),
    ("UDP", 21116, 21116, "remote desktop", "RustDesk", "rustdesk"),
)
# Programs that hold a socket for a service they start on demand; the port says more about it than their name does.
LAUNCHERS = {"systemd", "launchd", "inetd", "xinetd", "init"}

# Common services, only to name them: severity stays as the reachability rules decide.
SERVICE_PROGRAMS = {
    "ollama": "Ollama", "postgres": "PostgreSQL", "nats-server": "NATS", "redis-server": "Redis", "mysqld": "MySQL",
    "mariadbd": "MariaDB", "mongod": "MongoDB", "cupsd": "printing (CUPS)", "avahi-daemon": "network discovery (Avahi)",
    "systemd-resolved": "DNS resolver (systemd-resolved)", "dnsmasq": "DNS and DHCP (dnsmasq)",
    "syncthing": "Syncthing", "mosquitto": "MQTT (Mosquitto)", "dockerd": "Docker",
    "docker-proxy": "a Docker container's published port (docker-proxy)",
    "containerd": "container runtime (containerd)",
    "ssh": "SSH port forward (ssh)", "sshd-session": "SSH reverse tunnel (sshd-session)",
    "tailscaled": "Tailscale (tailscaled)",
}
SERVICE_PORTS = {
    ("TCP", "53"): "DNS", ("UDP", "53"): "DNS", ("TCP", "631"): "printing (CUPS)", ("UDP", "631"): "printing (CUPS)",
    ("TCP", "1883"): "MQTT", ("TCP", "3306"): "MySQL or MariaDB", ("TCP", "4222"): "NATS",
    ("TCP", "5432"): "PostgreSQL", ("TCP", "5433"): "PostgreSQL", ("TCP", "5434"): "PostgreSQL",
    ("TCP", "6379"): "Redis", ("TCP", "8384"): "Syncthing", ("TCP", "11434"): "Ollama", ("TCP", "27017"): "MongoDB",
}
# systemd units whose name isn't their program's.
UNIT_PROGRAMS = {"ssh": "sshd", "nxserver": "nxd", "postgresql": "postgres", "docker": "dockerd", "nats": "nats-server",
                 "redis": "redis-server", "mysql": "mysqld", "mariadb": "mariadbd", "cups": "cupsd",
                 "vncserver": "xvnc", "tigervncserver": "xvnc"}

# How to switch remote control off, each with its undo. {port}, {display} (VNC display) and {grd} (rdp or vnc) are
# filled in.
OFF = {
    "grd": "Switch it off in Settings > System > Remote Desktop (older GNOME: Settings > Sharing), or run "
           "`grdctl {grd} disable` and "
           "`systemctl --user disable --now gnome-remote-desktop` (undo: `grdctl {grd} enable` and "
           "`systemctl --user enable --now gnome-remote-desktop`). If it's the login screen's remote login (the system "
           "service), the same with sudo: `sudo grdctl --system {grd} disable` and "
           "`sudo systemctl disable --now gnome-remote-desktop`.",
    "xrdp": "Switch it off: `sudo systemctl disable --now xrdp xrdp-sesman` (undo: "
            "`sudo systemctl enable --now xrdp xrdp-sesman`).",
    "x11vnc": "Stop it with `pkill -x x11vnc` (undo: start x11vnc again), then remove what starts it (a systemd unit "
              "or an autostart entry) so it stays off.",
    "vino": "Switch it off in Settings > Sharing > Screen Sharing, or `systemctl --user disable --now vino-server` "
            "(undo: switch it back on).",
    "xvnc": "Stop it with `vncserver -kill :{display}` (undo: `vncserver :{display}`); if a systemd unit starts it, "
            "`sudo systemctl disable --now vncserver@:{display}` (undo: the same with enable).",
    "wayvnc": "On Raspberry Pi OS: `sudo raspi-config`, Interface Options, VNC, No (undo: the same, Yes). Elsewhere, "
              "stop it with `pkill -x wayvnc` and remove its autostart entry.",
    "realvnc": "On Raspberry Pi OS: `sudo raspi-config`, Interface Options, VNC, No (undo: the same, Yes). Elsewhere: "
               "`sudo systemctl disable --now vncserver-x11-serviced` (undo: the same with enable).",
    "krfb": "Quit Desktop Sharing (krfb) and turn off its autostart in its settings (undo: start krfb again).",
    "rustdesk": "Switch it off: `sudo systemctl disable --now rustdesk` (undo: `sudo systemctl enable --now rustdesk`), "
                "or quit RustDesk if you only start it when you need it.",
    "anydesk": "Switch it off: `sudo systemctl disable --now anydesk` (undo: `sudo systemctl enable --now anydesk`); "
               "on macOS, quit AnyDesk.",
    "teamviewer": "Switch it off: `sudo teamviewer daemon disable` (undo: `sudo teamviewer daemon enable`); on macOS, "
                  "quit TeamViewer.",
    "nomachine": "Switch it off: `sudo /etc/NX/nxserver --shutdown`, then `sudo /etc/NX/nxserver --startmode manual` "
                 "so it doesn't start at boot (undo: `--startmode automatic`, then `--startup`).",
    "macos_sharing": "Switch it off: System Settings > General > Sharing (System Preferences > Sharing on older "
                     "macOS), turn off Screen Sharing and Remote Management (undo: turn them back on).",
    "rdp": "If it's GNOME's remote login: Settings > System > Remote Desktop, or `sudo grdctl --system rdp disable` "
           "(undo: `sudo grdctl --system rdp enable`). If it's xrdp: `sudo systemctl disable --now xrdp` (undo: "
           "`sudo systemctl enable --now xrdp`).",
    "vnc": "If it's GNOME's: `grdctl vnc disable` (undo: `grdctl vnc enable`). If it's TigerVNC: "
           "`vncserver -kill :{display}` (undo: `vncserver :{display}`).",
    "ssh": "SSH on port 22 isn't reported. If you moved SSH to port {port} on purpose, add {port} to expected.json. If "
           "you didn't, a second SSH server is running: find it with `sudo ss -ltnp 'sport = :{port}'` and stop it "
           "(undo: start it again).",
}

TAILSCALE_NETS = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))
_ADDR = re.compile(r"^(.*):(\d+)$")


def loopback(host: str) -> bool:
    h = host.split("%", 1)[0].strip("[]")
    return h.startswith("127.") or h in ("::1", "localhost") or h.startswith("::ffff:127.")


def _norm(host: str) -> str:
    """An address in one spelling: no brackets or zone, IPv6 compressed. (lsof and netstat both write "*" for any
    address, so the wildcard needs no mapping.)"""
    h = host.split("%", 1)[0].strip("[]")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        return h


def _tailscale_range(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(_norm(host))
    except ValueError:
        return False
    return any(ip in net for net in TAILSCALE_NETS)


def _lookup(table: dict, names):
    """The table's entry for the first of these program names it knows (lower case; a 15-character name, as Linux cuts
    them, also matches a longer one it starts)."""
    for n in names:
        n = n.lower()
        for key, value in table.items():
            if n == key or (len(n) >= 15 and key.startswith(n)):
                return value
    return None


def _sock(proto, host, port, line, programs=(), pid="", uid=None, user="", cgroup=""):
    return {"proto": proto, "host": host, "port": port, "line": line, "programs": list(programs), "pid": pid,
            "uid": uid, "user": user, "cgroup": cgroup, "exe": ""}


# ── Linux ──

def parse_ss(output: str, proto: str) -> list:
    """Sockets from `ss -tlnp -e` or `ss -ulnp -e` output. ss -e prints uid: only when it isn't 0, so a line with ino:
    and no uid: is root's; a line with neither (an old ss, or no -e) has no known owner."""
    socks = []
    for line in output.splitlines():  # a header line has no host:port in the address column, so it's skipped below
        f = line.split()
        if not f:
            continue
        p = proto
        if f[0].lower() in ("tcp", "udp"):  # ss prints the protocol first when asked for both
            p, f = f[0].upper(), f[1:]
        m = _ADDR.match(f[3]) if len(f) > 3 else None
        if not m:
            continue
        procs = re.findall(r'\("([^"]*)",pid=(\d+)', line)
        uid = re.search(r"\buid:(\d+)", line)
        cgroup = re.search(r"\bcgroup:(\S+)", line)
        socks.append(_sock(p, m.group(1), m.group(2), line.strip(), [n for n, _ in procs],
                           procs[0][1] if procs else "",
                           int(uid.group(1)) if uid else (0 if re.search(r"\bino:\d+", line) else None),
                           cgroup=cgroup.group(1) if cgroup else ""))
    return socks


def _hex_host(h: str) -> str:
    """An address from /proc/net: 32-bit words in host order (little-endian on the machines Sereno runs on)."""
    raw = bytes.fromhex(h)
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    return "[%s]" % socket.inet_ntop(socket.AF_INET6, raw)


def proc_sockets(proto: str):
    """Listening sockets from /proc/net, for when ss can't run, with their programs where /proc/<pid>/fd may be read.
    None when no /proc/net file for this protocol could be read."""
    socks, inodes, read_any = [], {}, False
    for name in (proto.lower(), proto.lower() + "6"):
        try:
            text = (PROC / "net" / name).read_text()
        except OSError:
            continue
        read_any = True
        for line in text.splitlines()[1:]:
            f = line.split()
            if len(f) < 10:
                continue
            listening = f[3] == "0A" if proto == "TCP" else (f[3] == "07" and f[2].endswith(":0000"))
            if not listening:
                continue
            addr, _, port = f[1].partition(":")
            try:
                s = _sock(proto, _hex_host(addr), str(int(port, 16)), line.strip(), uid=int(f[7]))
            except (ValueError, OSError):
                continue
            socks.append(s)
            inodes.setdefault(f[9], []).append(s)
    if not read_any:
        return None
    for inode, (pid, comm) in _inode_owners(set(inodes)).items():
        for s in inodes[inode]:
            s["programs"].append(comm)
            s["pid"] = s["pid"] or pid
    return socks


def _inode_owners(inodes: set) -> dict:
    """socket inode -> (pid, program name), for the processes whose fd folder Sereno may read."""
    owners = {}
    try:
        pids = sorted((p for p in os.listdir(str(PROC)) if p.isdigit()), key=int)  # a shared socket: the parent
    except OSError:
        return owners
    for pid in pids:
        try:
            fds = os.listdir(str(PROC / pid / "fd"))
        except OSError:
            continue  # another user's process: not readable without sudo
        for fd in fds:
            try:
                target = os.readlink(str(PROC / pid / "fd" / fd))
            except OSError:
                continue
            m = re.match(r"socket:\[(\d+)\]", target)  # a file's link is an absolute path, never this
            if m and m.group(1) in inodes and m.group(1) not in owners:
                try:
                    comm = (PROC / pid / "comm").read_text().strip()
                except OSError:
                    comm = "?"
                owners[m.group(1)] = (pid, comm)
    return owners


def _linux_exe(pid: str) -> str:
    try:
        return os.readlink(str(PROC / pid / "exe"))
    except OSError:
        return ""


def _gather_linux(run):
    socks, unchecked = [], []
    for proto, flag in (("TCP", "-tlnp"), ("UDP", "-ulnp")):
        output, rc = run(["ss", flag, "-e"])
        if rc == 0:
            socks += parse_ss(output, proto)
            continue
        found = proc_sockets(proto)
        if found is None:
            unchecked.append(proto)
        else:
            socks += found
    for s in socks:
        if s["pid"]:
            s["exe"] = _linux_exe(s["pid"])
    return socks, unchecked


# ── macOS ──

def parse_lsof(output: str, proto: str) -> list:
    """Sockets from `lsof +c 0 -nP -iTCP -sTCP:LISTEN` or `-iUDP`. A connected UDP socket (a->b) isn't listening."""
    socks = []
    for line in output.splitlines():
        f = line.split()
        if proto not in f or f.index(proto) + 1 >= len(f) or len(f) < 3:
            continue
        name = f[f.index(proto) + 1]
        m = _ADDR.match(name)
        if "->" in name or not m:
            continue
        socks.append(_sock(proto, m.group(1), m.group(2), line.strip(), [f[0].replace("\\x20", " ")], f[1],
                           uid=_uid_of(f[2]), user=f[2]))
    return socks


def _uid_of(user: str):
    """lsof's USER column as a user id (it prints the id itself when the name is unknown); None when unknown."""
    if user.isdigit():
        return int(user)
    try:
        import pwd
        return pwd.getpwnam(user).pw_uid
    except (ImportError, KeyError):
        return None


def parse_netstat(output: str, proto: str) -> list:
    """Every listening socket from macOS `netstat -an -p tcp` or `-p udp` (local address written host.port), owners
    unknown."""
    socks = []
    for line in output.splitlines():
        f = line.split()
        if len(f) < 5 or not f[0].startswith(proto.lower()):
            continue
        listening = (len(f) > 5 and f[5] == "LISTEN") if proto == "TCP" else f[4] == "*.*"
        host, _, port = f[3].rpartition(".")
        if listening and host and port.isdigit():
            socks.append(_sock(proto, host, port, line.strip()))
    return socks


def _gather_macos(run):
    socks, unchecked = [], []
    for proto, lsof_args, family in (("TCP", ["-iTCP", "-sTCP:LISTEN"], "tcp"), ("UDP", ["-iUDP"], "udp")):
        output, rc = run(["lsof", "+c", "0", "-nP"] + lsof_args)
        seen = parse_lsof(output, proto)  # lsof exits 1 when it has nothing to list, so rc only says "not checked"
        stat, src = run(["netstat", "-an", "-p", family])
        if rc != 0 and src != 0:
            unchecked.append(proto)
        keys = {(_norm(s["host"]), s["port"]) for s in seen}
        hidden = [s for s in parse_netstat(stat, proto) if (_norm(s["host"]), s["port"]) not in keys] if src == 0 else []
        socks += seen + hidden
    pids = sorted({s["pid"] for s in socks if s["pid"]})
    if pids:
        output, _ = run(["ps", "-o", "pid=,comm=", "-p", ",".join(pids)])  # a ps that fails prints nothing
        exes = dict(line.strip().split(None, 1) for line in output.splitlines() if len(line.split(None, 1)) == 2)
        for s in socks:
            s["exe"] = exes.get(s["pid"], "")
    return socks, unchecked


# ── Tailscale ──

def tailnet(run, macos: bool):
    """(this machine's tailnet addresses, the (address, port) pairs it lists as its peer API), from `tailscale status
    --json`; two empty sets when tailscale isn't installed or doesn't answer in 5 seconds."""
    cmds = [["tailscale", "status", "--json"]]
    if macos:
        cmds.append(["/Applications/Tailscale.app/Contents/MacOS/Tailscale", "status", "--json"])
    for cmd in cmds:
        # It answered in 0.03 s on Asdf (5 runs, 2026-10-24); 5 s only bounds a tailscaled that hangs, so one stuck
        # daemon can't stall the scan the way the default 30 s would
        output, rc = run(cmd, timeout=5)
        if rc != 0:
            continue
        try:
            me = json.loads(output).get("Self") or {}
            ips = {_norm(str(a)) for a in me.get("TailscaleIPs") or []}
            api = set()
            for url in me.get("PeerAPIURL") or []:
                try:
                    u = urlsplit(str(url))
                    if u.hostname and u.port:
                        api.add((_norm(u.hostname), str(u.port)))
                except ValueError:
                    continue  # one malformed URL mustn't drop the others
            return ips, api
        except (ValueError, AttributeError, TypeError):
            continue
    return set(), set()


# ── Naming ──

def _unit(cgroup: str) -> str:
    """The systemd unit a socket was opened in, from its cgroup path; "" when it isn't one."""
    last = cgroup.rstrip("/").rsplit("/", 1)[-1]
    return last if last.endswith((".service", ".socket", ".scope")) else ""


def _names(s) -> list:
    """The program names to match: as listed, and the binary's file name."""
    exe = s["exe"][:-len(" (deleted)")] if s["exe"].endswith(" (deleted)") else s["exe"]
    return s["programs"] + ([os.path.basename(exe)] if exe else [])


def _unit_names(s) -> list:
    base = re.split(r"[@.]", _unit(s["cgroup"]), 1)[0]
    return [UNIT_PROGRAMS.get(base, base)] if base else []


def _remote_port(proto: str, port: str):
    for p, first, last, what, name, off in REMOTE_PORTS:
        if p == proto and first <= int(port) <= last:
            return what, name, off
    return None


def _tailscale_reason(s, ts_ips, ts_api):
    """How a socket is known to be Tailscale's own, or "" when it isn't."""
    if (_norm(s["host"]), s["port"]) in ts_api and _norm(s["host"]) in ts_ips:
        return "tailscale status"
    if s["uid"] == 0 and _lookup({"tailscaled": 1}, s["programs"]):
        return "program"
    if s["uid"] == 0 and s["cgroup"] == "/system.slice/tailscaled.service":
        return "unit"
    return ""


def _unseen(s) -> bool:
    """The program isn't visible, or is only a launcher that holds the socket for a service it starts on demand."""
    return not s["programs"] or set(s["programs"]) <= LAUNCHERS


def identify(members, proto, port, ts_ips, ts_api) -> dict:
    """What the sockets on one port are: kind ("remote", "tailscale", "service" or ""), label, how it was told
    ("program", "unit", "port", "tailscale status") and, for remote control, how to switch it off. A visible program
    is the best witness; a systemd unit or the port speak only for sockets whose program isn't visible."""
    unseen = [s for s in members if _unseen(s)]
    for how, names, among in (("program", _names, members), ("unit", _unit_names, unseen)):
        for s in among:
            hit = _lookup(REMOTE_PROGRAMS, names(s))
            if hit:
                return {"kind": "remote", "label": "%s (%s)" % hit[:2], "how": how, "off": hit[2]}
    reasons = [_tailscale_reason(s, ts_ips, ts_api) for s in members]
    if all(reasons):
        label = "Tailscale peer API (tailscaled)" if reasons[0] == "tailscale status" else "Tailscale (tailscaled)"
        return {"kind": "tailscale", "label": label, "how": reasons[0], "off": ""}
    hit = _remote_port(proto, port)
    if unseen and hit:
        return {"kind": "remote", "label": "%s (%s)" % hit[:2], "how": "port", "off": hit[2]}
    for how, names, among in (("program", _names, members), ("unit", _unit_names, unseen)):
        for s in among:
            label = _lookup(SERVICE_PROGRAMS, names(s))
            if label:
                return {"kind": "service", "label": label, "how": how, "off": ""}
    label = SERVICE_PORTS.get((proto, port))
    if unseen and label:
        return {"kind": "service", "label": label, "how": "port", "off": ""}
    return {"kind": "", "label": "", "how": "", "off": ""}


def _reported(proto, port, local, ident) -> bool:
    """0060f82's rules, with remote control added: a remote desktop is reported on any port, SSH on 22 still isn't."""
    remote = ident["kind"] == "remote"
    if proto == "TCP":
        owned = remote and ident["how"] in ("program", "unit") and not (ident["off"] == "ssh" and port == "22")
        return port not in COMMON_TCP or owned
    if local:
        return False
    return (remote and _remote_port(proto, port) is not None) or (int(port) <= 1024 and port not in COMMON_UDP)


def _user(uid) -> str:
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError, TypeError, OverflowError):
        return "uid %s" % uid


def _who(members, euid) -> tuple:
    """(a sentence on who owns the sockets, visible?)."""
    seen = [s for s in members if s["programs"]]
    hidden = [s for s in members if not s["programs"]]
    parts = []
    if seen:
        s = seen[0]
        progs = ", ".join(dict.fromkeys(p for x in seen for p in x["programs"]))
        extra = ", ".join(x for x in ("pid " + s["pid"] if s["pid"] else "", s["exe"]) if x)
        user = s["user"] or (_user(s["uid"]) if s["uid"] is not None else "")
        parts.append("Program: %s%s%s." % (progs, " (%s)" % extra if extra else "", ", user " + user if user else ""))
    if hidden:
        s = hidden[0]
        facts = [x for x in ("user " + (s["user"] or _user(s["uid"])) if s["uid"] is not None or s["user"] else "",
                             "systemd unit " + _unit(s["cgroup"]) if _unit(s["cgroup"]) else "") if x]
        known = " The system shows it belongs to %s." % " and ".join(facts) if facts else ""
        if euid == 0:
            parts.append("No program holds %s: it's the kernel's (WireGuard and NFS work this way).%s"
                         % ("one socket on this port" if seen else "it", known))
        else:
            parts.append("%s: owner not visible without sudo.%s"
                         % ("Another socket on this port" if seen else "Sereno can't see which program this is",
                            known))
    return " ".join(parts), not hidden


def _how(ident, members, proto, port) -> str:
    how = ident["how"]
    if ident["kind"] == "tailscale" and how != "tailscale status":
        return "Identified by its %s, running as root." % (
            "program, tailscaled" if how == "program" else "systemd unit, tailscaled.service")
    if how == "tailscale status":
        s = members[0]
        return ("Identified by `tailscale status --json`, which lists %s port %s as this machine's peer API; it's bound "
                "only to this machine's tailnet address." % (_norm(s["host"]), port))
    if how == "port":
        return "Named by its port alone (%s is the usual port for it), so this is a likely guess, not a fact." % port
    hit = _remote_port(proto, port)
    hint = SERVICE_PORTS.get((proto, port)) or ("%s (%s)" % hit[:2] if hit else "")
    said = {"program": "Named by its program.", "unit": "Named by its systemd unit."}.get(how, "")
    if hint and hint.lower() not in ident["label"].lower():  # "DNS resolver (systemd-resolved)" needn't add "DNS"
        said += " Port %s is the usual port for %s." % (port, hint)
    return said.strip()


def _remediation(ident, port, local, macos, visible, expected, root) -> str:
    if expected:
        return ""
    # Running as root already shows every program: a socket still without one is the kernel's, and sudo can't add more
    find = ("" if visible or root or ident["how"] in ("program", "unit") else "To see which program it is: `sudo %s`. "
            % ("lsof -nP -i :%s" % port if macos else "ss -ltnup 'sport = :%s'" % port))
    if ident["kind"] == "tailscale":
        if local or ident.get("tailnet_only"):
            return "Nothing to do: Tailscale runs this, and your tailnet's access rules decide which devices reach it."
        return ("tailscaled's own listeners sit on tailnet addresses. One open to other machines is usually a proxy "
                "set with --socks5-server or --outbound-http-proxy-listen: bind it to localhost (undo: set it back), "
                "or add %s to expected.json if you share it on purpose." % port)
    if ident["kind"] == "remote":
        key = "macos_sharing" if macos and ident["off"] == "vnc" else ident["off"]
        display = int(port) - 5900 if 5900 <= int(port) <= 5999 else "N"
        off = OFF[key].format(port=port, display=display, grd="vnc" if 5900 <= int(port) <= 5910 else "rdp")
        tail = "" if key == "ssh" else " If you use it on purpose, add %s to expected.json: it stays listed, as info." % port
        return (find + ("Only this machine can reach it (an SSH tunnel is the usual way in). If you didn't set that "
                        "up: " if local else "") + off + tail)
    if ident["kind"] == "service" and ident["how"] != "port":
        return ("If you know %s and run it on purpose, add %s to expected.json. If you don't recognize it, investigate."
                % (ident["label"], port))
    return (find + "Check what's using port %s. If you don't recognize it, investigate. If you run it on purpose, "
                   "add %s to expected.json." % (port, port))


def _clip(line: str, n: int = 160) -> str:
    """A socket's line for the description, spaces squeezed and the cut marked; details keep it whole."""
    line = " ".join(line.split())
    return line if len(line) <= n else line[:n - 3] + "..."


def _euid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else -1


def check_listeners(make, run, macos: bool, expected: set) -> list:
    """Findings for every listening port; `make(severity, title, description, remediation, details)`."""
    euid = _euid()
    socks, unchecked = (_gather_macos if macos else _gather_linux)(run)
    out = []
    for proto in unchecked:
        tools = "lsof and netstat" if macos else "ss and /proc/net"
        out.append(make("medium", "Listening ports not checked (%s)" % proto,
                        "Sereno couldn't list the %s ports: %s didn't work, so nothing listening on %s was checked."
                        % (proto, tools, proto),
                        "Make sure %s is available (on Linux, ss comes in the iproute2 package), then scan again."
                        % ("netstat" if macos else "ss"),
                        {"proto": proto, "not_checked": True}))
    ts_ips, ts_api = set(), set()
    if any(_tailscale_range(s["host"]) for s in socks):
        ts_ips, ts_api = tailnet(run, macos)
    groups = {}
    for s in socks:
        groups.setdefault((s["proto"], s["port"]), []).append(s)
    for (proto, port), members in groups.items():
        hosts = list(dict.fromkeys(s["host"] for s in members))
        local = all(loopback(h) for h in hosts)
        ident = identify(members, proto, port, ts_ips, ts_api)
        if not _reported(proto, port, local, ident):
            continue
        # A socket tailscaled itself holds on an address in Tailscale's range is on its tailnet address, even when
        # the tailscale command isn't there to list them
        tailnet_only = all(loopback(h) or _norm(h) in ts_ips or (ident["kind"] == "tailscale" and _tailscale_range(h))
                           for h in hosts)
        ident["tailnet_only"] = tailnet_only
        is_expected = port in expected
        if is_expected or local or (ident["kind"] == "tailscale" and tailnet_only):
            severity = "info"
        else:
            severity = "high" if ident["kind"] == "remote" else "medium"
        udp = "" if proto == "TCP" else " (UDP)"
        name = ident["label"][:1].upper() + ident["label"][1:]
        if ident["label"] and ident["how"] == "port":
            name = "Likely " + ident["label"]
        if is_expected:
            title = "%s%s (expected by operator)" % (name + " on port " + port if name else "Listening port " + port, udp)
        elif name:
            title = "%s on port %s%s%s" % (name, port, udp, " (this machine only)" if local else "")
        else:
            title = "Unexpected listening port: %s%s%s" % (port, udp, " (this machine only)" if local else "")
        where = ("this machine only" if local else
                 "machines on your Tailscale network" if tailnet_only else "other machines")
        who, visible = _who(members, euid)
        expected_note = " Port %s is listed in expected.json." % port if is_expected else ""
        description = " ".join(x for x in (
            "Something is listening on %s port %s, reachable from %s (bound to %s)." % (proto, port, where,
                                                                                      ", ".join(hosts)),
            who, _how(ident, members, proto, port), expected_note.strip(),
            "Line: %s" % _clip(members[0]["line"])) if x)
        first = members[0]
        shown = next((s for s in members if s["programs"]), first)
        out.append(make(severity, title, description,
                        _remediation(ident, port, local, macos, visible, is_expected, euid == 0),
                        {"port": port, "proto": proto, "host": first["host"], "hosts": hosts, "line": first["line"],
                         "loopback": local, "expected": is_expected, "service": ident["label"],
                         "identified_by": ident["how"], "programs": shown["programs"], "pid": shown["pid"],
                         "exe": shown["exe"], "uid": first["uid"], "unit": _unit(first["cgroup"]),
                         "owner_visible": visible}))
    return out
