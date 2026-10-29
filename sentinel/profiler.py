"""System Profiler — know your machine.

Takes a snapshot of what's installed, what's running, what's listening,
and what's configured. This is the context layer that makes everything
else meaningful — you can't spot what's wrong if you don't know what's normal.

The profile is stored locally and used by the scanner and advisor
to calibrate their findings. A web server on a development laptop
is normal. A web server on grandpa's desktop is suspicious.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .paths import sentinel_home, skip_list, walk


@dataclass
class SystemProfile:
    """Snapshot of the system's identity and configuration."""
    hostname: str = ""
    platform: str = ""
    architecture: str = ""
    os_version: str = ""
    username: str = ""
    home_dir: str = ""
    profiled_at: str = ""

    # Hardware
    cpu_count: int = 0
    memory_gb: float = 0.0
    disk_usage_percent: float = 0.0

    # Software
    python_version: str = ""
    node_version: str = ""
    npm_version: str = ""
    git_version: str = ""
    docker_present: bool = False
    ollama_present: bool = False

    # Package managers
    pip_packages: int = 0
    npm_global_packages: int = 0
    node_modules_dirs: int = 0

    # Network
    listening_ports: list[dict] = field(default_factory=list)
    ssh_keys: int = 0
    has_npmrc: bool = False
    has_env_files: int = 0

    # AI-specific
    ollama_models: list[str] = field(default_factory=list)
    claude_code_installed: bool = False
    claude_hooks: list[str] = field(default_factory=list)
    vscode_present: bool = False

    # What the skip list kept the counts out of (sentinel/paths.py): its notes' titles, so a partial count says so
    not_counted: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"System: {self.hostname} ({self.platform} {self.architecture})",
            f"User: {self.username}",
            f"Hardware: {self.cpu_count} cores, {self.memory_gb:.1f}GB RAM, {self.disk_usage_percent:.0f}% disk used",
            f"Software: Python {self.python_version}, Node {self.node_version or 'N/A'}",
            f"Packages: {self.pip_packages} pip, {self.npm_global_packages} npm global, {self.node_modules_dirs} project node_modules",
            f"Network: {len(self.listening_ports)} listening ports, {self.ssh_keys} SSH keys",
            f"AI: Ollama {'yes' if self.ollama_present else 'no'} ({len(self.ollama_models)} models), Claude Code {'yes' if self.claude_code_installed else 'no'}",
        ]
        lines += self.not_counted   # "Not checked: 2 folders on your skip list": the counts above leave them out
        return "\n".join(lines)


def _run(cmd: list[str], timeout: int = 10) -> tuple[str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return "", -1


def profile_system(skip=None) -> SystemProfile:
    """Take a complete system profile snapshot. skip: the folders not to enter (None: the user's skip list)."""
    import shutil

    home = Path.home()
    skip = skip_list(skip)
    p = SystemProfile(
        hostname=platform.node(),
        platform=platform.system(),
        architecture=platform.machine(),
        os_version=platform.version()[:80],
        username=os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        home_dir=str(home),
        profiled_at=datetime.now(timezone.utc).isoformat(),
    )

    # Hardware
    p.cpu_count = os.cpu_count() or 0
    try:
        if platform.system() == "Darwin":
            mem_out, _ = _run(["sysctl", "-n", "hw.memsize"])
            p.memory_gb = int(mem_out) / (1024**3) if mem_out else 0
        else:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal"):
                        p.memory_gb = int(line.split()[1]) / (1024**2)
                        break
    except Exception:
        pass

    try:
        usage = shutil.disk_usage(str(home))
        p.disk_usage_percent = (usage.used / usage.total) * 100
    except Exception:
        pass

    # Software versions
    p.python_version = platform.python_version()

    node_out, rc = _run(["node", "--version"])
    if rc == 0:
        p.node_version = node_out.lstrip("v")

    npm_out, rc = _run(["npm", "--version"])
    if rc == 0:
        p.npm_version = npm_out

    git_out, rc = _run(["git", "--version"])
    if rc == 0:
        p.git_version = git_out.replace("git version ", "")

    p.docker_present = shutil.which("docker") is not None

    # Ollama
    p.ollama_present = shutil.which("ollama") is not None
    if p.ollama_present:
        models_out, rc = _run(["ollama", "list"])
        if rc == 0:
            for line in models_out.splitlines()[1:]:
                name = line.split()[0] if line.strip() else ""
                if name:
                    p.ollama_models.append(name)

    # Package counts
    pip_out, rc = _run(["pip3", "list", "--format=columns"])
    if rc == 0:
        p.pip_packages = max(0, len(pip_out.splitlines()) - 2)

    npm_global, rc = _run(["npm", "list", "-g", "--depth=0"])
    if rc == 0:
        p.npm_global_packages = max(0, len(npm_global.splitlines()) - 1)

    nm_count = 0
    for dirpath, dirnames, _files in walk(home, skip):
        if "node_modules" in dirnames and "node_modules/node_modules" not in os.path.join(dirpath, "node_modules"):
            nm_count += 1
        if nm_count > 50:
            break
    p.node_modules_dirs = nm_count

    # SSH keys (names only; nothing on the skip list, or linked into it, is looked at)
    ssh_dir = home / ".ssh"
    if not skip.covers(ssh_dir) and ssh_dir.exists():
        p.ssh_keys = sum(1 for f in ssh_dir.iterdir()
                         if f.suffix != ".pub" and f.name not in ("known_hosts", "config", "authorized_keys")
                         and not skip.covers(f) and f.is_file())

    p.has_npmrc = not skip.covers(home / ".npmrc") and (home / ".npmrc").exists()

    env_count = 0
    for dirpath, dirnames, filenames in walk(home, skip):
        # a folder named .env (a virtual environment) counted too, as rglob counted it
        if (".env" in filenames or ".env" in dirnames) and "node_modules" not in dirpath and ".git" not in dirpath:
            env_count += 1
        if env_count > 20:
            break
    p.has_env_files = env_count

    # Claude Code
    claude_bin = shutil.which("claude")
    p.claude_code_installed = claude_bin is not None

    claude_settings = home / ".claude" / "settings.json"
    if not skip.covers(claude_settings) and claude_settings.exists():
        try:
            data = json.loads(claude_settings.read_text())
            hooks = data.get("hooks", {})
            p.claude_hooks = list(hooks.keys())
        except (json.JSONDecodeError, OSError):
            pass

    p.vscode_present = shutil.which("code") is not None
    # what the skip list kept out of the counts (an entry that matched nothing changed no count)
    p.not_counted = [title for _sev, title, _d, _r, details in skip.notes() if "entries" not in details]

    return p


def save_profile(profile: SystemProfile, path: str = "") -> None:
    save_path = Path(path) if path else sentinel_home() / "profile.json"
    save_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = save_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(profile), indent=2))
    os.replace(str(tmp), str(save_path))


def load_profile(path: str = "") -> Optional[SystemProfile]:
    load_path = Path(path) if path else sentinel_home() / "profile.json"
    if not load_path.exists():
        return None
    try:
        data = json.loads(load_path.read_text())
        return SystemProfile(**{k: v for k, v in data.items() if k in SystemProfile.__dataclass_fields__})
    except (json.JSONDecodeError, TypeError):
        return None
