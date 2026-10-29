"""Hardening Advisor — tells you what to fix in language you understand.

Not a penetration test. Not a compliance checklist. Just a neighbor
who knows enough about locks to tell you which ones are broken.

Checks common misconfigurations and suggests fixes. Each recommendation
comes with:
  - What's wrong (plain language)
  - Why it matters (what could happen)
  - How to fix it (exact commands)
  - How hard the fix is (easy/moderate/involved)
"""
from __future__ import annotations

import logging
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.paths import skip_list

logger = logging.getLogger(__name__)   # assess() logs a check that failed (it was never defined, so a failure raised)


@dataclass
class Recommendation:
    """A single hardening recommendation."""
    category: str  # network, auth, filesystem, software, privacy
    severity: str  # critical, important, suggested, informational
    title: str
    what: str
    why: str
    fix: str
    difficulty: str  # easy, moderate, involved

    def human_readable(self) -> str:
        icons = {"critical": "!!!", "important": "!!", "suggested": "!", "informational": "."}
        icon = icons.get(self.severity, "?")
        lines = [
            f"[{icon}] {self.title}",
            f"    What: {self.what}",
            f"    Why:  {self.why}",
            f"    Fix:  {self.fix}",
            f"    Difficulty: {self.difficulty}",
        ]
        return "\n".join(lines)


def _run(cmd: list[str], timeout: int = 15) -> tuple[str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return "", -1


def _home() -> Path:
    return Path.home()


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _is_linux() -> bool:
    return platform.system() == "Linux"


# ── Checks ──

def check_ssh_config(skip=None) -> list[Recommendation]:
    """Check SSH configuration for common issues. skip: the folders not to enter (None: the user's skip list); asked
    before each path is looked up, so ~/.ssh linked into a skipped folder is never listed (2026-10-29)."""
    recs = []
    home = _home()
    skip = skip_list(skip)

    ssh_dir = home / ".ssh"
    if skip.covers(ssh_dir) or not ssh_dir.exists():
        return recs

    # Check SSH key permissions
    for key_file in ssh_dir.glob("*"):
        if key_file.suffix == ".pub" or key_file.name in ("known_hosts", "config", "authorized_keys"):
            continue
        if not skip.covers(key_file) and key_file.is_file():
            mode = oct(key_file.stat().st_mode)[-3:]
            if mode != "600":
                recs.append(Recommendation(
                    category="auth",
                    severity="important",
                    title=f"SSH key {key_file.name} has loose permissions",
                    what=f"Your SSH key {key_file.name} has permissions {mode} (should be 600).",
                    why="Anyone who can read this file can impersonate you on every server you connect to.",
                    fix=f"chmod 600 {key_file}",
                    difficulty="easy",
                ))

    # Check authorized_keys
    auth_keys = ssh_dir / "authorized_keys"
    if not skip.covers(auth_keys) and auth_keys.exists():
        mode = oct(auth_keys.stat().st_mode)[-3:]
        if mode not in ("600", "644"):
            recs.append(Recommendation(
                category="auth",
                severity="important",
                title="authorized_keys has unusual permissions",
                what=f"~/.ssh/authorized_keys has permissions {mode}.",
                why="If writable by others, someone could add their key and log into your machine.",
                fix=f"chmod 644 {auth_keys}",
                difficulty="easy",
            ))

    # Check for password auth in SSH config
    sshd_config = Path("/etc/ssh/sshd_config")
    if sshd_config.exists():
        try:
            content = sshd_config.read_text()
            if re.search(r"^\s*PasswordAuthentication\s+yes", content, re.M):
                recs.append(Recommendation(
                    category="auth",
                    severity="important",
                    title="SSH allows password authentication",
                    what="Your SSH server accepts passwords, not just keys.",
                    why="Passwords can be brute-forced. Keys can't.",
                    fix="Edit /etc/ssh/sshd_config: set PasswordAuthentication no, then restart sshd.",
                    difficulty="moderate",
                ))
        except PermissionError:
            pass

    return recs


def check_firewall() -> list[Recommendation]:
    """Check if a firewall is active."""
    recs = []

    if _is_macos():
        output, rc = _run(["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"])
        if rc == 0 and output.strip() == "0":
            recs.append(Recommendation(
                category="network",
                severity="important",
                title="macOS firewall is disabled",
                what="Your Mac's built-in firewall is turned off.",
                why="Without a firewall, any program can accept incoming connections from the internet.",
                fix="System Settings → Network → Firewall → Turn On",
                difficulty="easy",
            ))
    elif _is_linux():
        ufw_output, rc = _run(["ufw", "status"])
        if rc == 0 and "inactive" in ufw_output.lower():
            recs.append(Recommendation(
                category="network",
                severity="important",
                title="UFW firewall is inactive",
                what="Your Linux firewall (ufw) is installed but not turned on.",
                why="Without a firewall, services you run are exposed to your network and possibly the internet.",
                fix="sudo ufw enable && sudo ufw default deny incoming && sudo ufw allow ssh",
                difficulty="easy",
            ))
        elif rc != 0:
            iptables_output, rc2 = _run(["iptables", "-L", "-n"])
            if rc2 == 0 and iptables_output.count("\n") < 5:
                recs.append(Recommendation(
                    category="network",
                    severity="suggested",
                    title="No firewall rules detected",
                    what="No iptables rules found and ufw isn't installed.",
                    why="Your machine may be accepting connections on any port.",
                    fix="sudo apt install ufw && sudo ufw enable && sudo ufw default deny incoming",
                    difficulty="easy",
                ))

    return recs


def check_open_ports() -> list[Recommendation]:
    """Check for services listening on all interfaces."""
    recs = []

    if _is_linux():
        output, rc = _run(["ss", "-tlnp"])
    elif _is_macos():
        output, rc = _run(["lsof", "-iTCP", "-sTCP:LISTEN", "-nP"])
    else:
        return recs

    if rc != 0:
        return recs

    wildcard_listeners = []
    for line in output.splitlines()[1:]:
        if "0.0.0.0:" in line or "::::" in line or "*:" in line:
            port_match = re.search(r"[:\*](\d+)", line)
            if port_match:
                port = port_match.group(1)
                if int(port) > 0:
                    wildcard_listeners.append((port, line.strip()[:100]))

    if wildcard_listeners:
        ports = ", ".join(p for p, _ in wildcard_listeners[:5])
        recs.append(Recommendation(
            category="network",
            severity="suggested",
            title=f"Services listening on all interfaces: {ports}",
            what=f"{len(wildcard_listeners)} services are accepting connections from any network interface.",
            why="If you're on a public network, anyone nearby can connect to these services.",
            fix="Configure services to listen on 127.0.0.1 (localhost only) unless they need to be public.",
            difficulty="moderate",
        ))

    return recs


def check_auto_updates() -> list[Recommendation]:
    """Check if automatic security updates are enabled."""
    recs = []

    if _is_linux():
        unattended = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        if unattended.exists():
            try:
                content = unattended.read_text()
                if '"0"' in content or not re.search(r'Unattended-Upgrade\s+"1"', content):
                    recs.append(Recommendation(
                        category="software",
                        severity="suggested",
                        title="Automatic security updates may be disabled",
                        what="Your system may not be installing security updates automatically.",
                        why="Unpatched vulnerabilities are the #1 way machines get compromised.",
                        fix="sudo dpkg-reconfigure unattended-upgrades",
                        difficulty="easy",
                    ))
            except PermissionError:
                pass
        else:
            recs.append(Recommendation(
                category="software",
                severity="suggested",
                title="Automatic updates not configured",
                what="No automatic update configuration found.",
                why="You're responsible for checking and installing every security patch manually.",
                fix="sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades",
                difficulty="easy",
            ))

    return recs


def check_sensitive_files(skip=None) -> list[Recommendation]:
    """Check for sensitive files with wrong permissions. skip: as check_ssh_config's; a file on the list, or linked
    into it, isn't looked up."""
    recs = []
    home = _home()
    skip = skip_list(skip)

    sensitive = [
        (home / ".env", "600", "Environment file with secrets"),
        (home / ".npmrc", "600", "npm config (may contain tokens)"),
        (home / ".netrc", "600", "Network credentials"),
        (home / ".docker" / "config.json", "600", "Docker credentials"),
        (home / ".kube" / "config", "600", "Kubernetes credentials"),
    ]

    for path, expected_mode, label in sensitive:
        if not skip.covers(path) and path.exists():
            actual = oct(path.stat().st_mode)[-3:]
            if actual != expected_mode and int(actual, 8) > int(expected_mode, 8):
                recs.append(Recommendation(
                    category="filesystem",
                    severity="important",
                    title=f"{label} has loose permissions",
                    what=f"{path} has permissions {actual} (should be {expected_mode}).",
                    why=f"Other users on this machine could read your {label.lower()}.",
                    fix=f"chmod {expected_mode} {path}",
                    difficulty="easy",
                ))

    return recs


def check_git_config() -> list[Recommendation]:
    """Check git configuration for privacy issues."""
    recs = []

    output, rc = _run(["git", "config", "--global", "user.email"])
    if rc == 0 and output:
        if "@users.noreply" not in output and "+" not in output:
            recs.append(Recommendation(
                category="privacy",
                severity="informational",
                title="Git commits use your real email",
                what=f"Your git commits contain your email: {output}",
                why="Every commit you push to a public repo exposes this email to scrapers and spam.",
                fix="git config --global user.email 'your-username@users.noreply.github.com'",
                difficulty="easy",
            ))

    return recs


def check_ollama_exposure() -> list[Recommendation]:
    """Check if Ollama is exposed beyond localhost."""
    recs = []

    if _is_linux():
        output, rc = _run(["ss", "-tlnp"])
    elif _is_macos():
        output, rc = _run(["lsof", "-iTCP", "-sTCP:LISTEN", "-nP"])
    else:
        return recs

    if rc != 0:
        return recs

    for line in output.splitlines():
        if "11434" in line and ("0.0.0.0" in line or ":::" in line or "*:11434" in line):
            recs.append(Recommendation(
                category="network",
                severity="important",
                title="Ollama is exposed to the network",
                what="Your Ollama instance is listening on all interfaces, not just localhost.",
                why="Anyone on your network can use your GPU for inference, and there's no authentication.",
                fix="Set OLLAMA_HOST=127.0.0.1:11434 in your Ollama config or systemd override.",
                difficulty="moderate",
            ))
            break

    return recs


# ── Main Advisor ──

class HardeningAdvisor:
    """Run all hardening checks and produce recommendations. skip: the folders not to enter, as for a scan (None: the
    user's skip list, a list of paths: added to it, as --skip is); what it kept the checks out of is in notes()."""

    ALL_CHECKS = [
        check_ssh_config,
        check_firewall,
        check_open_ports,
        check_auto_updates,
        check_sensitive_files,
        check_git_config,
        check_ollama_exposure,
    ]

    # The checks that read files under home, and so take the skip list
    HOME_CHECKS = (check_ssh_config, check_sensitive_files)

    def __init__(self, skip=None):
        self.skip = skip_list(skip)

    def assess(self) -> list[Recommendation]:
        """Run all checks and return recommendations."""
        recs = []
        for check_fn in self.ALL_CHECKS:
            try:
                recs.extend(check_fn(self.skip) if check_fn in self.HOME_CHECKS else check_fn())
            except Exception as e:
                logger.warning("Hardening check %s failed: %s", check_fn.__name__, e)
        return recs

    def notes(self) -> list:
        """What the skip list kept these checks out of, and what's wrong with the list, in its own words
        (sentinel/paths.py SkipList.notes), so a skip is never silent."""
        return ["%s. %s" % (title, description) for _severity, title, description, _fix, _details in self.skip.notes()]

    def report(self) -> str:
        """Generate a human-readable hardening report."""
        recs = self.assess()
        notes = self.notes()
        if not recs:
            if notes:
                return "\n".join(["No recommendations for what was checked."] + notes)
            return "Your machine looks well-configured. No recommendations at this time."

        lines = [
            "Hardening Recommendations",
            "=" * 40,
            f"{len(recs)} things to consider:\n",
        ]
        for sev in ["critical", "important", "suggested", "informational"]:
            sev_recs = [r for r in recs if r.severity == sev]
            for r in sev_recs:
                lines.append(r.human_readable())
                lines.append("")

        easy_count = sum(1 for r in recs if r.difficulty == "easy")
        if easy_count:
            lines.append(f"\n{easy_count} of these are quick fixes you can do right now.")

        if notes:
            lines.append("")
            lines.extend(notes)

        return "\n".join(lines)
