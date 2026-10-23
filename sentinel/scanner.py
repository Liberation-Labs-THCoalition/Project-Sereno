"""Sentinel Scanner — the core sweep engine.

Runs a battery of security checks against the local machine and reports
findings in plain language. Designed to run as a cron job on anything
from a Raspberry Pi to a Mac Studio.

No cloud services. No accounts. No telemetry. Everything local.

Checks:
  1. Supply chain: compromised npm/pip packages against known-bad lists
  2. Persistence: hooks, services, launch agents, scheduled tasks, .pth files
  3. Process: unexpected listeners, suspicious process trees
  4. Credentials: exposed tokens, keys in common locations
  5. File integrity: changes to critical system/config files
  6. Network: unexpected listening ports, suspicious connections

Each check returns a Finding with severity, plain-language description,
and step-by-step remediation.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import re
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A single security finding."""
    check: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    remediation: str = ""
    details: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def human_readable(self) -> str:
        """Format for someone who doesn't speak security."""
        icons = {"critical": "!!!", "high": "!!", "medium": "!", "low": "~", "info": "."}
        icon = icons.get(self.severity, "?")
        lines = [f"[{icon}] {self.title}"]
        lines.append(f"    {self.description}")
        if self.remediation:
            lines.append(f"    Fix: {self.remediation}")
        return "\n".join(lines)


@dataclass
class ScanResult:
    """Complete scan results."""
    hostname: str
    platform: str
    scan_time: str
    duration_ms: float
    findings: list[Finding] = field(default_factory=list)
    checks_run: int = 0
    checks_clean: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def summary(self) -> str:
        total = len(self.findings)
        if total == 0:
            return f"All clear. {self.checks_run} checks passed on {self.hostname}."
        parts = [f"{total} findings on {self.hostname}:"]
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for f in self.findings if f.severity == sev)
            if count:
                parts.append(f"  {count} {sev}")
        return "\n".join(parts)

    def human_report(self) -> str:
        """Full human-readable report."""
        lines = [
            f"Security Scan — {self.hostname}",
            f"{'=' * 40}",
            f"Time: {self.scan_time}",
            f"Platform: {self.platform}",
            f"Checks: {self.checks_run} run, {self.checks_clean} clean",
            "",
        ]
        if not self.findings:
            lines.append("No issues found. Your machine looks clean.")
        else:
            lines.append(f"{len(self.findings)} issues found:\n")
            for sev in ["critical", "high", "medium", "low", "info"]:
                sev_findings = [f for f in self.findings if f.severity == sev]
                for f in sev_findings:
                    lines.append(f.human_readable())
                    lines.append("")
        return "\n".join(lines)


def _run(cmd: list[str], timeout: int = 30) -> tuple[str, int]:
    """Run a command safely, return (stdout, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip(), result.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return "", -1


def _home() -> Path:
    return Path.home()


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _is_wsl() -> bool:
    if not _is_linux():
        return False
    try:
        return "microsoft" in Path("/proc/version").read_text().lower()
    except Exception:
        return False


# ── Check: Supply Chain (npm) ──

def check_npm_supply_chain(known_bad: dict | None = None) -> list[Finding]:
    """Scan node_modules for known-compromised packages."""
    findings = []
    if known_bad is None:
        known_bad = load_known_bad_npm()

    if not known_bad:
        return findings

    home = _home()
    node_modules_dirs = []
    for search_root in [home]:
        for nm in search_root.rglob("node_modules"):
            if nm.is_dir() and "node_modules/node_modules" not in str(nm):
                node_modules_dirs.append(nm)

    for nm_dir in node_modules_dirs:
        for scope_or_pkg in nm_dir.iterdir():
            if scope_or_pkg.name.startswith("@") and scope_or_pkg.is_dir():
                scope = scope_or_pkg.name
                if scope in known_bad.get("scopes", []):
                    for pkg in scope_or_pkg.iterdir():
                        pkg_json = pkg / "package.json"
                        if pkg_json.exists():
                            try:
                                data = json.loads(pkg_json.read_text())
                                version = data.get("version", "unknown")
                                full_name = f"{scope}/{pkg.name}"
                                bad_versions = known_bad.get("packages", {}).get(full_name, [])
                                if not bad_versions or version in bad_versions:
                                    findings.append(Finding(
                                        check="supply_chain_npm",
                                        severity="critical",
                                        title=f"Compromised package: {full_name}@{version}",
                                        description=(
                                            f"The package {full_name} version {version} was found in "
                                            f"{nm_dir}. This package is on the known-compromised list. "
                                            f"It may contain malware that steals credentials and spreads "
                                            f"to other projects."
                                        ),
                                        remediation=(
                                            "1. Disconnect from the internet immediately.\n"
                                            "2. Do NOT revoke tokens from this machine (dead man's switch).\n"
                                            "3. From a DIFFERENT device, revoke all npm/GitHub tokens.\n"
                                            "4. Delete the node_modules directory and reinstall from a clean lockfile.\n"
                                            "5. Rotate ALL credentials on this machine."
                                        ),
                                        details={"path": str(pkg), "version": version},
                                    ))
                            except (json.JSONDecodeError, OSError):
                                continue
            elif scope_or_pkg.name in known_bad.get("packages", {}):
                findings.append(Finding(
                    check="supply_chain_npm",
                    severity="high",
                    title=f"Suspicious package: {scope_or_pkg.name}",
                    description=f"Package {scope_or_pkg.name} found in {nm_dir}.",
                    details={"path": str(scope_or_pkg)},
                ))

    return findings


# ── Check: Supply Chain (pip) ──

def check_pip_supply_chain(known_bad: dict | None = None) -> list[Finding]:
    """Check installed pip packages against known-compromised list."""
    findings = []
    if known_bad is None:
        known_bad = load_known_bad_pip()

    if not known_bad:
        return findings

    pip_list, rc = _run(["pip3", "list", "--format=json"])
    if rc != 0:
        pip_list, rc = _run(["pip", "list", "--format=json"])
    if rc != 0:
        return findings

    try:
        packages = json.loads(pip_list)
    except json.JSONDecodeError:
        return findings

    for pkg in packages:
        name = pkg.get("name", "").lower()
        version = pkg.get("version", "")
        bad_versions = known_bad.get(name)
        if name.startswith("_") or bad_versions is None:
            continue
        # An empty list means "had compromised releases, versions not listed". Until 2026-10-23 such entries were
        # skipped entirely, so a clean result said nothing about them.
        exact = version in bad_versions
        if any(bad_versions) and not exact:
            continue
        if exact:
            findings.append(Finding(
                check="supply_chain_pip",
                severity="critical",
                title=f"Compromised pip package: {name}=={version}",
                description=(
                    f"The package {name} version {version} is on the known-compromised list. "
                    f"It may contain malware."
                ),
                remediation=f"Run: pip uninstall {name} && pip install {name}==(known good version)",
                details={"package": name, "version": version},
            ))
        else:
            findings.append(Finding(
                check="supply_chain_pip",
                severity="high",
                title=f"Package with compromised releases: {name}=={version}",
                description=(
                    f"{name} had compromised releases, and Sereno's list doesn't say which versions. "
                    f"Check {version} against the package's security advisory."
                ),
                remediation=f"Look up {name}'s advisory (osv.dev lists them) and upgrade past any bad version.",
                details={"package": name, "version": version, "versions_listed": False},
            ))

    return findings


# ── Check: Persistence Mechanisms ──

def check_persistence() -> list[Finding]:
    """Check for known malware persistence mechanisms."""
    findings = []
    home = _home()

    # gh-token-monitor (Shai-Hulud specific)
    persistence_paths = [
        (home / ".local/bin/gh-token-monitor.sh", "critical", "Shai-Hulud token monitor script"),
        (home / ".config/gh-token-monitor", "critical", "Shai-Hulud token monitor config"),
    ]

    if _is_linux():
        persistence_paths.append(
            (home / ".config/systemd/user/gh-token-monitor.service", "critical",
             "Shai-Hulud systemd persistence")
        )

    if _is_macos():
        persistence_paths.append(
            (home / "Library/LaunchAgents/com.user.gh-token-monitor.plist", "critical",
             "Shai-Hulud LaunchAgent persistence")
        )

    for path, severity, label in persistence_paths:
        if path.exists():
            findings.append(Finding(
                check="persistence",
                severity=severity,
                title=f"Malware persistence found: {label}",
                description=(
                    f"Found {path}. This is a known malware persistence mechanism. "
                    f"DO NOT delete it yet — see remediation steps."
                ),
                remediation=(
                    "1. DISCONNECT from the internet immediately.\n"
                    "2. From a DIFFERENT device, revoke all GitHub/npm tokens.\n"
                    "3. Then remove this file and associated processes.\n"
                    "4. Rotate ALL credentials."
                ),
                details={"path": str(path)},
            ))

    # Payload files — check name AND location context
    payload_names = ["router_runtime.js", "router_init.js", "setup.mjs", "tanstack_runner.js"]
    # sysmon.py is only suspicious outside of known-safe locations (e.g. coverage package)
    sysmon_safe_parents = {"coverage", "sysmon", "psutil", "watchdog"}

    for name in payload_names:
        for found in home.rglob(name):
            if "node_modules" in str(found):
                continue
            findings.append(Finding(
                check="persistence",
                severity="critical",
                title=f"Malware payload found: {name}",
                description=f"Found {found}. This is a known Shai-Hulud payload file.",
                remediation="Disconnect from internet, revoke tokens from another device, then delete.",
                details={"path": str(found)},
            ))

    for found in home.rglob("sysmon.py"):
        if any(safe in str(found.parent) for safe in sysmon_safe_parents):
            continue
        if "site-packages" in str(found):
            continue
        findings.append(Finding(
            check="persistence",
            severity="critical",
            title="Malware payload found: sysmon.py",
            description=f"Found {found}. This may be a Shai-Hulud payload file.",
            remediation="Disconnect from internet, revoke tokens from another device, then delete.",
            details={"path": str(found)},
        ))

    # Claude Code hook injection
    claude_settings = home / ".claude" / "settings.json"
    if claude_settings.exists():
        try:
            data = json.loads(claude_settings.read_text())
            hooks = data.get("hooks", {})
            for event_type, hook_list in hooks.items():
                if isinstance(hook_list, list):
                    for hook_group in hook_list:
                        for hook in hook_group.get("hooks", []):
                            cmd = hook.get("command", "")
                            if any(sus in cmd.lower() for sus in [
                                "router_init", "tanstack", "shai", "token-monitor",
                                "curl ", "wget ", "nc ", "base64",
                            ]):
                                findings.append(Finding(
                                    check="persistence",
                                    severity="critical",
                                    title=f"Suspicious Claude Code hook: {event_type}",
                                    description=f"Hook command looks malicious: {cmd[:100]}",
                                    remediation="Remove the hook from .claude/settings.json",
                                    details={"event": event_type, "command": cmd},
                                ))
        except (json.JSONDecodeError, OSError):
            pass

    # VS Code task injection
    for tasks_json in home.rglob(".vscode/tasks.json"):
        try:
            content = tasks_json.read_text()
            if any(sus in content.lower() for sus in [
                "router_init", "tanstack_runner", "gh-token-monitor",
            ]):
                findings.append(Finding(
                    check="persistence",
                    severity="critical",
                    title="Suspicious VS Code task",
                    description=f"Found suspicious task in {tasks_json}",
                    remediation="Review and remove the malicious task entry.",
                    details={"path": str(tasks_json)},
                ))
        except OSError:
            continue

    # Python startup hooks: a .pth line starting with "import" runs at every interpreter start, and so does a
    # sitecustomize.py or usercustomize.py. litellm 1.107.0's malware (2026-10-21) used a .pth whose only line was
    # `import cook`, which the old exec()/eval() keyword check couldn't see.
    pths, customizes = _startup_files(home)
    for pth in pths:
        try:
            content = pth.read_text(errors="replace")
        except OSError:
            continue
        severity, reason = pth_verdict(pth.name, content)
        if severity:
            findings.append(Finding(
                check="persistence",
                severity=severity,
                title=f"Python startup file runs code: {pth.name}",
                description=(f"{pth} {reason} Python runs it every time it starts in that environment. "
                             f"Legitimate packages occasionally do this, so look before you act."),
                remediation=(f"Check which package installed {pth.name} (pip show, or look for a matching "
                             f"*.dist-info folder beside it). If you don't recognise it, remove it and the package, "
                             f"then treat that environment's secrets as exposed."),
                details={"path": str(pth), "content": content[:200]},
            ))
    for f in customizes:
        findings.append(Finding(
            check="persistence",
            severity="high",
            title=f"Python startup file: {f}",
            description=(f"Python imports {f.name} every time it starts in that environment, and most "
                         f"environments have none. litellm 1.107.0's malware installed one as an hourly "
                         f"remote code loader."),
            remediation=f"Read {f}. If you didn't put it there, remove it and treat that environment's secrets "
                        f"as exposed.",
            details={"path": str(f)},
        ))

    return findings


# Startup hooks that are normal, recognised by name AND content, so a file can't pass by borrowing a name.
_PTH_SAFE = [
    (re.compile(r"^_virtualenv\.pth$"), re.compile(r"^import _virtualenv\s*$")),
    (re.compile(r"^distutils-precedence\.pth$"), re.compile(r"SETUPTOOLS_USE_DISTUTILS")),
    (re.compile(r"^__editable__\..*\.pth$"),
     re.compile(r"^import (__editable___\w+_finder); \1\.install\([^()]*\)\s*$")),
    (re.compile(r"coverage.*\.pth$"), re.compile(r"COVERAGE_PROCESS_START")),
    (re.compile(r"^pytest-cov\.pth$"), re.compile(r"COV_CORE_SOURCE")),
    (re.compile(r"-nspkg\.pth$"), re.compile(r"sys\.modules\.setdefault|importlib\.util|types\.ModuleType")),
    (re.compile(r"^coloredlogs\.pth$"), re.compile(r"coloredlogs")),
]
_PTH_RISKY = re.compile(r"exec\(|eval\(|compile\(|base64|b64decode|zlib|marshal|subprocess|os\.system|"
                        r"urllib|socket|http\.client|__import__")


def _startup_files(home: Path):
    """(.pth files, sitecustomize/usercustomize files) inside site-packages or dist-packages under home, found in ONE
    walk (one walk per pattern would multiply the time on a Pi). Links aren't followed; node_modules and .git are
    skipped."""
    pths, customizes = [], []
    for dirpath, dirnames, filenames in os.walk(str(home), followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git")]
        if "site-packages" not in dirpath and "dist-packages" not in dirpath:
            continue
        for f in filenames:
            if f.endswith(".pth"):
                pths.append(Path(dirpath) / f)
            elif f in ("sitecustomize.py", "usercustomize.py"):
                customizes.append(Path(dirpath) / f)
    return pths, customizes


def pth_verdict(name: str, content: str):
    """(severity, reason) for a .pth file, or (None, "") when it runs nothing or is a known-normal hook."""
    imports = [line for line in content.splitlines() if re.match(r"^import[ \t]", line)]
    if not imports:
        return None, ""  # path lines only: Python adds them to sys.path and runs nothing
    for name_re, content_re in _PTH_SAFE:
        if name_re.search(name) and all(content_re.search(line) for line in imports):
            return None, ""
    if _PTH_RISKY.search(content):
        return "high", "has an import line that runs code (exec, decoding, a shell or the network)."
    return "high", "has an import line, which runs code."


# ── Check: Processes ──

def check_processes() -> list[Finding]:
    """Check for suspicious running processes."""
    findings = []

    output, rc = _run(["ps", "aux"])
    if rc != 0:
        return findings

    suspicious_patterns = [
        (r"gh-token-monitor", "critical", "Shai-Hulud token monitor daemon"),
        (r"router_init\.js", "critical", "Shai-Hulud payload process"),
        (r"tanstack_runner", "critical", "Shai-Hulud runner process"),
        (r"sysmon\.py", "high", "Suspicious sysmon process"),
        (r"cryptominer|xmrig|minerd", "high", "Possible cryptominer"),
        (r"reverse.shell|revshell|nc -e|bash -i >& /dev/tcp", "critical", "Possible reverse shell"),
    ]

    for line in output.splitlines():
        for pattern, severity, label in suspicious_patterns:
            if re.search(pattern, line, re.I):
                # Filter out our own grep/scan commands
                if "grep" in line or "pgrep" in line or "scanner.py" in line:
                    continue
                findings.append(Finding(
                    check="processes",
                    severity=severity,
                    title=f"Suspicious process: {label}",
                    description=f"Found: {line.strip()[:150]}",
                    remediation="Investigate this process. If not recognized, disconnect from network and kill it.",
                    details={"process_line": line.strip()},
                ))

    return findings


# ── Check: Network ──

def _expected_ports() -> tuple:
    """(ports the operator runs on purpose, a Finding when expected.json can't be read). Ports compare as strings."""
    from .paths import sentinel_home
    path = sentinel_home() / "expected.json"
    if not path.exists():
        return set(), None
    try:
        data = json.loads(path.read_text())
        return {str(p) for p in data.get("ports", [])}, None
    except (OSError, ValueError, AttributeError, TypeError) as e:
        return set(), Finding(check="network", severity="medium", title="expected.json unreadable",
                              description=f"{path} could not be read ({type(e).__name__}), so no port is treated as expected.",
                              remediation=f"Fix or remove {path}.", details={"path": str(path)})


def check_network() -> list[Finding]:
    """Check for unexpected listening ports and connections."""
    findings = []
    expected, problem = _expected_ports()
    if problem is not None:
        findings.append(problem)

    if _is_linux() or _is_macos():
        if _is_macos():
            output, rc = _run(["lsof", "-iTCP", "-sTCP:LISTEN", "-nP"])
        else:
            output, rc = _run(["ss", "-tlnp"])

        if rc == 0 and output:
            known_safe_ports = {"22", "80", "443"}
            for line in output.splitlines()[1:]:
                parts = line.split()
                for part in parts:
                    port_match = re.search(r":(\d+)", part)
                    if port_match:
                        port = port_match.group(1)
                        if port not in known_safe_ports and int(port) > 1024:
                            if port in expected:
                                findings.append(Finding(
                                    check="network",
                                    severity="info",
                                    title=f"Listening port {port} (expected by operator)",
                                    description=f"Port {port} is listed in expected.json. Line: {line.strip()[:120]}",
                                    remediation="",
                                    details={"port": port, "line": line.strip(), "expected": True},
                                ))
                            else:
                                findings.append(Finding(
                                    check="network",
                                    severity="medium",
                                    title=f"Unexpected listening port: {port}",
                                    description=f"Something is listening on port {port}. Line: {line.strip()[:120]}",
                                    remediation=f"Check what's using port {port}. If you don't recognize it, investigate.",
                                    details={"port": port, "line": line.strip()},
                                ))
                        break

    return findings


# ── Check: Credential Exposure ──

def check_credentials() -> list[Finding]:
    """Check for exposed credentials in common locations."""
    findings = []
    home = _home()

    # .npmrc with tokens
    npmrc = home / ".npmrc"
    if npmrc.exists():
        try:
            content = npmrc.read_text()
            if "authToken" in content or "_auth" in content:
                findings.append(Finding(
                    check="credentials",
                    severity="high",
                    title="npm authentication token exposed",
                    description=f"Found authentication tokens in {npmrc}. If compromised, attackers can publish packages under your name.",
                    remediation="Rotate your npm tokens at npmjs.com and update .npmrc.",
                    details={"path": str(npmrc)},
                ))
        except OSError:
            pass

    # .env files with secrets
    for env_file in home.rglob(".env"):
        if "node_modules" in str(env_file) or ".git" in str(env_file):
            continue
        try:
            content = env_file.read_text()
            secret_patterns = [
                (r"(?i)(api.?key|secret|token|password)\s*=\s*\S+", "API key or secret"),
                (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key"),
                (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal access token"),
                (r"npm_[a-zA-Z0-9]{36}", "npm token"),
                (r"AKIA[0-9A-Z]{16}", "AWS access key"),
            ]
            for pattern, label in secret_patterns:
                if re.search(pattern, content):
                    findings.append(Finding(
                        check="credentials",
                        severity="medium",
                        title=f"Credentials in .env file: {label}",
                        description=f"Found what looks like a {label} in {env_file}. Make sure this file isn't committed to git or accessible to other users.",
                        remediation="Ensure .env is in .gitignore. Consider using a secrets manager.",
                        details={"path": str(env_file), "type": label},
                    ))
                    break
        except OSError:
            continue

    return findings


# ── Check: Git Repository Safety ──

def check_git_repos() -> list[Finding]:
    """Check local git repos for signs of compromise."""
    findings = []
    home = _home()

    dune_patterns = re.compile(r"shai.?hulud|arrakis|spice|sandworm|fremen|muad.?dib", re.I)

    for git_dir in home.rglob(".git"):
        if not git_dir.is_dir():
            continue
        repo = git_dir.parent
        branches, rc = _run(["git", "-C", str(repo), "branch", "-a"])
        if rc == 0 and dune_patterns.search(branches):
            findings.append(Finding(
                check="git_repos",
                severity="critical",
                title=f"Shai-Hulud exfiltration branch in {repo.name}",
                description=f"Found Dune-themed git branch in {repo}. The Shai-Hulud worm uses these branches to exfiltrate stolen data.",
                remediation="Do NOT push. Delete the branch locally. Revoke all tokens from a different device.",
                details={"repo": str(repo)},
            ))

    return findings


# ── Threat Feed Loading ──

def load_known_bad_npm() -> dict:
    """Load known-bad npm packages from the threat feed."""
    feed_path = Path(__file__).parent.parent / "feeds" / "npm_known_bad.json"
    if feed_path.exists():
        try:
            return json.loads(feed_path.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def load_known_bad_pip() -> dict:
    """Load known-bad pip packages from the threat feed."""
    feed_path = Path(__file__).parent.parent / "feeds" / "pip_known_bad.json"
    if feed_path.exists():
        try:
            return json.loads(feed_path.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


# ── Check: MCP servers (sentinel/mcp.py) ──

def check_mcp() -> list[Finding]:
    """MCP servers launched with no fixed version, and MCP configs holding secrets in plain text."""
    from .mcp import check_mcp_servers

    def make(severity, title, description, remediation, details):
        return Finding(check="mcp_servers", severity=severity, title=title, description=description,
                       remediation=remediation, details=details)
    return check_mcp_servers(make, _home(), load_known_bad_npm(), load_known_bad_pip())


# ── Main Scanner ──

class SentinelScanner:
    """The main scanner orchestrator."""

    def __init__(self, checks: list[str] | None = None) -> None:
        self._checks = checks or [
            "npm_supply_chain", "pip_supply_chain", "persistence",
            "processes", "network", "credentials", "git_repos", "mcp_servers",
        ]

    def scan(self) -> ScanResult:
        """Run all enabled checks and return results."""
        t0 = time.time()
        hostname = platform.node()
        plat = f"{platform.system()} {platform.release()}"

        result = ScanResult(
            hostname=hostname,
            platform=plat,
            scan_time=datetime.now(timezone.utc).isoformat(),
            duration_ms=0,
        )

        check_map = {
            "npm_supply_chain": check_npm_supply_chain,
            "pip_supply_chain": check_pip_supply_chain,
            "persistence": check_persistence,
            "processes": check_processes,
            "network": check_network,
            "credentials": check_credentials,
            "git_repos": check_git_repos,
            "mcp_servers": check_mcp,
        }

        for check_name in self._checks:
            fn = check_map.get(check_name)
            if fn is None:
                continue
            try:
                result.checks_run += 1
                findings = fn()
                if findings:
                    result.findings.extend(findings)
                else:
                    result.checks_clean += 1
            except Exception as e:
                logger.warning("Check %s failed: %s", check_name, e)

        result.duration_ms = (time.time() - t0) * 1000
        return result

    def scan_and_report(self) -> str:
        """Scan and return a human-readable report."""
        result = self.scan()
        return result.human_report()

    def scan_to_json(self, output_path: str = "") -> str:
        """Scan and save results as JSON."""
        result = self.scan()
        data = asdict(result)
        if output_path:
            Path(output_path).write_text(json.dumps(data, indent=2))
        return json.dumps(data, indent=2)
