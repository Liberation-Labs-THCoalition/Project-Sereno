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

    @property
    def issues(self) -> list[Finding]:
        """Findings that ask for action: everything but info notes (2026-10-23: a machine whose only findings were
        notes, such as a loopback listener, read as "issues found")."""
        return [f for f in self.findings if f.severity != "info"]

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
        notes = len(self.findings) - len(self.issues)
        if not self.findings:
            lines.append("No issues found. Your machine looks clean.")
        elif not self.issues:
            lines.append(f"No issues found. {notes} note{'s' if notes != 1 else ''} below, for your information:\n")
        else:
            n = len(self.issues)
            lines.append(f"{n} issue{'s' if n != 1 else ''} found"
                         + (f", and {notes} note{'s' if notes != 1 else ''}" if notes else "") + ":\n")
        # Notes print too when they're all there is (2026-10-24: "7 notes below" was followed by nothing)
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

    scopes = set(known_bad.get("scopes", []))
    listed = known_bad.get("packages", {})
    for nm_dir in node_modules_dirs:
        try:
            entries = list(nm_dir.iterdir())
        except OSError:
            continue
        candidates = []
        for entry in entries:
            if entry.name.startswith("@") and entry.is_dir():
                try:
                    candidates += [(f"{entry.name}/{pkg.name}", pkg, entry.name) for pkg in entry.iterdir()]
                except OSError:
                    continue
            elif entry.name in listed:
                candidates.append((entry.name, entry, None))
        for full_name, pkg, scope in candidates:
            if full_name not in listed and scope not in scopes:
                continue
            version = _npm_version(pkg)
            finding = _npm_verdict(full_name, version, listed.get(full_name), scope in scopes)
            if finding:
                severity, title, description, remediation = finding
                findings.append(Finding(check="supply_chain_npm", severity=severity, title=title,
                                        description=description.format(where=nm_dir), remediation=remediation,
                                        details={"path": str(pkg), "version": version}))

    return findings


NPM_COMPROMISED_STEPS = (
    "1. Disconnect from the internet immediately.\n"
    "2. Do NOT revoke tokens from this machine (dead man's switch).\n"
    "3. From a DIFFERENT device, revoke all npm/GitHub tokens.\n"
    "4. Delete the node_modules directory and reinstall from a clean lockfile.\n"
    "5. Rotate ALL credentials on this machine.")


def _npm_version(pkg: Path) -> str:
    try:
        return str(json.loads((pkg / "package.json").read_text()).get("version", "unknown"))
    except (OSError, ValueError, AttributeError):
        return "unknown"


def _npm_verdict(name: str, version: str, bad_versions, scope_listed: bool):
    """(severity, title, description, remediation) for one installed npm package, or None. How sure the feed is decides
    the severity (2026-10-23): an exact bad version is critical; a package listed without versions is high; a package
    that's only under a listed scope is medium, because scopes are broad and most of their packages are fine (every
    @tanstack package used to be called critical)."""
    if bad_versions is not None and version in bad_versions:
        return ("critical", f"Compromised package: {name}@{version}",
                f"The package {name} version {version} was found in {{where}}. This version is on the "
                f"known-compromised list. It may contain malware that steals credentials and spreads to other projects.",
                NPM_COMPROMISED_STEPS)
    if bad_versions is not None and not any(bad_versions):
        return ("high", f"Package with compromised releases: {name}@{version}",
                f"{name} is on Sereno's list without specific versions, found in {{where}}. Check {version} against "
                f"the package's security advisory (osv.dev lists them).",
                "If your version is a bad one, follow the steps for a compromised package: disconnect, revoke tokens "
                "from another device, reinstall from a clean lockfile, rotate credentials.")
    if bad_versions and version == "unknown":
        return ("medium", f"Listed package with an unreadable version: {name}",
                f"{name} has known-compromised versions and is in {{where}}, but Sereno couldn't read its "
                f"package.json to see which version this is.",
                f"Run `npm ls {name}` in that project and compare the version with: {', '.join(bad_versions)}.")
    if bad_versions is None and scope_listed:
        return ("medium", f"Package from a scope that had compromised releases: {name}@{version}",
                f"Some packages under {name.split('/')[0]} had compromised releases, and {name} {version} is in "
                f"{{where}}. Most packages under a listed scope are fine: compare your version with the advisory.",
                "Look up the scope's advisory (osv.dev); only act if your exact version is named there.")
    return None


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

    # Payload files. Distinctive names are the worm's own and are critical anywhere outside node_modules. Generic
    # names (setup.mjs, sysmon.py) are common in ordinary projects, so they're critical only with corroboration: a
    # distinctive payload in the same folder, or content that names one. Otherwise they're info (2026-10-23: a plain
    # setup.mjs or a homemade sysmon.py was called critical malware).
    sysmon_safe_parents = {"coverage", "sysmon", "psutil", "watchdog"}
    for name in PAYLOAD_DISTINCTIVE:
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
    for name in PAYLOAD_GENERIC:
        for found in home.rglob(name):
            # The skips main had, per name: setup.mjs outside node_modules, sysmon.py outside site-packages and
            # known tools' folders
            if name == "setup.mjs" and "node_modules" in str(found):
                continue
            if name == "sysmon.py" and ("site-packages" in str(found)
                                        or any(safe in str(found.parent) for safe in sysmon_safe_parents)):
                continue
            if _payload_corroborated(found):
                findings.append(Finding(
                    check="persistence",
                    severity="critical",
                    title=f"Malware payload found: {name}",
                    description=f"Found {found}, alongside or naming the Shai-Hulud worm's other payload files.",
                    remediation="Disconnect from internet, revoke tokens from another device, then delete.",
                    details={"path": str(found)},
                ))
            else:
                findings.append(Finding(
                    check="persistence",
                    severity="info",
                    title=f"A file named like a worm payload: {found}",
                    description=(f"The Shai-Hulud worm used the name {name}, but it's also a common name, and nothing "
                                 f"else here points to the worm. Look at it if you don't recognise it."),
                    remediation="",
                    details={"path": str(found)},
                ))

    # Claude Code settings: hooks and API-endpoint overrides, user-level and in project folders (sentinel/claude_settings.py)
    from .claude_settings import check_claude_settings

    def make(severity, title, description, remediation, details):
        return Finding(check="persistence", severity=severity, title=title, description=description,
                       remediation=remediation, details=details)
    findings.extend(check_claude_settings(make, home))

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


PAYLOAD_DISTINCTIVE = ("router_runtime.js", "router_init.js", "tanstack_runner.js")
PAYLOAD_GENERIC = ("setup.mjs", "sysmon.py")


def _payload_corroborated(path: Path) -> bool:
    """A generic payload name counts as the worm's when a distinctive payload sits in the same folder, or the file
    names one (or the worm's token monitor)."""
    if any((path.parent / n).exists() for n in PAYLOAD_DISTINCTIVE):
        return True
    try:
        text = path.read_text(errors="replace")[:200_000]
    except OSError:
        return False
    return any(n in text for n in PAYLOAD_DISTINCTIVE + ("gh-token-monitor",))


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


def _loopback(host: str) -> bool:
    from .listeners import loopback
    return loopback(host)


def check_network() -> list[Finding]:
    """Listening ports, TCP and UDP, each tied to its program and binary where visible and named when it's a known
    service (sentinel/listeners.py, 2026-10-24). TCP: every listener except 22, 80 and 443, low ports included. Open to
    other machines: medium, or high for remote control (a remote desktop, or SSH off port 22) whatever the port; bound
    to this machine only (127.x, ::1): info. UDP: services on ports at or below 1024 open to other machines, beyond the
    common client ones, and remote control's own UDP ports. Tailscale's listeners on its tailnet addresses: info."""
    from .listeners import check_listeners
    findings = []
    expected, problem = _expected_ports()
    if problem is not None:
        findings.append(problem)
    if not (_is_linux() or _is_macos()):
        return findings

    def make(severity, title, description, remediation, details):
        return Finding(check="network", severity=severity, title=title, description=description,
                       remediation=remediation, details=details)
    findings.extend(check_listeners(make, _run, _is_macos(), expected))
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

CHECK_NAMES = ("npm_supply_chain", "pip_supply_chain", "persistence", "processes", "network", "credentials",
               "git_repos", "mcp_servers")

class SentinelScanner:
    """The main scanner orchestrator."""

    def __init__(self, checks: list[str] | None = None) -> None:
        self._checks = checks or list(CHECK_NAMES)
        unknown = [c for c in self._checks if c not in CHECK_NAMES]
        if unknown:
            # A misspelled name used to run nothing and report clean
            raise ValueError("unknown check name(s): %s; the checks are: %s" % (", ".join(unknown), ", ".join(CHECK_NAMES)))

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
            fn = check_map[check_name]
            try:
                result.checks_run += 1
                findings = fn()
                if findings:
                    result.findings.extend(findings)
                else:
                    result.checks_clean += 1
            except Exception as e:
                # A check that couldn't run checked nothing, so the result must not read as clean (2026-10-23: a
                # crash was only logged, and the scan still said "Your machine looks clean")
                logger.warning("Check %s failed: %s", check_name, e)
                result.findings.append(Finding(
                    check=check_name,
                    severity="high",
                    title=f"Check couldn't run: {check_name}",
                    description=f"The {check_name} check stopped with an error ({type(e).__name__}: {str(e)[:200]}), "
                                f"so nothing it looks for was checked.",
                    remediation="Run it again; if it keeps failing, report it with this message.",
                    details={"error": f"{type(e).__name__}: {e}"},
                ))

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
