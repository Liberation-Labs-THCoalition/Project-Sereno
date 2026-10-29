"""Skill Engine — typed, composable, proactive security operations.

Skills are the hands. The BDI loop is the mind. The model is the voice.

Each skill has typed input/output, can be composed into chains, and
can be triggered proactively by the belief engine. The model never
fabricates findings because every claim routes through verify().

Architecture:
  Beliefs (system state) → Desires (security goals) → Intentions (skill chains)
  Skills produce grounded data → Model translates for humans

Skill types:
  Sensor:    observe system state → Observation
  Analyzer:  interpret observations → Assessment
  Verifier:  check claims against data → bool
  Advisor:   generate recommendations → [Action]
  Actuator:  execute actions → Result
  Reporter:  translate for humans → Report
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .paths import sentinel_home

logger = logging.getLogger(__name__)


# ── Typed data structures ──

@dataclass
class Observation:
    """Raw data from a sensor skill."""
    source: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data: dict = field(default_factory=dict)
    raw_output: str = ""


@dataclass
class Assessment:
    """Interpreted observation — what does this mean?"""
    severity: str = "info"  # critical, high, medium, low, info
    title: str = ""
    details: str = ""
    grounded_in: list[str] = field(default_factory=list)
    confidence: float = 1.0


@dataclass
class Action:
    """A recommended remediation step."""
    description: str
    command: str = ""
    difficulty: str = "easy"
    requires_approval: bool = True


@dataclass
class SkillResult:
    """Output of any skill execution."""
    skill: str
    success: bool
    observations: list[Observation] = field(default_factory=list)
    assessments: list[Assessment] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    raw: str = ""
    duration_ms: float = 0.0


# ── Skill definitions ──

class Skill:
    """A single typed, executable skill."""
    def __init__(
        self,
        name: str,
        category: str,
        description: str,
        execute_fn: Callable[..., SkillResult],
    ) -> None:
        self.name = name
        self.category = category
        self.description = description
        self._execute = execute_fn

    def run(self, **kwargs) -> SkillResult:
        t0 = time.time()
        try:
            result = self._execute(**kwargs)
            result.duration_ms = (time.time() - t0) * 1000
            return result
        except Exception as e:
            logger.error("Skill %s failed: %s", self.name, e)
            return SkillResult(skill=self.name, success=False, raw=str(e))


# ── Sensor skills ──

HARDENING_SEVERITY = {"critical": "critical", "important": "high", "suggested": "medium", "informational": "info"}


def _findings_to_result(skill: str, checks: list[str]) -> SkillResult:
    """Run the scanner in-process on these checks; one Assessment per Finding (rollout spec S2)."""
    from .scanner import SentinelScanner
    result = SentinelScanner(checks=checks).scan()
    assessments = [Assessment(severity=f.severity, title=f.title, details=f.description, grounded_in=[f.check])
                   for f in result.findings]
    obs = Observation(source=skill, data={"findings_count": len(result.findings)})
    raw = "\n".join(f.human_readable() for f in result.findings)   # what a chained verify_claim reads
    return SkillResult(skill=skill, success=True, observations=[obs], assessments=assessments, raw=raw)


def _scan_packages(**kwargs) -> SkillResult:
    """Scan installed packages against known-bad lists."""
    try:
        return _findings_to_result("scan_packages", ["npm_supply_chain", "pip_supply_chain", "mcp_servers"])
    except Exception as e:
        return SkillResult(skill="scan_packages", success=False, raw=str(e))


def _scan_persistence(**kwargs) -> SkillResult:
    """Check for malware persistence mechanisms."""
    try:
        return _findings_to_result("scan_persistence", ["persistence", "processes"])
    except Exception as e:
        return SkillResult(skill="scan_persistence", success=False, raw=str(e))


def _scan_network(**kwargs) -> SkillResult:
    """Check network listeners and connections."""
    try:
        return _findings_to_result("scan_network", ["network", "credentials"])
    except Exception as e:
        return SkillResult(skill="scan_network", success=False, raw=str(e))


def _check_baseline(**kwargs) -> SkillResult:
    """Check file integrity against the baseline. An empty baseline is not a clean one."""
    from .baseline import FileBaseline, escalates
    try:
        baseline = FileBaseline.load()
        if not baseline._records:
            assessments = [Assessment(severity="medium", title="No file-integrity baseline exists",
                                      details="Run: python3 -m sentinel baseline create", grounded_in=["baseline"])]
        else:
            assessments = [Assessment(severity="high" if c.change_type in ("modified", "removed") or escalates(c)
                                      else "medium",
                                      title=f"File {c.change_type}: {c.path}", details=c.path, grounded_in=["baseline"])
                           for c in baseline.check()]
            # what the skip list kept the check out of, so a skip is never silent (sentinel/paths.py)
            skip = getattr(baseline, "last_skip", None)
            assessments += [Assessment(severity=severity, title=title, details=description, grounded_in=["skip_list"])
                            for severity, title, description, _r, _d in (skip.notes() if skip is not None else [])]
        obs = Observation(source="baseline_check", data={"assessments": len(assessments)})
        return SkillResult(skill="check_baseline", success=True, observations=[obs], assessments=assessments)
    except Exception as e:
        return SkillResult(skill="check_baseline", success=False, raw=str(e))


def _profile_system(**kwargs) -> SkillResult:
    """Take a system profile snapshot."""
    from .profiler import profile_system
    try:
        p = profile_system()
        return SkillResult(skill="profile_system", success=True, observations=[Observation(source="system_profile", data={"hostname": p.hostname})])
    except Exception as e:
        return SkillResult(skill="profile_system", success=False, raw=str(e))


def _get_hardening(bdi=None, **kwargs) -> SkillResult:
    """Hardening recommendations, as assessments only when the set of titles changed since the last run."""
    from advisor.hardening import HardeningAdvisor
    try:
        recs = HardeningAdvisor().assess()
        titles = sorted(r.title for r in recs)
        last = bdi.get_belief("last_hardening") if bdi is not None else None
        changed = last != titles
        if bdi is not None:
            bdi.believe("last_hardening", titles, source="get_hardening")
        assessments = [Assessment(severity=HARDENING_SEVERITY.get(r.severity, "high"), title=r.title, details=r.what,
                                  grounded_in=["hardening"]) for r in recs] if changed else []
        obs = Observation(source="hardening", data={"recommendations": len(recs), "changed": changed})
        return SkillResult(skill="get_hardening", success=True, observations=[obs], assessments=assessments)
    except Exception as e:
        return SkillResult(skill="get_hardening", success=False, raw=str(e))


# ── Verifier skill ──

def _verify_claim(claim: str = "", scan_data: str = "", **kwargs) -> SkillResult:
    """Check if a claim is supported by scan data."""
    claim_lower = claim.lower()
    data_lower = scan_data.lower()

    if not scan_data:
        assessment = Assessment(
            severity="medium",
            title="Unverified claim",
            details=f"Claim '{claim[:100]}' cannot be verified — no scan data available.",
            confidence=0.0,
        )
        return SkillResult(skill="verify_claim", success=True, assessments=[assessment])

    # Check if the claim's key terms appear in the data
    key_terms = [t for t in claim_lower.split() if len(t) > 3]
    matches = sum(1 for t in key_terms if t in data_lower)
    coverage = matches / len(key_terms) if key_terms else 0

    if coverage > 0.5:
        assessment = Assessment(
            severity="info", title="Claim supported",
            details=f"'{claim[:100]}' is consistent with scan data.",
            grounded_in=[f"{matches}/{len(key_terms)} key terms found in data"],
            confidence=coverage,
        )
    else:
        assessment = Assessment(
            severity="medium", title="Claim weakly supported",
            details=f"'{claim[:100]}' has limited support in scan data ({matches}/{len(key_terms)} terms match).",
            confidence=coverage,
        )

    return SkillResult(skill="verify_claim", success=True, assessments=[assessment])


# ── BDI Engine ──

@dataclass
class Belief:
    """A belief about system state."""
    key: str
    value: Any
    updated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = ""


@dataclass
class Desire:
    """A security goal."""
    name: str
    description: str
    priority: int = 5  # 1=highest
    satisfied: bool = False


@dataclass
class Intention:
    """A planned skill chain to satisfy a desire."""
    desire: str
    skills: list[str]
    trigger: str = "manual"  # manual, periodic, event
    interval_seconds: int = 0
    last_run: str = ""


# How early a periodic intention may count as due (2026-10-27, found from Ember's guardian log). last_run is stamped
# when the chain finishes, and cron starts the guardian on the same period as the intervals, so at the next slot the
# elapsed time fell a few seconds short and every check waited one extra slot: 4 h checks ran every 8 h, 8 h every
# 12 h, 24 h every 28 h. The grace is capped at a tenth of the interval, so a short interval can't fire every run.
DUE_GRACE_SECONDS = 300


def due_grace(interval_seconds: int) -> int:
    return min(DUE_GRACE_SECONDS, interval_seconds // 10)


class BDIEngine:
    """Beliefs-Desires-Intentions engine for proactive security.

    Maintains beliefs about system state, desires for security,
    and intentions that fire skill chains to satisfy desires.
    """

    def __init__(self, state_file: str = "") -> None:
        self._state_file = Path(state_file) if state_file else sentinel_home() / "bdi_state.json"
        self.beliefs: dict[str, Belief] = {}
        self.desires: list[Desire] = []
        self.intentions: list[Intention] = []
        self._load()

    def believe(self, key: str, value: Any, source: str = "") -> None:
        self.beliefs[key] = Belief(key=key, value=value, source=source)
        self._save()

    def get_belief(self, key: str) -> Any:
        b = self.beliefs.get(key)
        return b.value if b else None

    def add_desire(self, name: str, description: str, priority: int = 5) -> None:
        if not any(d.name == name for d in self.desires):
            self.desires.append(Desire(name=name, description=description, priority=priority))
            self._save()

    def add_intention(self, desire: str, skills: list[str],
                      trigger: str = "manual", interval: int = 0) -> None:
        self.intentions.append(Intention(
            desire=desire, skills=skills, trigger=trigger, interval_seconds=interval,
        ))
        self._save()

    def get_due_intentions(self) -> list[Intention]:
        """Return intentions that should fire now."""
        now = datetime.now(timezone.utc)
        due = []
        for intention in self.intentions:
            if intention.trigger == "periodic" and intention.interval_seconds > 0:
                if not intention.last_run:
                    due.append(intention)
                else:
                    last = datetime.fromisoformat(intention.last_run)
                    elapsed = (now - last).total_seconds()
                    if elapsed >= intention.interval_seconds - due_grace(intention.interval_seconds):
                        due.append(intention)
        return due

    def mark_run(self, intention: Intention) -> None:
        intention.last_run = datetime.now(timezone.utc).isoformat()
        self._save()

    def summary(self) -> str:
        lines = [f"Beliefs: {len(self.beliefs)}"]
        for k, b in self.beliefs.items():
            lines.append(f"  {k}: {b.value}")
        lines.append(f"Desires: {len(self.desires)}")
        for d in sorted(self.desires, key=lambda x: x.priority):
            lines.append(f"  [{'x' if d.satisfied else ' '}] P{d.priority}: {d.name}")
        lines.append(f"Intentions: {len(self.intentions)}")
        for i in self.intentions:
            lines.append(f"  {i.desire} → {' → '.join(i.skills)} ({i.trigger})")
        return "\n".join(lines)

    def _save(self) -> None:
        import os
        data = {
            "beliefs": {k: {"key": b.key, "value": b.value, "updated": b.updated, "source": b.source}
                        for k, b in self.beliefs.items()},
            "desires": [{"name": d.name, "description": d.description, "priority": d.priority, "satisfied": d.satisfied}
                        for d in self.desires],
            "intentions": [{"desire": i.desire, "skills": i.skills, "trigger": i.trigger,
                            "interval_seconds": i.interval_seconds, "last_run": i.last_run}
                           for i in self.intentions],
        }
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(str(tmp), str(self._state_file))

    def _load(self) -> None:
        if not self._state_file.exists():
            return
        try:
            data = json.loads(self._state_file.read_text())
            for k, b in data.get("beliefs", {}).items():
                self.beliefs[k] = Belief(**b)
            for d in data.get("desires", []):
                self.desires.append(Desire(**d))
            for i in data.get("intentions", []):
                self.intentions.append(Intention(**i))
        except (json.JSONDecodeError, TypeError):
            pass


# ── Skill Registry ──

class SkillRegistry:
    """Registry of available skills with composition support."""

    def __init__(self) -> None:
        self._skills: dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        self._skills[skill.name] = skill

    def get(self, name: str) -> Optional[Skill]:
        return self._skills.get(name)

    def run(self, name: str, **kwargs) -> SkillResult:
        skill = self._skills.get(name)
        if not skill:
            return SkillResult(skill=name, success=False, raw=f"Unknown skill: {name}")
        return skill.run(**kwargs)

    def run_chain(self, skill_names: list[str], **kwargs) -> list[SkillResult]:
        """Run a chain of skills, passing context forward."""
        results = []
        accumulated_data = ""
        for name in skill_names:
            result = self.run(name, scan_data=accumulated_data, **kwargs)
            results.append(result)
            if result.raw:
                accumulated_data += "\n" + result.raw
        return results

    def list_skills(self) -> list[dict]:
        return [{"name": s.name, "category": s.category, "description": s.description}
                for s in self._skills.values()]


def create_default_registry() -> SkillRegistry:
    """Create a registry with all built-in security skills."""
    registry = SkillRegistry()

    registry.register(Skill("scan_packages", "sensor", "Scan npm/pip packages against known-bad lists", _scan_packages))
    registry.register(Skill("scan_persistence", "sensor", "Check for malware persistence mechanisms", _scan_persistence))
    registry.register(Skill("scan_network", "sensor", "Check network listeners and credentials", _scan_network))
    registry.register(Skill("check_baseline", "sensor", "Check file integrity against baseline", _check_baseline))
    registry.register(Skill("profile_system", "sensor", "Take system profile snapshot", _profile_system))
    registry.register(Skill("get_hardening", "advisor", "Get hardening recommendations", _get_hardening))
    registry.register(Skill("verify_claim", "verifier", "Verify a claim against scan data", _verify_claim))

    return registry


def create_default_bdi() -> BDIEngine:
    """Create a BDI engine with default security desires and intentions."""
    bdi = BDIEngine()

    if not bdi.desires:
        bdi.add_desire("system_integrity", "All monitored systems maintain file integrity", priority=1)
        bdi.add_desire("no_compromised_packages", "No known-compromised packages installed", priority=1)
        bdi.add_desire("no_persistence", "No malware persistence mechanisms present", priority=1)
        bdi.add_desire("hardened_config", "System configurations follow security best practices", priority=3)
        bdi.add_desire("known_network_surface", "All listening ports are documented and expected", priority=2)

    if not bdi.intentions:
        bdi.add_intention("no_compromised_packages", ["scan_packages"], trigger="periodic", interval=14400)
        bdi.add_intention("no_persistence", ["scan_persistence"], trigger="periodic", interval=14400)
        bdi.add_intention("system_integrity", ["check_baseline"], trigger="periodic", interval=28800)
        bdi.add_intention("known_network_surface", ["scan_network"], trigger="periodic", interval=28800)
        bdi.add_intention("hardened_config", ["get_hardening"], trigger="periodic", interval=86400)

    return bdi
