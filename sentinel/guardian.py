"""Guardian — the proactive security loop.

Runs periodically (cron). Checks BDI intentions, fires due skill chains,
records results, alerts on findings. The model is optional — the guardian
operates without it. When a model is available, it translates findings
for humans.

Usage:
  python3 -m sentinel.guardian              # Run due intentions
  python3 -m sentinel.guardian --status      # Show BDI state
  python3 -m sentinel.guardian --force all   # Force all intentions now
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .skills import (
    create_default_registry, create_default_bdi,
    SkillRegistry, BDIEngine, SkillResult,
)
from .alerts import AlertBus, StdoutAlert, FileAlert, DiscordWebhookAlert
from .paths import sentinel_home

log = logging.getLogger(__name__)


def run_guardian(
    registry: SkillRegistry | None = None,
    bdi: BDIEngine | None = None,
    force: str = "",
    alert_bus: AlertBus | None = None,
) -> list[SkillResult]:
    """Run the guardian loop — check intentions, fire skills, alert."""
    registry = registry or create_default_registry()
    bdi = bdi or create_default_bdi()
    bus = alert_bus or AlertBus([StdoutAlert()])

    all_results: list[SkillResult] = []

    if force:
        if force == "all":
            intentions = list(bdi.intentions)
        else:
            intentions = [i for i in bdi.intentions if i.desire == force]
    else:
        intentions = bdi.get_due_intentions()

    if not intentions:
        log.info("No intentions due. System nominal.")
        return all_results

    log.info("Running %d due intentions", len(intentions))

    for intention in intentions:
        log.info("Intention: %s → %s", intention.desire, " → ".join(intention.skills))
        results = registry.run_chain(intention.skills, bdi=bdi)
        all_results.extend(results)
        bdi.mark_run(intention)

        # Check for findings
        for result in results:
            if not result.success:
                for t in bus._transports:
                    t.send(f"Skill {result.skill} failed: {result.raw[:200]}", "high")
                continue

            for assessment in result.assessments:
                if assessment.severity in ("critical", "high"):
                    for t in bus._transports:
                        t.send(
                            f"[{assessment.severity.upper()}] {assessment.title}: {assessment.details[:200]}",
                            assessment.severity,
                        )

            # Update beliefs from observations
            for obs in result.observations:
                bdi.believe(
                    f"last_{result.skill}",
                    obs.data if obs.data else "completed",
                    source=result.skill,
                )

    # Save run results
    runs = sentinel_home() / "guardian_runs"
    runs.mkdir(parents=True, exist_ok=True)
    run_file = runs / f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    run_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "intentions_run": len(intentions),
        "skills_run": len(all_results),
        "findings": sum(len(r.assessments) for r in all_results),
        "results": [
            {
                "skill": r.skill,
                "success": r.success,
                "duration_ms": r.duration_ms,
                "observations": len(r.observations),
                "assessments": len(r.assessments),
            }
            for r in all_results
        ],
    }
    run_file.write_text(json.dumps(run_data, indent=2))
    log.info("Run saved: %s", run_file)

    return all_results


def main():
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [guardian] %(message)s")
    parser = argparse.ArgumentParser(description="Guardian — proactive security loop")
    parser.add_argument("--status", action="store_true", help="Show BDI state")
    parser.add_argument("--force", default="", help="Force intention(s): 'all' or desire name")
    parser.add_argument("--discord", default="", help="Discord webhook URL")
    parser.add_argument("--log", default="", help="Log file path")
    args = parser.parse_args()

    bdi = create_default_bdi()

    if args.status:
        print(bdi.summary())
        return

    transports = [StdoutAlert()]
    if args.log:
        transports.append(FileAlert(args.log))
    if args.discord:
        transports.append(DiscordWebhookAlert(args.discord))

    bus = AlertBus(transports)
    results = run_guardian(bdi=bdi, force=args.force, alert_bus=bus)

    total_findings = sum(len(r.assessments) for r in results)
    if total_findings:
        print(f"\n{total_findings} findings from {len(results)} skills.")
    else:
        print(f"\nAll clear. {len(results)} skills ran clean.")


if __name__ == "__main__":
    main()
