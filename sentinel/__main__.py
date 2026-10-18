"""Community Defender — security for the rest of us.

Usage:
  python -m sentinel                       # Full scan, print report
  python -m sentinel scan                  # Same as above
  python -m sentinel scan --json           # Output as JSON
  python -m sentinel scan --cron           # Quiet — only output if findings
  python -m sentinel harden                # Hardening recommendations
  python -m sentinel profile               # System profile
  python -m sentinel baseline create       # Create file integrity baseline
  python -m sentinel baseline check        # Check for changes
  python -m sentinel baseline update       # Accept changes as new baseline
  python -m sentinel all                   # Everything: scan + harden + baseline
"""
import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .scanner import SentinelScanner
from .alerts import AlertBus, StdoutAlert, FileAlert, DiscordWebhookAlert
from .baseline import FileBaseline
from .profiler import profile_system, save_profile


def cmd_scan(args) -> int:
    checks = args.checks.split(",") if args.checks else None
    scanner = SentinelScanner(checks=checks)
    result = scanner.scan()

    transports = []
    if not args.cron or result.findings:
        transports.append(StdoutAlert())
    if args.log:
        transports.append(FileAlert(args.log))
    if args.discord:
        transports.append(DiscordWebhookAlert(args.discord))

    bus = AlertBus(transports)

    if args.json:
        # One scan: the JSON printed is the result that chose the alerts and the exit code (rollout spec S4).
        output = json.dumps(asdict(result), indent=2)
        if args.output:
            Path(args.output).write_text(output)
        if not args.cron or result.findings:
            print(output)
    else:
        if not args.cron or result.findings:
            print(result.human_report())

    if result.findings:
        bus.alert_findings(result)

    return 1 if result.critical_count > 0 else 0


def cmd_harden(args) -> int:
    from advisor.hardening import HardeningAdvisor
    advisor = HardeningAdvisor()
    print(advisor.report())
    return 0


def cmd_profile(args) -> int:
    print("Profiling system...")
    profile = profile_system()
    save_profile(profile)
    print(profile.summary())
    print(f"\nProfile saved to ~/.sentinel/profile.json")
    return 0


def cmd_baseline(args) -> int:
    action = args.action

    if action == "create":
        print("Creating file integrity baseline...")
        baseline = FileBaseline()
        count = baseline.create()
        baseline.save()
        print(f"Baseline created: {count} files tracked.")
        print("Saved to ~/.sentinel/baseline.json")
        return 0

    elif action == "check":
        baseline = FileBaseline.load()
        if not baseline.file_count:
            print("No baseline found. Run: python -m sentinel baseline create")
            return 1
        changes = baseline.check()
        if not changes:
            print(f"No changes detected. {baseline.file_count} files unchanged.")
            return 0
        print(f"{len(changes)} changes since baseline:\n")
        for change in changes:
            print(change.human_readable())
        return 0

    elif action == "update":
        baseline = FileBaseline.load()
        if not baseline.file_count:
            print("No baseline found. Run: python -m sentinel baseline create")
            return 1
        count = baseline.update()
        baseline.save()
        print(f"Baseline updated: {count} files.")
        return 0

    else:
        print(f"Unknown baseline action: {action}")
        return 1


def cmd_all(args) -> int:
    print("=" * 50)
    print("COMMUNITY DEFENDER — FULL ASSESSMENT")
    print("=" * 50)

    print("\n[1/4] System Profile\n")
    profile = profile_system()
    save_profile(profile)
    print(profile.summary())

    print(f"\n{'—' * 50}")
    print("\n[2/4] Security Scan\n")
    scanner = SentinelScanner()
    result = scanner.scan()
    print(result.human_report())

    print(f"\n{'—' * 50}")
    print("\n[3/4] Hardening Recommendations\n")
    from advisor.hardening import HardeningAdvisor
    advisor = HardeningAdvisor()
    print(advisor.report())

    print(f"\n{'—' * 50}")
    print("\n[4/4] File Integrity Baseline\n")
    baseline = FileBaseline.load()
    if baseline.file_count:
        changes = baseline.check()
        if changes:
            print(f"{len(changes)} file changes since last baseline:\n")
            for c in changes[:20]:
                print(c.human_readable())
            if len(changes) > 20:
                print(f"  ... and {len(changes) - 20} more")
        else:
            print(f"File integrity clean. {baseline.file_count} files unchanged.")
    else:
        print("No baseline exists yet. Creating one now...")
        baseline = FileBaseline()
        count = baseline.create()
        baseline.save()
        print(f"Baseline created: {count} files tracked.")

    print(f"\n{'=' * 50}")
    total_issues = len(result.findings)
    if total_issues == 0:
        print("Your machine looks good. Stay safe out there.")
    else:
        print(f"{total_issues} issues found. Check the details above.")
    print("=" * 50)

    return 1 if result.critical_count > 0 else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Community Defender — security for the rest of us",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    scan_p = sub.add_parser("scan", help="Run security sweep")
    scan_p.add_argument("--json", action="store_true")
    scan_p.add_argument("-o", "--output", default="")
    scan_p.add_argument("--discord", default="")
    scan_p.add_argument("--log", default="")
    scan_p.add_argument("--checks", default="")
    scan_p.add_argument("--cron", action="store_true")

    # harden
    sub.add_parser("harden", help="Hardening recommendations")

    # profile
    sub.add_parser("profile", help="System profile")

    # baseline
    baseline_p = sub.add_parser("baseline", help="File integrity baseline")
    baseline_p.add_argument("action", choices=["create", "check", "update"])

    # all
    sub.add_parser("all", help="Full assessment: scan + harden + baseline")

    args = parser.parse_args()

    if args.command is None:
        # Default: full scan
        args.json = False
        args.output = ""
        args.discord = ""
        args.log = ""
        args.checks = ""
        args.cron = False
        sys.exit(cmd_scan(args))
    elif args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "harden":
        sys.exit(cmd_harden(args))
    elif args.command == "profile":
        sys.exit(cmd_profile(args))
    elif args.command == "baseline":
        sys.exit(cmd_baseline(args))
    elif args.command == "all":
        sys.exit(cmd_all(args))


if __name__ == "__main__":
    main()
