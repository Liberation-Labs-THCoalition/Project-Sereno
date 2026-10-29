"""Sereno — security for the rest of us.

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
  python -m sentinel scan --skip ~/agents/someone-else   # Don't enter a folder (repeatable; see skip.json in README)
"""
import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from .scanner import CHECK_NAMES, SentinelScanner
from .alerts import AlertBus, StdoutAlert, FileAlert, DiscordWebhookAlert
from .baseline import FileBaseline
from .paths import sentinel_home, state_folder_note
from .profiler import profile_system, save_profile


def _skip_kw(args) -> dict:
    """{"skip": [...]} for the --skip paths given, made absolute from the current folder (a ! in front, which takes a
    path back off the list, is kept), or {} when there are none, so the user's skip.json alone applies."""
    entries = []
    for entry in (getattr(args, "skip", None) or []):
        negate = entry.startswith("!")
        path = entry[1:] if negate else entry
        if not path.startswith("~"):
            path = os.path.abspath(path)
        entries.append(("!" if negate else "") + path)
    return {"skip": entries} if entries else {}


def _print_skip_notes(baseline) -> None:
    """What the skip list kept a baseline out of, in its own words (sentinel/paths.py)."""
    skip = getattr(baseline, "last_skip", None)
    for _severity, title, description, _remediation, _details in (skip.notes() if skip is not None else []):
        print(f"{title}. {description}")


def _closed(baseline) -> bool:
    """Whether the baseline's last create or check ran with a skip list that couldn't be read, and so looked nowhere."""
    return bool(getattr(getattr(baseline, "last_skip", None), "closed", False))


NOT_SAVED = "Baseline not saved: with the skip list unreadable it would hold nothing (see above). Fix the list first."


def _unchanged(baseline, clean: str) -> str:
    """The line for a baseline check that found no change: `clean` when it looked everywhere, else what it can say."""
    skip = getattr(baseline, "last_skip", None)
    if skip is not None and skip.closed:
        return "File integrity not checked: the skip list couldn't be read (see above)."
    if skip is not None and skip.skipped():
        return "No changes detected outside the folders on your skip list (see above)."
    return clean


def cmd_scan(args) -> int:
    checks = [c.strip() for c in args.checks.split(",") if c.strip()] if args.checks else None
    try:
        scanner = SentinelScanner(checks=checks, **_skip_kw(args))
    except ValueError as e:
        # A misspelled check name used to run nothing and report a clean machine (2026-10-23)
        print(f"sentinel: {e}", file=sys.stderr)
        return 2
    result = scanner.scan()

    # --cron stays quiet unless something asks for action; info notes alone don't (2026-10-23)
    transports = []
    if not args.cron or result.issues:
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
        if not args.cron or result.issues:
            print(output)
    else:
        if not args.cron or result.issues:
            print(result.human_report())

    if result.issues:
        bus.alert_findings(result)

    return 1 if result.critical_count > 0 else 0


def cmd_harden(args) -> int:
    from advisor.hardening import HardeningAdvisor
    advisor = HardeningAdvisor(**_skip_kw(args))
    print(advisor.report())
    return 0


def cmd_profile(args) -> int:
    print("Profiling system...")
    profile = profile_system(**_skip_kw(args))
    save_profile(profile)
    print(profile.summary())
    print(f"\nProfile saved to {sentinel_home() / 'profile.json'}")
    print(f"State folder: {state_folder_note()}")
    return 0


def cmd_baseline(args) -> int:
    action = args.action
    kw = _skip_kw(args)

    if action == "create":
        print("Creating file integrity baseline...")
        baseline = FileBaseline()
        count = baseline.create(**kw)
        if _closed(baseline):   # an empty baseline saved over a good one would hide every later change
            _print_skip_notes(baseline)
            print(NOT_SAVED)
            print(f"State folder: {state_folder_note()}")
            return 1
        baseline.save()
        print(f"Baseline created: {count} files tracked.")
        _print_skip_notes(baseline)
        print(f"Saved to {sentinel_home() / 'baseline.json'}")
        print(f"State folder: {state_folder_note()}")
        return 0

    elif action == "check":
        baseline = FileBaseline.load()
        if not baseline.file_count:
            print("No baseline found. Run: python -m sentinel baseline create")
            print(f"State folder: {state_folder_note()}")
            return 1
        changes = baseline.check(**kw)
        _print_skip_notes(baseline)
        print(f"State folder: {state_folder_note()}")
        if not changes:
            print(_unchanged(baseline, f"No changes detected. {baseline.file_count} files unchanged."))
            return 1 if _closed(baseline) else 0
        print(f"{len(changes)} changes since baseline:\n")
        for change in changes:
            print(change.human_readable())
        return 0

    elif action == "update":
        baseline = FileBaseline.load()
        if not baseline.file_count:
            print("No baseline found. Run: python -m sentinel baseline create")
            print(f"State folder: {state_folder_note()}")
            return 1
        count = baseline.update(**kw)
        if _closed(baseline):
            _print_skip_notes(baseline)
            print(NOT_SAVED)
            print(f"State folder: {state_folder_note()}")
            return 1
        baseline.save()
        print(f"Baseline updated: {count} files.")
        _print_skip_notes(baseline)
        print(f"State folder: {state_folder_note()}")
        return 0

    else:
        print(f"Unknown baseline action: {action}")
        return 1


def cmd_all(args) -> int:
    kw = _skip_kw(args)
    print("=" * 50)
    print("SERENO — FULL ASSESSMENT")
    print(f"State folder: {state_folder_note()}")
    print("=" * 50)

    print("\n[1/4] System Profile\n")
    profile = profile_system(**kw)
    save_profile(profile)
    print(profile.summary())

    print(f"\n{'—' * 50}")
    print("\n[2/4] Security Scan\n")
    scanner = SentinelScanner(**kw)
    result = scanner.scan()
    print(result.human_report())

    print(f"\n{'—' * 50}")
    print("\n[3/4] Hardening Recommendations\n")
    from advisor.hardening import HardeningAdvisor
    advisor = HardeningAdvisor(**kw)
    print(advisor.report())

    print(f"\n{'—' * 50}")
    print("\n[4/4] File Integrity Baseline\n")
    baseline = FileBaseline.load()
    if baseline.file_count:
        changes = baseline.check(**kw)
        _print_skip_notes(baseline)
        if changes:
            print(f"{len(changes)} file changes since last baseline:\n")
            for c in changes[:20]:
                print(c.human_readable())
            if len(changes) > 20:
                print(f"  ... and {len(changes) - 20} more")
        else:
            print(_unchanged(baseline, f"File integrity clean. {baseline.file_count} files unchanged."))
    else:
        print("No baseline exists yet. Creating one now...")
        baseline = FileBaseline()
        count = baseline.create(**kw)
        if _closed(baseline):
            _print_skip_notes(baseline)
            print(NOT_SAVED)
        else:
            baseline.save()
            print(f"Baseline created: {count} files tracked.")
            _print_skip_notes(baseline)

    print(f"\n{'=' * 50}")
    total_issues = len(result.issues)
    if total_issues == 0:
        print("No issues found. Stay safe out there.")
    else:
        print(f"{total_issues} issues found. Check the details above.")
    print("=" * 50)

    return 1 if result.critical_count > 0 else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sereno — security for the rest of us",
    )
    sub = parser.add_subparsers(dest="command")

    # --skip, for every command that searches folders under home
    skip_p = argparse.ArgumentParser(add_help=False)
    skip_p.add_argument("--skip", action="append", default=[], metavar="PATH",
                        help="Don't enter this folder (repeatable); added to the list in $SENTINEL_HOME/skip.json")

    # scan
    scan_p = sub.add_parser("scan", help="Run security sweep", parents=[skip_p])
    scan_p.add_argument("--json", action="store_true")
    scan_p.add_argument("-o", "--output", default="")
    scan_p.add_argument("--discord", default="")
    scan_p.add_argument("--log", default="")
    scan_p.add_argument("--checks", default="", help="Comma-separated, from: " + ", ".join(CHECK_NAMES))
    scan_p.add_argument("--cron", action="store_true")

    # harden
    sub.add_parser("harden", help="Hardening recommendations", parents=[skip_p])

    # profile
    sub.add_parser("profile", help="System profile", parents=[skip_p])

    # baseline
    baseline_p = sub.add_parser("baseline", help="File integrity baseline", parents=[skip_p])
    baseline_p.add_argument("action", choices=["create", "check", "update"])

    # all
    sub.add_parser("all", help="Full assessment: scan + harden + baseline", parents=[skip_p])

    args = parser.parse_args()

    if args.command is None:
        # Default: full scan
        args.json = False
        args.output = ""
        args.discord = ""
        args.log = ""
        args.checks = ""
        args.cron = False
        args.skip = []
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
