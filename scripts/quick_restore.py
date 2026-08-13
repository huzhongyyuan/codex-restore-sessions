#!/usr/bin/env python3
"""Restore local Codex sessions with a short, zero-configuration command."""

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


GUARD = Path(__file__).with_name("session_guard.py").resolve()
REQUIREMENTS = GUARD.parent.parent / "requirements.txt"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Safely restore the default Codex home in one command. "
            "Uses CODEX_HOME when set, otherwise ~/.codex."
        )
    )
    parser.add_argument(
        "--check",
        "--dry-run",
        dest="check",
        action="store_true",
        help="Only diagnose session health; do not change anything",
    )
    parser.add_argument(
        "--codex-home",
        help="Override CODEX_HOME/~/.codex with this Codex home",
    )
    parser.add_argument(
        "--profile",
        help="Use the same profile name passed to `codex -p <name>`",
    )
    parser.add_argument(
        "--provider",
        help="Override the provider detected from the selected Codex config",
    )
    parser.add_argument(
        "--fail-live",
        action="store_true",
        help="Fail instead of safely deferring sessions that are still being written",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the underlying machine-readable JSON result",
    )
    args = parser.parse_args()
    if args.check and args.fail_live:
        parser.error("--fail-live cannot be used with --check")
    return args


def guard_command(args: argparse.Namespace) -> List[str]:
    command = [sys.executable, str(GUARD)]
    if args.codex_home:
        command.extend(["--codex-home", args.codex_home])
    if args.profile:
        command.extend(["--profile", args.profile])
    if args.check:
        command.append("doctor")
    else:
        command.extend(["--compact", "restore"])
    if args.provider:
        command.extend(["--provider", args.provider])
    if args.fail_live:
        command.append("--fail-live")
    return command


def run_guard(args: argparse.Namespace) -> int:
    result = subprocess.run(guard_command(args), capture_output=True, text=True)
    if result.returncode:
        if (
            "No module named 'tomli'" in result.stderr
            or "install the bundled requirements.txt (tomli)" in result.stderr
        ):
            print(
                "This Python version needs the small TOML compatibility dependency.",
                file=sys.stderr,
            )
            print(
                f"Install: {shlex.join([sys.executable, '-m', 'pip', 'install', '-r', str(REQUIREMENTS)])}",
                file=sys.stderr,
            )
            return result.returncode
        if result.stdout:
            print(result.stdout, end="", file=sys.stderr)
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode

    if args.json:
        print(result.stdout, end="")
        return 0

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("The session guard returned an unreadable result.", file=sys.stderr)
        print(result.stdout, end="", file=sys.stderr)
        return 1

    if args.check:
        print_check(payload, args)
    else:
        print_restore(payload)
    return 0


def audit_from_doctor(payload: Dict[str, Any]) -> Dict[str, Any]:
    plan = payload.get("plan")
    if isinstance(plan, dict) and isinstance(plan.get("audit"), dict):
        return plan["audit"]
    return {}


def print_counts(audit: Dict[str, Any]) -> None:
    if not audit:
        return
    print(f"Home: {audit.get('codex_home', 'unknown')}")
    target = audit.get("target") or {}
    profile = target.get("profile") or "default"
    provider = target.get("provider") or "unknown"
    print(f"Target: profile={profile}, provider={provider}")
    print(
        "Sessions: "
        f"{audit.get('threads', 0)} "
        f"({audit.get('active', 0)} active, {audit.get('archived', 0)} archived); "
        f"rollouts={audit.get('rollout_files', 0)}"
    )


def quick_command(args: argparse.Namespace) -> List[str]:
    command = [sys.executable, str(Path(__file__).resolve())]
    if args.codex_home:
        command.extend(["--codex-home", args.codex_home])
    if args.profile:
        command.extend(["--profile", args.profile])
    if args.provider:
        command.extend(["--provider", args.provider])
    return command


def print_check(payload: Dict[str, Any], args: argparse.Namespace) -> None:
    health = str(payload.get("health", "unknown"))
    print(f"Session check: {health.upper()}")
    print(str(payload.get("summary", "No summary was returned.")))
    audit = audit_from_doctor(payload)
    print_counts(audit)

    recommendations = payload.get("recommendations") or []
    if not recommendations:
        error = payload.get("diagnostic_error")
        if error:
            print(f"Details: {error}")
        return

    recommendation = recommendations[0]
    print(
        f"Recommended: {recommendation.get('action', 'review')} — "
        f"{recommendation.get('reason', 'Review the session state.')}"
    )
    if recommendation.get("action") == "restore":
        print(f"Run: {shlex.join(quick_command(args))}")
        return

    command = recommendation.get("command")
    if isinstance(command, list) and command:
        absolute = [str(item) for item in command]
        if len(absolute) > 1 and absolute[1] == "scripts/session_guard.py":
            absolute[0] = sys.executable
            absolute[1] = str(GUARD)
        print(f"Review first: {shlex.join(absolute)}")


def print_restore(payload: Dict[str, Any]) -> None:
    audit = payload.get("audit") or {}
    deferred = payload.get("deferred_live_sessions") or []
    if deferred:
        print(f"Session restore partially complete: {len(deferred)} live session(s) deferred.")
    elif payload.get("backup"):
        print("Session restore complete.")
    else:
        print("Sessions are already synchronized; no changes were needed.")
    print_counts(audit)
    backup = payload.get("backup")
    print(f"Backup: {backup or 'not created (no changes)'}")
    if deferred:
        print("Deferred files:")
        for path in deferred:
            print(f"  - {path}")
        print("Close those Codex sessions, then run this command again.")


def main() -> int:
    return run_guard(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
