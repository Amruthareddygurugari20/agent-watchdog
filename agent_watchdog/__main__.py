"""Command-line entry point: inspect a single action from the shell.

Examples
--------
    python -m agent_watchdog "rm -rf build/"
    python -m agent_watchdog --mode rules_only "git push --force"
    python -m agent_watchdog --request "list files" "find . -delete"

Exit codes: 0 = ALLOW, 1 = BLOCK, 2 = ASK unresolved (only in --no-human).
"""

from __future__ import annotations

import argparse
import sys

from .types import Verdict
from .watchdog import Watchdog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-watchdog",
        description="Decide ALLOW / ASK / BLOCK for an AI agent's action.",
    )
    parser.add_argument("command", help="the shell command / action to inspect")
    parser.add_argument(
        "--mode",
        choices=["rules_only", "hybrid"],
        default="hybrid",
        help="which layers to run (default: hybrid)",
    )
    parser.add_argument(
        "--request",
        default="",
        help="the user request that motivated the command (helps Layer 2)",
    )
    parser.add_argument(
        "--log",
        default=None,
        help="path to a JSON-lines audit log to append to",
    )
    parser.add_argument(
        "--no-human",
        action="store_true",
        help="do not prompt a human; print the machine verdict and exit",
    )
    args = parser.parse_args(argv)

    wd = Watchdog(mode=args.mode, log_path=args.log)

    if args.no_human:
        decision = wd.review(args.command, args.request)
    else:
        decision = wd.enforce(args.command, args.request)

    print(f"{decision.verdict.value}  (layer: {decision.layer.value})")
    print(f"reason: {decision.reason}")

    return {Verdict.ALLOW: 0, Verdict.BLOCK: 1, Verdict.ASK: 2}[decision.verdict]


if __name__ == "__main__":
    sys.exit(main())
