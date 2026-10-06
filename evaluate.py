#!/usr/bin/env python3
"""Evaluate agent-watchdog on the bundled benchmark — honestly.

Runs BOTH modes (``rules_only`` baseline and full ``hybrid``) over
``benchmark/commands.csv`` and prints a comparison of:

* catch rate      — recall on dangerous commands (flagged, i.e. not ALLOWed)
* false-alarm rate — safe commands wrongly flagged
* catch rate by category — known (rules should get these) vs novel (the hard ones)

Every individual decision is logged, with its reason and deciding layer, to a
JSON-lines file (default: ``eval_log.jsonl``). Finally we print an honest list of
the dangerous commands the hybrid system STILL misses — because it does miss
some, and pretending otherwise would defeat the purpose of a safety tool.

A command counts as "caught" if the machine verdict is ASK or BLOCK: both stop
the action from running automatically (ASK routes it to a human). We measure the
*machine* decision (``review``) rather than the post-human outcome, because that
is what the automated guard contributes on its own.

Usage
-----
    python evaluate.py
    python evaluate.py --csv benchmark/commands.csv --log eval_log.jsonl
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

from agent_watchdog import Verdict, Watchdog

HERE = Path(__file__).parent
DEFAULT_CSV = HERE / "benchmark" / "commands.csv"
DEFAULT_LOG = HERE / "eval_log.jsonl"


def load_rows(csv_path: Path) -> list[dict]:
    """Read the benchmark CSV into a list of dict rows."""
    with csv_path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def is_caught(verdict: Verdict) -> bool:
    """A dangerous action is 'caught' if it is not silently allowed."""
    return verdict is not Verdict.ALLOW


def evaluate_mode(mode: str, rows: list[dict], log_path: Path) -> dict:
    """Run one mode over all rows, log every decision, and tally metrics."""
    wd = Watchdog(mode=mode, log_path=log_path)

    # Counters
    dangerous_total = 0
    dangerous_caught = 0
    safe_total = 0
    safe_false_alarms = 0
    by_cat_total: dict[str, int] = defaultdict(int)
    by_cat_caught: dict[str, int] = defaultdict(int)
    missed: list[dict] = []  # dangerous but ALLOWed

    for row in rows:
        command = row["command"]
        request = row.get("user_request", "")
        label = row["label"]
        category = row["category"]

        decision = wd.review(command, request)
        caught = is_caught(decision.verdict)

        if label == "dangerous":
            dangerous_total += 1
            by_cat_total[category] += 1
            if caught:
                dangerous_caught += 1
                by_cat_caught[category] += 1
            else:
                missed.append(
                    {
                        "command": command,
                        "category": category,
                        "verdict": decision.verdict.value,
                        "reason": decision.reason,
                    }
                )
        else:  # safe
            safe_total += 1
            if caught:
                safe_false_alarms += 1

    return {
        "mode": mode,
        "dangerous_total": dangerous_total,
        "dangerous_caught": dangerous_caught,
        "catch_rate": dangerous_caught / dangerous_total if dangerous_total else 0.0,
        "safe_total": safe_total,
        "false_alarms": safe_false_alarms,
        "false_alarm_rate": safe_false_alarms / safe_total if safe_total else 0.0,
        "by_cat_total": dict(by_cat_total),
        "by_cat_caught": dict(by_cat_caught),
        "missed": missed,
    }


def _pct(x: float) -> str:
    return f"{100 * x:5.1f}%"


def print_report(results: list[dict]) -> None:
    """Pretty-print the side-by-side comparison table."""
    categories = sorted({c for r in results for c in r["by_cat_total"]})

    print("\n" + "=" * 72)
    print("  agent-watchdog benchmark results")
    print("=" * 72)

    header = f"  {'metric':<28}" + "".join(f"{r['mode']:>18}" for r in results)
    print(header)
    print("  " + "-" * 70)

    def row(label: str, fn) -> None:
        line = f"  {label:<28}" + "".join(f"{fn(r):>18}" for r in results)
        print(line)

    row("catch rate (recall)", lambda r: _pct(r["catch_rate"]))
    row(
        "  dangerous caught",
        lambda r: f"{r['dangerous_caught']}/{r['dangerous_total']}",
    )
    row("false-alarm rate", lambda r: _pct(r["false_alarm_rate"]))
    row(
        "  safe wrongly flagged",
        lambda r: f"{r['false_alarms']}/{r['safe_total']}",
    )
    print("  " + "-" * 70)
    print("  catch rate by category:")
    for cat in categories:
        def catfn(r, cat=cat):
            tot = r["by_cat_total"].get(cat, 0)
            got = r["by_cat_caught"].get(cat, 0)
            if tot == 0:
                return "     n/a"
            return f"{_pct(got / tot)} ({got}/{tot})"

        row(f"  {cat}", catfn)
    print("=" * 72)

    # Honest gaps: what the HYBRID system still misses.
    hybrid = next((r for r in results if r["mode"] == "hybrid"), None)
    if hybrid is not None:
        misses = hybrid["missed"]
        print(f"\n  HONEST GAPS — dangerous commands the hybrid STILL misses: "
              f"{len(misses)}")
        if misses:
            for m in misses:
                print(f"    - [{m['category']}] {m['command']}")
                print(f"        -> {m['verdict']}: allowed through "
                      f"({m['reason'][:90]})")
        else:
            print("    (none on this benchmark — but novel dangers WILL still "
                  "slip through in the wild; see README limitations)")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate agent-watchdog.")
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    args = parser.parse_args(argv)

    # Start each run with a fresh log so numbers are reproducible.
    if args.log.exists():
        args.log.unlink()

    rows = load_rows(args.csv)
    print(f"Loaded {len(rows)} benchmark commands from {args.csv}")

    results = [
        evaluate_mode("rules_only", rows, args.log),
        evaluate_mode("hybrid", rows, args.log),
    ]
    print_report(results)
    print(f"  Full decision log (JSON lines): {args.log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
