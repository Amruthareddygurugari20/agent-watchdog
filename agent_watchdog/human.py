"""Layer 3 — human approval.

When the machine decides ASK, a person makes the final call. A *human approver*
is any callable that takes a :class:`~agent_watchdog.types.Decision` and returns
a :class:`~agent_watchdog.types.Verdict` of ALLOW or BLOCK.

We ship a real interactive CLI approver, plus tiny helpers for tests and
automation. Keeping this a plain callable means tests can inject a fake without
any mocking machinery.
"""

from __future__ import annotations

from typing import Callable

from .types import Decision, Verdict

# A human approver is just: Decision -> Verdict (ALLOW or BLOCK).
HumanApprover = Callable[[Decision], Verdict]


def cli_approver(decision: Decision) -> Verdict:
    """Interactive approver: show the action and prompt the operator y/n.

    Returns ALLOW on an affirmative answer, BLOCK otherwise. Anything that isn't
    a clear "yes" is treated as BLOCK — failing safe is the point.
    """
    print("\n" + "=" * 70)
    print("  AGENT-WATCHDOG — human approval required")
    print("=" * 70)
    print(f"  Command      : {decision.command}")
    if decision.user_request:
        print(f"  User request : {decision.user_request}")
    print(f"  Flagged by   : layer '{decision.layer.value}'")
    if decision.rule_name:
        print(f"  Rule         : {decision.rule_name}")
    if decision.risk_score is not None:
        print(f"  Risk score   : {decision.risk_score}")
    print(f"  Reason       : {decision.reason}")
    print("-" * 70)

    try:
        answer = input("  Allow this action to run? [y/N]: ").strip().lower()
    except EOFError:
        # No TTY / piped input exhausted -> fail safe.
        answer = ""

    if answer in ("y", "yes"):
        return Verdict.ALLOW
    return Verdict.BLOCK


def always_allow(decision: Decision) -> Verdict:
    """Non-interactive approver that approves everything. For tests only."""
    return Verdict.ALLOW


def always_block(decision: Decision) -> Verdict:
    """Non-interactive approver that rejects everything (fail-safe default)."""
    return Verdict.BLOCK


def scripted_approver(answers: list[bool]) -> HumanApprover:
    """Build an approver that returns a preset sequence of yes/no answers.

    Useful in tests to simulate a human clicking through several prompts:

    >>> approver = scripted_approver([True, False])
    >>> # first ASK -> ALLOW, second ASK -> BLOCK
    """
    queue = list(answers)

    def _approver(decision: Decision) -> Verdict:
        allow = queue.pop(0) if queue else False
        return Verdict.ALLOW if allow else Verdict.BLOCK

    return _approver
