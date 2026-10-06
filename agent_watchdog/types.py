"""Core data types shared across the three watchdog layers.

Everything here is intentionally tiny and dependency-free so that the rules
engine, the AI judge, and the human approver all speak the same language.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    """The three things the watchdog can decide about an action.

    ALLOW  -> let the action run, no human needed.
    ASK    -> stop and ask a human (dangerous-but-sometimes-intended, or the
              AI judge flagged it). A human turns this into ALLOW or BLOCK.
    BLOCK  -> refuse outright (obvious, unrecoverable destruction).

    We subclass ``str`` so verdicts serialize cleanly to JSON / CSV and compare
    against plain strings ("ALLOW" == Verdict.ALLOW) without ceremony.
    """

    ALLOW = "ALLOW"
    ASK = "ASK"
    BLOCK = "BLOCK"


class Layer(str, Enum):
    """Which layer produced a decision (useful for auditing and evaluation)."""

    RULES = "rules"          # Layer 1 — deterministic pattern rules
    AI = "ai"                # Layer 2 — pluggable AI second opinion
    HUMAN = "human"          # Layer 3 — a person said yes/no
    DEFAULT_ALLOW = "default"  # nothing objected, so we allowed it


@dataclass
class Assessment:
    """The output of a Layer-2 AI judge.

    ``risky`` is the boolean the watchdog acts on; ``score`` (0..1) and
    ``reason`` are for transparency and logging.
    """

    risky: bool
    score: float
    reason: str


@dataclass
class Decision:
    """The final, auditable result of inspecting one action.

    Every field is here so an operator can reconstruct *why* something was
    allowed, asked, or blocked — that traceability is the whole point of a
    safety watchdog.
    """

    command: str
    verdict: Verdict
    layer: Layer
    reason: str
    user_request: str = ""
    rule_name: Optional[str] = None       # set when Layer 1 fired
    risk_score: Optional[float] = None     # set when Layer 2 ran
    # A running trail of everything each layer said, for debugging / logs.
    trail: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Flatten to a JSON-serializable dict for the JSON-lines audit log."""
        return {
            "command": self.command,
            "user_request": self.user_request,
            "verdict": self.verdict.value,
            "layer": self.layer.value,
            "reason": self.reason,
            "rule_name": self.rule_name,
            "risk_score": self.risk_score,
            "trail": self.trail,
        }
