"""The Watchdog — orchestrates the three layers.

Philosophy: **rules + AI + human, never AI alone.**

1. Layer 1 (rules) is consulted first because it is deterministic and reliable.
   If a rule fires, we honor its verdict immediately (BLOCK or ASK) — a
   fast, explainable veto that never depends on a model.
2. Layer 2 (AI judge) only runs for commands the rules did NOT catch, to surface
   novel/obfuscated dangers. A "risky" assessment becomes ASK.
3. Layer 3 (human) resolves every ASK into a final ALLOW or BLOCK.

Two modes let you compare the safety backbone against the full system:

* ``"rules_only"`` — Layer 1 only (the baseline).
* ``"hybrid"``     — all three layers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Union

from .ai_judge import AIJudge, HeuristicJudge
from .file_ops import FileAction, check_file_action
from .human import HumanApprover, cli_approver
from .rules import check_rules
from .types import Decision, Layer, Verdict


class Watchdog:
    """Inspect a proposed agent action and decide ALLOW / ASK / BLOCK.

    Parameters
    ----------
    mode:
        ``"hybrid"`` (default) runs all three layers; ``"rules_only"`` runs just
        the deterministic rules — useful as a baseline for evaluation.
    ai_judge:
        Any :class:`AIJudge`. Defaults to the model-free :class:`HeuristicJudge`
        so the watchdog always runs with zero external dependencies.
    human_approver:
        A callable resolving ASK -> ALLOW/BLOCK. Defaults to the interactive
        :func:`cli_approver`. Inject a fake in tests.
    log_path:
        Optional path to a JSON-lines audit log. Every decision is appended.
    """

    def __init__(
        self,
        mode: str = "hybrid",
        ai_judge: Optional[AIJudge] = None,
        human_approver: Optional[HumanApprover] = None,
        log_path: Optional[Union[str, Path]] = None,
    ):
        if mode not in ("rules_only", "hybrid"):
            raise ValueError(f"unknown mode {mode!r}; use 'rules_only' or 'hybrid'")
        self.mode = mode
        self.ai_judge = ai_judge or HeuristicJudge()
        self.human_approver = human_approver or cli_approver
        self.log_path = Path(log_path) if log_path else None

    # ------------------------------------------------------------------
    # review(): the machine decision — ALLOW / ASK / BLOCK — before any
    # human is involved. This is what the benchmark measures, because it
    # captures what the automated guard surfaces on its own.
    # ------------------------------------------------------------------
    def review(self, command: str, user_request: str = "") -> Decision:
        """Return the machine verdict for ``command`` (no human prompt)."""
        trail: list[str] = []

        # --- Layer 1: deterministic rules --------------------------------
        rule = check_rules(command)
        if rule is not None:
            trail.append(f"rules: matched '{rule.name}' -> {rule.verdict.value}")
            return self._log(
                Decision(
                    command=command,
                    verdict=rule.verdict,
                    layer=Layer.RULES,
                    reason=rule.reason,
                    user_request=user_request,
                    rule_name=rule.name,
                    trail=trail,
                )
            )
        trail.append("rules: no match")

        # In the baseline mode we stop here: anything the rules miss is allowed.
        if self.mode == "rules_only":
            return self._log(
                Decision(
                    command=command,
                    verdict=Verdict.ALLOW,
                    layer=Layer.DEFAULT_ALLOW,
                    reason="no rule matched (rules_only mode)",
                    user_request=user_request,
                    trail=trail,
                )
            )

        # --- Layer 2: AI second opinion ----------------------------------
        assessment = self.ai_judge.assess(command, user_request)
        trail.append(
            f"ai: risky={assessment.risky} score={assessment.score} :: {assessment.reason}"
        )
        if assessment.risky:
            return self._log(
                Decision(
                    command=command,
                    verdict=Verdict.ASK,
                    layer=Layer.AI,
                    reason=assessment.reason,
                    user_request=user_request,
                    risk_score=assessment.score,
                    trail=trail,
                )
            )

        # Nothing objected -> allow.
        return self._log(
            Decision(
                command=command,
                verdict=Verdict.ALLOW,
                layer=Layer.DEFAULT_ALLOW,
                reason="rules found nothing and the AI judge saw no risk",
                user_request=user_request,
                risk_score=assessment.score,
                trail=trail,
            )
        )

    # ------------------------------------------------------------------
    # review_file_action(): the same machine decision for a *structured*
    # file operation. Deterministic path/verb rules run first (Layer 1);
    # anything they don't object to falls back to reviewing the equivalent
    # rendered command, so the AI layer still gets a look in hybrid mode.
    # ------------------------------------------------------------------
    def review_file_action(self, action: FileAction, user_request: str = "") -> Decision:
        """Return the machine verdict for a :class:`FileAction`."""
        rendered = action.to_command()
        result = check_file_action(action)
        if result is not None:
            verdict, reason, name = result
            return self._log(
                Decision(
                    command=rendered,
                    verdict=verdict,
                    layer=Layer.RULES,
                    reason=reason,
                    user_request=user_request,
                    rule_name=name,
                    trail=[f"file-rules: matched '{name}' -> {verdict.value}"],
                )
            )
        # Nothing intrinsically dangerous about the path/verb — defer to the
        # normal command review of the rendered equivalent (covers obfuscated
        # or novel content, and honors rules_only vs hybrid mode).
        decision = self.review(rendered, user_request)
        decision.trail.insert(0, "file-rules: no match -> reviewing rendered command")
        return decision

    def enforce_file_action(self, action: FileAction, user_request: str = "") -> Decision:
        """Like :meth:`review_file_action`, prompting a human on ASK."""
        decision = self.review_file_action(action, user_request)
        if decision.verdict is not Verdict.ASK:
            return decision
        human_verdict = self.human_approver(decision)
        if human_verdict not in (Verdict.ALLOW, Verdict.BLOCK):
            human_verdict = Verdict.BLOCK
        decision.trail.append(f"human: {human_verdict.value}")
        return self._log(
            Decision(
                command=decision.command,
                verdict=human_verdict,
                layer=Layer.HUMAN,
                reason=f"human {'approved' if human_verdict is Verdict.ALLOW else 'rejected'} "
                f"an ASK: {decision.reason}",
                user_request=user_request,
                rule_name=decision.rule_name,
                risk_score=decision.risk_score,
                trail=decision.trail,
            )
        )

    # ------------------------------------------------------------------
    # enforce(): the full pipeline. Same as review(), but an ASK is sent
    # to the human approver, yielding a terminal ALLOW or BLOCK. This is
    # what you call in a real integration.
    # ------------------------------------------------------------------
    def enforce(self, command: str, user_request: str = "") -> Decision:
        """Return the final verdict, prompting a human on ASK."""
        decision = self.review(command, user_request)
        if decision.verdict is not Verdict.ASK:
            return decision

        # Hand the ASK to a human (Layer 3).
        human_verdict = self.human_approver(decision)
        if human_verdict not in (Verdict.ALLOW, Verdict.BLOCK):
            # A well-behaved approver only returns ALLOW/BLOCK; be defensive.
            human_verdict = Verdict.BLOCK
        decision.trail.append(f"human: {human_verdict.value}")

        resolved = Decision(
            command=command,
            verdict=human_verdict,
            layer=Layer.HUMAN,
            reason=f"human {'approved' if human_verdict is Verdict.ALLOW else 'rejected'} "
            f"an ASK raised by layer '{decision.layer.value}': {decision.reason}",
            user_request=user_request,
            rule_name=decision.rule_name,
            risk_score=decision.risk_score,
            trail=decision.trail,
        )
        return self._log(resolved)

    # ------------------------------------------------------------------
    # Auditing
    # ------------------------------------------------------------------
    def _log(self, decision: Decision) -> Decision:
        """Append the decision to the JSON-lines audit log (if configured)."""
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(decision.to_dict()) + "\n")
        return decision
