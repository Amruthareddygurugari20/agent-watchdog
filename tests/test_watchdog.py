"""Tests for the Watchdog orchestrator, modes, and audit logging."""

import json

import pytest

from agent_watchdog import Verdict, Watchdog, always_block
from agent_watchdog.types import Layer


def test_invalid_mode_raises():
    with pytest.raises(ValueError):
        Watchdog(mode="magic")


def test_rules_only_blocks_known_danger():
    wd = Watchdog(mode="rules_only")
    assert wd.review("rm -rf /").verdict is Verdict.BLOCK


def test_rules_only_allows_novel_danger():
    """The baseline is EXPECTED to miss novel dangers — that's why we have L2."""
    wd = Watchdog(mode="rules_only")
    d = wd.review("find . -delete", "list files")
    assert d.verdict is Verdict.ALLOW
    assert d.layer is Layer.DEFAULT_ALLOW


def test_hybrid_catches_novel_danger_as_ask():
    wd = Watchdog(mode="hybrid")
    d = wd.review("find . -delete", "list files")
    assert d.verdict is Verdict.ASK
    assert d.layer is Layer.AI


def test_hybrid_allows_genuinely_safe_command():
    wd = Watchdog(mode="hybrid")
    d = wd.review("ls -la", "list files")
    assert d.verdict is Verdict.ALLOW


def test_rules_take_precedence_over_ai():
    """A rule match short-circuits before the AI judge runs."""
    wd = Watchdog(mode="hybrid")
    d = wd.review("rm -rf /", "clean up")
    assert d.layer is Layer.RULES
    assert d.rule_name == "rm_rf"
    assert d.risk_score is None  # AI judge never ran


def test_decision_trail_is_populated():
    wd = Watchdog(mode="hybrid")
    d = wd.review("find . -delete", "list files")
    assert any("rules:" in t for t in d.trail)
    assert any("ai:" in t for t in d.trail)


def test_audit_log_is_written(tmp_path):
    log = tmp_path / "audit.jsonl"
    wd = Watchdog(mode="hybrid", log_path=log)
    wd.review("rm -rf /")
    wd.review("ls -la")
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["verdict"] == "BLOCK"
    assert first["command"] == "rm -rf /"
    assert "trail" in first


def test_enforce_resolves_ask_via_human(tmp_path):
    wd = Watchdog(mode="hybrid", human_approver=always_block, log_path=tmp_path / "l.jsonl")
    d = wd.enforce("git push --force origin main", "ship")
    assert d.verdict is Verdict.BLOCK
    assert d.layer is Layer.HUMAN


def test_review_never_prompts_human():
    """review() must be side-effect free w.r.t. the human (used by the benchmark)."""
    def exploding_approver(decision):
        raise AssertionError("review() must not call the human")

    wd = Watchdog(mode="hybrid", human_approver=exploding_approver)
    # These would each be ASK; review must not invoke the approver.
    wd.review("git push --force origin main")
    wd.review("find . -delete", "list files")
