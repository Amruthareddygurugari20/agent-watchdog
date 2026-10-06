"""Tests for Layer 3 — the human approval flow."""

import builtins

import pytest

from agent_watchdog import (
    Verdict,
    Watchdog,
    always_allow,
    always_block,
    scripted_approver,
)
from agent_watchdog.human import cli_approver
from agent_watchdog.types import Decision, Layer


def _ask_decision():
    return Decision(
        command="git push --force",
        verdict=Verdict.ASK,
        layer=Layer.RULES,
        reason="force push",
        rule_name="git_push_force",
    )


def test_injected_approver_allow():
    wd = Watchdog(mode="hybrid", human_approver=always_allow)
    final = wd.enforce("git push --force origin main", "ship it")
    assert final.verdict is Verdict.ALLOW
    assert final.layer is Layer.HUMAN


def test_injected_approver_block():
    wd = Watchdog(mode="hybrid", human_approver=always_block)
    final = wd.enforce("git push --force origin main", "ship it")
    assert final.verdict is Verdict.BLOCK
    assert final.layer is Layer.HUMAN


def test_scripted_approver_sequence():
    approver = scripted_approver([True, False])
    wd = Watchdog(mode="hybrid", human_approver=approver)
    first = wd.enforce("git reset --hard HEAD~1", "undo")
    second = wd.enforce("kill -9 999", "stop it")
    assert first.verdict is Verdict.ALLOW
    assert second.verdict is Verdict.BLOCK


def test_human_not_consulted_for_block():
    """A hard BLOCK from the rules must never reach the human."""
    calls = []

    def spy(decision):
        calls.append(decision)
        return Verdict.ALLOW

    wd = Watchdog(mode="hybrid", human_approver=spy)
    final = wd.enforce("rm -rf /", "clean up")
    assert final.verdict is Verdict.BLOCK
    assert calls == []  # human never asked to approve a hard block


def test_human_not_consulted_for_allow():
    calls = []

    def spy(decision):
        calls.append(decision)
        return Verdict.BLOCK

    wd = Watchdog(mode="hybrid", human_approver=spy)
    final = wd.enforce("ls -la", "list files")
    assert final.verdict is Verdict.ALLOW
    assert calls == []


def test_cli_approver_yes(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda _prompt="": "y")
    assert cli_approver(_ask_decision()) is Verdict.ALLOW


@pytest.mark.parametrize("answer", ["n", "no", "", "maybe", "nope"])
def test_cli_approver_non_yes_is_block(monkeypatch, answer):
    monkeypatch.setattr(builtins, "input", lambda _prompt="": answer)
    assert cli_approver(_ask_decision()) is Verdict.BLOCK


def test_cli_approver_eof_fails_safe(monkeypatch):
    def _raise(_prompt=""):
        raise EOFError

    monkeypatch.setattr(builtins, "input", _raise)
    assert cli_approver(_ask_decision()) is Verdict.BLOCK
