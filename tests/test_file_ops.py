"""Tests for structured file-operation review (agent_watchdog.file_ops)."""

import pytest

from agent_watchdog import FileAction, Verdict, Watchdog


@pytest.fixture
def wd():
    return Watchdog(mode="hybrid")


# --- dangerous shapes that MUST be flagged --------------------------------

@pytest.mark.parametrize(
    "action, expected",
    [
        (FileAction("delete", "/"), Verdict.BLOCK),
        (FileAction("delete", "~"), Verdict.BLOCK),
        (FileAction("delete", "$HOME"), Verdict.BLOCK),
        (FileAction("delete", "build", recursive=True), Verdict.BLOCK),
        (FileAction("delete", "/etc/nginx"), Verdict.BLOCK),
        (FileAction("write", "/etc/hosts"), Verdict.ASK),
        (FileAction("write", "/usr/bin/python"), Verdict.ASK),
        (FileAction("read", "~/.ssh/id_rsa"), Verdict.ASK),
        (FileAction("read", "project/.env"), Verdict.ASK),
        (FileAction("write", ".env"), Verdict.ASK),
        (FileAction("delete", "secrets/service.pem"), Verdict.ASK),
        (FileAction("truncate", "app.log"), Verdict.ASK),
        (FileAction("chmod", "app.py", mode="777"), Verdict.ASK),
        (FileAction("chmod", "config", mode="000"), Verdict.ASK),
        (FileAction("move", "important.db", dest="/dev/null"), Verdict.ASK),
    ],
)
def test_dangerous_file_actions_are_flagged(wd, action, expected):
    decision = wd.review_file_action(action)
    assert decision.verdict is expected, f"{action} -> {decision.verdict} ({decision.reason})"


# --- ordinary operations that MUST be allowed -----------------------------

@pytest.mark.parametrize(
    "action",
    [
        FileAction("read", "README.md"),
        FileAction("read", ".env.example"),          # template, not a secret
        FileAction("write", "output/report.json"),
        FileAction("append", "logs/run.log"),
        FileAction("delete", "tmp/scratch.txt"),      # single, non-recursive
        FileAction("create", "new_module.py"),
        FileAction("copy", "src/a.py", dest="src/b.py"),
        FileAction("move", "old.txt", dest="new.txt"),
        FileAction("chmod", "run.sh", mode="755"),
    ],
)
def test_ordinary_file_actions_are_allowed(wd, action):
    decision = wd.review_file_action(action)
    assert decision.verdict is Verdict.ALLOW, f"{action} -> {decision.verdict} ({decision.reason})"


def test_env_example_is_not_treated_as_secret(wd):
    assert wd.review_file_action(FileAction("read", ".env.example")).verdict is Verdict.ALLOW
    assert wd.review_file_action(FileAction("read", ".env")).verdict is Verdict.ASK


def test_relative_etc_dir_is_not_a_system_path(wd):
    # A project subdirectory literally named "etc/" must not be treated as /etc.
    assert wd.review_file_action(FileAction("write", "etc/config.yaml")).verdict is Verdict.ALLOW
    assert wd.review_file_action(FileAction("write", "/etc/config.yaml")).verdict is Verdict.ASK


def test_file_action_records_layer_and_rule(wd):
    decision = wd.review_file_action(FileAction("delete", "/", recursive=False))
    assert decision.rule_name == "file_delete_root"
    assert decision.layer.value == "rules"


def test_enforce_file_action_routes_ask_to_human():
    approvals = iter([Verdict.ALLOW])
    wd = Watchdog(mode="hybrid", human_approver=lambda d: next(approvals))
    decision = wd.enforce_file_action(FileAction("read", "~/.ssh/id_rsa"))
    assert decision.verdict is Verdict.ALLOW
    assert decision.layer.value == "human"


def test_rules_only_mode_still_applies_file_rules():
    wd = Watchdog(mode="rules_only")
    # Path-based danger is Layer 1, so it fires even without the AI layer.
    assert wd.review_file_action(FileAction("read", "~/.ssh/id_rsa")).verdict is Verdict.ASK
