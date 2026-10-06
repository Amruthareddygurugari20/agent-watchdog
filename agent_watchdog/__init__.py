"""agent-watchdog — an open safety watchdog for AI coding agents.

Inspect an action a coding agent wants to take (a shell command or file
operation) and decide ALLOW, BLOCK, or ASK-a-human *before* it runs, using three
layers: deterministic rules, a pluggable AI second opinion, and a human.

Quick start
-----------
>>> from agent_watchdog import Watchdog
>>> wd = Watchdog(mode="hybrid")
>>> wd.review("rm -rf /").verdict.value
'BLOCK'
>>> wd.review("ls -la").verdict.value
'ALLOW'
"""

from .ai_judge import AIJudge, Assessment, HeuristicJudge, LocalLLMJudge
from .file_ops import FileAction, check_file_action
from .human import (
    always_allow,
    always_block,
    cli_approver,
    scripted_approver,
)
from .rules import RULES, Rule, check_rules
from .types import Decision, Layer, Verdict
from .watchdog import Watchdog

__version__ = "0.1.0"

__all__ = [
    "Watchdog",
    "Verdict",
    "Layer",
    "Decision",
    "Assessment",
    "AIJudge",
    "HeuristicJudge",
    "LocalLLMJudge",
    "Rule",
    "RULES",
    "check_rules",
    "FileAction",
    "check_file_action",
    "cli_approver",
    "always_allow",
    "always_block",
    "scripted_approver",
    "__version__",
]
