"""Layer 1 — fixed, deterministic rules (NO AI).

This is the reliable safety backbone. Every rule is a regular expression paired
with a verdict and a plain-English reason. Matching is dumb on purpose: no
model, no network, no randomness. If a rule fires, we know *exactly* why.

Design choices
--------------
* BLOCK is reserved for actions that are obviously, unrecoverably destructive
  (wiping a disk, deleting a filesystem, dropping a table). There is almost no
  legitimate reason for an autonomous agent to run these unprompted.
* ASK is for actions that are dangerous but *sometimes* genuinely intended
  (force-push, reset --hard, reading secrets, remote installers). A human is the
  right arbiter, so we escalate rather than veto.

Rules are just data — extend :data:`RULES` to cover more cases. Order matters
only in that the FIRST match wins, so keep the most specific / most dangerous
patterns near the top.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .types import Verdict


@dataclass(frozen=True)
class Rule:
    """A single deterministic rule.

    Attributes
    ----------
    name:     short stable identifier (shows up in logs).
    pattern:  compiled, case-insensitive regex tested against the command.
    verdict:  BLOCK or ASK when the pattern matches.
    reason:   human-readable explanation of the danger.
    """

    name: str
    pattern: re.Pattern
    verdict: Verdict
    reason: str


def _rx(pattern: str) -> re.Pattern:
    """Compile a pattern case-insensitively (commands vary in casing)."""
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# The rule list. Grouped by intent and commented so contributors can audit and
# extend it confidently. FIRST match wins.
# ---------------------------------------------------------------------------
RULES: list[Rule] = [
    # --- Recursive / forced file deletion --------------------------------
    Rule(
        "rm_rf",
        # rm with a recursive flag AND a force flag, in any order/combination
        # (e.g. "rm -rf", "rm -fr", "rm -r -f", "rm --recursive --force").
        _rx(r"\brm\b(?=.*(-[a-z]*r|--recursive))(?=.*(-[a-z]*f|--force))"),
        Verdict.BLOCK,
        "Recursive, forced file deletion (rm -rf) can wipe entire trees "
        "irreversibly.",
    ),
    Rule(
        "rm_root_slash",
        # rm -r targeting the filesystem root, /*, or a bare home wipe.
        _rx(r"\brm\b.*\s(/|/\*|~|~/\*)(\s|$)"),
        Verdict.BLOCK,
        "Deletion targeting the filesystem root or home directory.",
    ),
    Rule(
        "rm_recursive",
        # rm with a recursive flag but NOT force (the -rf case is caught above
        # and BLOCKed). Recursive delete still wipes a whole tree, so ASK.
        _rx(r"\brm\b(?=.*(-[a-z]*r|--recursive))"),
        Verdict.ASK,
        "Recursive delete (rm -r) removes an entire directory tree.",
    ),
    # --- Filesystem / disk destruction -----------------------------------
    Rule(
        "mkfs",
        _rx(r"\bmkfs(\.\w+)?\b"),
        Verdict.BLOCK,
        "Creating a new filesystem (mkfs) erases everything on the target "
        "device.",
    ),
    Rule(
        "dd_to_disk",
        # dd writing to a raw block device (/dev/sd?, /dev/nvme?, /dev/disk?).
        _rx(r"\bdd\b.*of=\s*/dev/(sd|nvme|disk|hd|vd)"),
        Verdict.BLOCK,
        "dd writing directly to a disk device overwrites it at the block "
        "level.",
    ),
    Rule(
        "wipe_tools",
        _rx(r"\b(wipefs|shred|blkdiscard)\b"),
        Verdict.BLOCK,
        "Low-level disk/file wiping tool — data is unrecoverable.",
    ),
    Rule(
        "redirect_to_disk",
        _rx(r">\s*/dev/(sd|nvme|disk|hd|vd)\w*"),
        Verdict.BLOCK,
        "Redirecting output straight onto a disk device corrupts it.",
    ),
    # --- Fork bomb --------------------------------------------------------
    Rule(
        "fork_bomb",
        # The classic :(){ :|:& };:  and light obfuscations of it.
        _rx(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        Verdict.BLOCK,
        "Fork bomb — spawns processes until the machine is unusable.",
    ),
    # --- SQL destruction --------------------------------------------------
    Rule(
        "sql_drop_truncate",
        _rx(r"\b(drop\s+(table|database|schema)|truncate\s+table)\b"),
        Verdict.BLOCK,
        "DROP/TRUNCATE destroys database objects and their data.",
    ),
    Rule(
        "sql_delete_no_where",
        # DELETE FROM <table> that is NOT followed by a WHERE clause.
        _rx(r"\bdelete\s+from\s+\w+\s*(;|$)(?!.*\bwhere\b)"),
        Verdict.BLOCK,
        "DELETE without a WHERE clause removes every row in the table.",
    ),
    # --- Git foot-guns (recoverable-ish, so ASK not BLOCK) ---------------
    Rule(
        "git_push_force",
        _rx(r"\bgit\s+push\b.*(--force\b|--force-with-lease\b|\s-f\b)"),
        Verdict.ASK,
        "Force-push can overwrite shared history on the remote.",
    ),
    Rule(
        "git_reset_hard",
        _rx(r"\bgit\s+reset\b.*--hard\b"),
        Verdict.ASK,
        "git reset --hard discards uncommitted work permanently.",
    ),
    Rule(
        "git_clean",
        _rx(r"\bgit\s+clean\b.*-[a-z]*f"),
        Verdict.ASK,
        "git clean -f deletes untracked files that git cannot recover.",
    ),
    Rule(
        "git_checkout_discard",
        # `git checkout -- <path>` or `git checkout .` throws away local edits.
        # A plain `git checkout <branch>` (no '--' and no bare '.') is NOT
        # matched, so switching branches stays allowed.
        _rx(r"\bgit\s+checkout\b[^\n]*(\s--\s|\s\.\s*$)"),
        Verdict.ASK,
        "git checkout -- / . discards uncommitted changes in the working tree.",
    ),
    # --- Permissions / ownership -----------------------------------------
    Rule(
        "chmod_777",
        _rx(r"\bchmod\b.*(-R\s*)?\b0?777\b"),
        Verdict.ASK,
        "chmod 777 makes files world-writable — a security risk.",
    ),
    Rule(
        "chown_recursive",
        _rx(r"\bchown\b.*-R\b"),
        Verdict.ASK,
        "Recursive ownership change can lock you out of files.",
    ),
    # --- Process / power control -----------------------------------------
    Rule(
        "kill_9",
        # kill / killall / pkill sending SIGKILL, whether written as "-9" or
        # "-s 9" / "-s SIGKILL". The alternation must list "killall" before it
        # can be mistaken for "kill", and \b handles the word split correctly.
        _rx(r"\b(kill|killall|pkill)\b.*(-9\b|-s(ig)?\s*(9|SIGKILL)\b)"),
        Verdict.ASK,
        "kill -9 force-terminates processes, risking data loss/corruption.",
    ),
    Rule(
        "power_control",
        _rx(r"\b(shutdown|reboot|halt|poweroff|init\s+0|init\s+6)\b"),
        Verdict.ASK,
        "Powering off or rebooting the machine interrupts everything running.",
    ),
    # --- Remote code execution -------------------------------------------
    Rule(
        "curl_pipe_shell",
        # curl/wget ... | sh|bash — running unreviewed remote code.
        _rx(r"\b(curl|wget)\b.*\|\s*(sudo\s+)?(ba|z|k)?sh\b"),
        Verdict.ASK,
        "Piping a downloaded script straight into a shell runs unreviewed "
        "remote code.",
    ),
    # --- Secret exfiltration / reads -------------------------------------
    Rule(
        "read_ssh_keys",
        _rx(r"(~|/root|/home/\w+)?/?\.ssh/(id_\w+|.*key)"),
        Verdict.ASK,
        "Accessing private SSH keys — sensitive credential material.",
    ),
    Rule(
        "read_dotenv",
        # cat/less/etc. of a .env file (secrets), but not '.env.example'.
        _rx(r"\b(cat|less|more|head|tail|cp|scp|curl\s+-T)\b[^\n]*\.env\b(?!\.example)"),
        Verdict.ASK,
        "Reading or copying a .env file exposes application secrets.",
    ),
    Rule(
        "read_cloud_creds",
        _rx(r"\.aws/credentials|\.config/gcloud|/etc/shadow|/etc/passwd"),
        Verdict.ASK,
        "Accessing cloud credentials or system account files.",
    ),
    # --- Sudo privilege escalation (context-dependent, so ASK) -----------
    Rule(
        "sudo_su",
        _rx(r"\bsudo\s+su\b|\bsudo\s+-i\b|\bsu\s+-\s*$|\bsu\s+root\b"),
        Verdict.ASK,
        "Escalating to a root shell grants unrestricted system access.",
    ),
]


# Quotes wedged *between* two word characters (e.g. the '' in `r''m`) are almost
# always obfuscation — no one quotes the middle of a command name for a real
# reason. Quotes that wrap whole arguments (e.g. "DELETE FROM" in a grep) are
# preceded/followed by whitespace, so this pattern leaves them alone and we
# avoid turning a safe `grep "DROP TABLE"` into a false alarm.
_WORD_ADJ_QUOTES = re.compile(r"(?<=\w)['\"]+(?=\w)")


def _normalize(command: str) -> str:
    """Undo cheap shell obfuscation that does NOT change what actually runs.

    The shell treats ``\\rm``, ``r''m`` and ``rm`` identically, so a text guard
    that only sees the literal spelling can be trivially bypassed. We strip:

    * backslashes used to escape/split tokens (``\\rm``, ``rm\\ -rf``), and
    * word-adjacent quotes (``r''m`` -> ``rm``).

    The result is used ONLY for matching — we never execute it — so being
    aggressive here is safe. We deliberately keep argument-wrapping quotes
    intact to avoid false alarms.
    """
    s = command.replace("\\", "")
    s = _WORD_ADJ_QUOTES.sub("", s)
    return s


def check_rules(command: str) -> Optional[Rule]:
    """Return the FIRST rule that matches ``command``, or ``None``.

    This function is the entire Layer 1 API. It is pure and side-effect free:
    given the same command it always returns the same rule, which is exactly
    the property we want from a safety backbone.

    Each rule is tested against both the raw command and a de-obfuscated
    ("normalized") copy, so trivial evasions like ``r''m -rf /`` or ``\\rm`` are
    still caught without changing the verdict for legitimately-quoted commands.
    """
    if not command:
        return None
    norm = _normalize(command)
    for rule in RULES:
        if rule.pattern.search(command):
            return rule
        if norm != command and rule.pattern.search(norm):
            return rule
    return None
