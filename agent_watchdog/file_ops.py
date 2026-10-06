"""File operations as first-class actions.

The watchdog's spec covers "a shell command *or file operation*". Everything
else in the package inspects command *strings*; this module lets a caller pass a
**structured** file operation instead — ``FileAction(op="delete", path=...)`` —
so an agent framework that already knows it's about to delete a path doesn't
have to render (and we don't have to re-parse) a shell string.

Danger for a file operation comes from three things, and this layer reasons
about them directly rather than by keyword:

1. **The path** — secrets (`~/.ssh`, `.env`, `*.pem`), protected system
   locations (`/etc`, `/usr`, `/dev`), or the root/home directory itself.
2. **Recursion** — a recursive delete is `rm -rf` by another name.
3. **The verb** — truncating empties a file; loosening permissions is risky.

Plain creation or reading of an ordinary project file is intentionally allowed:
agents write files constantly, and flagging every write would make the guard
useless. Only the genuinely dangerous shapes above are escalated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .types import Verdict

# --- path classifiers (deterministic, case-insensitive) --------------------

# Secret / credential material anywhere in the path. `.env` matches but
# `.env.example` does not (a common, safe template file).
_SECRET = re.compile(
    r"(^|/)\.(ssh|aws|gnupg)(/|$)"          # secret directories
    r"|(^|/)\.env(?!\.example)($|[^\w])"      # .env but not .env.example
    r"|(^|/)id_(rsa|dsa|ecdsa|ed25519)\b"     # private keys
    r"|\.(pem|key|p12|pfx)$"                   # key/cert files
    r"|/etc/(shadow|passwd|sudoers)\b"         # system account files
    r"|(^|/)credentials$",                     # cloud credential files
    re.I,
)

# Protected system locations — only ABSOLUTE paths, so a project subdirectory
# that merely happens to be named "etc/" is not swept up (avoids false alarms).
_SYSTEM = re.compile(
    r"^/(etc|bin|sbin|boot|sys|proc|usr|lib|lib64|var/lib)(/|$)|^/dev/",
    re.I,
)

# The filesystem root or a home directory as the whole target (optionally "/*").
_ROOT_HOME = re.compile(r"^\s*(/|~|~/|\$HOME/?|/root/?)\*?\s*$", re.I)

# The delete-family of verbs, however the caller spells them.
_DELETE_OPS = {"delete", "remove", "rm", "unlink"}


@dataclass
class FileAction:
    """A structured file operation an agent proposes to perform.

    Parameters
    ----------
    op:        one of read, write, append, truncate, delete, chmod, move, copy.
    path:      the primary path acted on.
    dest:      destination path (for move/copy).
    recursive: whether the op recurses into directories.
    mode:      permission mode for chmod (e.g. "777").
    """

    op: str
    path: str
    dest: str = ""
    recursive: bool = False
    mode: str = ""

    def to_command(self) -> str:
        """Render an equivalent shell command (for logging + the AI fallback)."""
        op = self.op.lower().strip()
        p = self.path
        if op == "read":
            return f"cat {p}"
        if op == "write":
            return f"tee {p}"
        if op == "append":
            return f"tee -a {p}"
        if op == "truncate":
            return f"truncate -s 0 {p}"
        if op in _DELETE_OPS:
            return f"rm {'-rf ' if self.recursive else ''}{p}"
        if op == "chmod":
            return f"chmod {'-R ' if self.recursive else ''}{self.mode} {p}".strip()
        if op in ("move", "mv"):
            return f"mv {p} {self.dest}"
        if op in ("copy", "cp"):
            return f"cp {'-r ' if self.recursive else ''}{p} {self.dest}"
        return f"{op} {p}"


# Result of the file-op rules: (verdict, reason, rule_name) or None.
FileRule = Optional[tuple]


def check_file_action(action: FileAction) -> FileRule:
    """Deterministic Layer-1 checks for a structured file operation.

    Returns ``(verdict, reason, rule_name)`` when a rule fires, else ``None``
    (meaning "nothing dangerous about the path/verb itself" — the caller may
    then fall back to the normal command review of ``to_command()``).
    """
    op = action.op.lower().strip()
    path = (action.path or "").strip()
    dest = (action.dest or "").strip()
    is_delete = op in _DELETE_OPS

    # 1. Catastrophic: deleting the root or a home directory.
    if is_delete and _ROOT_HOME.match(path):
        return (Verdict.BLOCK,
                "Deleting the filesystem root or home directory.",
                "file_delete_root")

    # 2. Recursive delete is `rm -rf` semantics regardless of target.
    if is_delete and action.recursive:
        return (Verdict.BLOCK,
                "Recursive delete removes an entire directory tree irreversibly.",
                "file_delete_recursive")

    # 3. Touching a protected SYSTEM path.
    if _SYSTEM.search(path) or (dest and _SYSTEM.search(dest)):
        if is_delete:
            return (Verdict.BLOCK,
                    "Deleting a protected system path.",
                    "file_delete_system")
        if op != "read":
            return (Verdict.ASK,
                    "Modifying a protected system path.",
                    "file_write_system")

    # 4. Touching a SECRET / credential file.
    if _SECRET.search(path) or (dest and _SECRET.search(dest)):
        if op == "read":
            return (Verdict.ASK,
                    "Reading a secret or credential file.",
                    "file_read_secret")
        return (Verdict.ASK,
                "Writing to, moving, or deleting a secret or credential file.",
                "file_touch_secret")

    # 5. Truncation empties an existing file's contents.
    if op == "truncate":
        return (Verdict.ASK,
                "Truncating a file discards its current contents.",
                "file_truncate")

    # 6. Loosening / removing permissions.
    if op == "chmod" and re.search(r"\b0?(777|666|000)\b", action.mode or ""):
        return (Verdict.ASK,
                "Setting world-writable or no-access permissions.",
                "file_chmod")

    # 7. Moving/copying a file into /dev/null (a disguised delete).
    if dest and re.search(r"/dev/null\b", dest):
        return (Verdict.ASK,
                "Moving or copying a file into /dev/null destroys it.",
                "file_devnull")

    return None
