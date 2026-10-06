#!/usr/bin/env python3
"""A tiny end-to-end demo of agent-watchdog.

Run it with:  python demo.py

It shows the watchdog deciding on both shell commands and structured file
operations, across all three layers, without needing a human at the prompt.
"""

from agent_watchdog import FileAction, Watchdog


def show(label, decision):
    print(f"  {decision.verdict.value:6} [{decision.layer.value:7}] {label}")
    print(f"         └─ {decision.reason}")


def main():
    wd = Watchdog(mode="hybrid")

    print("\nShell commands")
    print("-" * 66)
    commands = [
        ("rm -rf /", "clean up the project"),
        ("ls -la", "list the files"),
        ("find . -delete", "list the files"),          # novel danger (AI layer)
        ("git push --force origin main", "ship my work"),
        ("kubectl delete namespace production", "reset the dev cluster"),
        ("cat README.md", "read the docs"),
    ]
    for cmd, req in commands:
        show(cmd, wd.review(cmd, req))

    print("\nStructured file operations")
    print("-" * 66)
    actions = [
        FileAction("delete", "node_modules", recursive=True),
        FileAction("read", "~/.ssh/id_rsa"),
        FileAction("write", "/etc/hosts"),
        FileAction("write", "dist/app.js"),
        FileAction("read", ".env.example"),
        FileAction("chmod", "server.py", mode="777"),
    ]
    for action in actions:
        show(action.to_command(), wd.review_file_action(action))

    print()


if __name__ == "__main__":
    main()
