# Security Policy

agent-watchdog is a safety control for AI coding agents, so its own
trustworthiness matters. If you find a vulnerability — a bypass that lets a
dangerous action through, a way to make the guard wrongly return `ALLOW`, or any
issue in the project's own code — please report it.

## Supported versions

The project is pre-1.0 and moves fast. Fixes land on the `main` branch; please
test against the latest `main` before reporting.

| Version          | Supported |
| ---------------- | :-------: |
| `main` (latest)  |    ✅     |
| older tags       |    ❌     |

## Reporting a vulnerability

Please **do not open a public issue for a security bypass.** Instead:

1. Use GitHub's [private vulnerability reporting](https://github.com/Amruthareddygurugari20/agent-watchdog/security/advisories/new)
   (the **Security** tab → *Report a vulnerability*), or
2. email the maintainer at the address on the GitHub profile.

Please include a minimal reproduction: the exact command or `FileAction`, the
mode (`rules_only` / `hybrid`), the verdict you got, and the verdict you
expected.

## Scope

A **bypass** is a dangerous action that agent-watchdog returns `ALLOW` for (or
fails to escalate to `ASK` / `BLOCK`). Some bypasses are **known and documented**
in the README's "Limitations" and adversarial stress-test sections — commands
assembled entirely at runtime (e.g. `p=r;c=m;${p}${c} -rf /`) are invisible to
any text guard by construction and are out of scope. A *new* class of bypass
that the stress test does not already surface is very much in scope.

## Response

You can expect an acknowledgement within a few days. Confirmed issues are fixed
on `main`, with a benchmark or stress-test case added so the gap stays closed.
Reporters are credited unless they ask otherwise.
