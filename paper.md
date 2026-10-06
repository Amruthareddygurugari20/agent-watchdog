---
title: "agent-watchdog: A layered, open safety gate for AI coding agents"
tags:
  - Python
  - AI safety
  - LLM agents
  - guardrails
  - software security
authors:
  - name: agent-watchdog contributors
    affiliation: 1
affiliations:
  - name: Independent
    index: 1
date: 27 July 2026
bibliography: paper.bib
---

# Summary

AI coding agents increasingly run shell commands and edit files on a user's
behalf. This autonomy is useful, but it introduces a new failure mode: an agent
may execute a destructive action — deleting a directory tree, wiping a disk,
dropping a database table, force-pushing over shared history, or exfiltrating a
secret — either because it misunderstood the task, hallucinated a step, or was
manipulated through prompt injection. `agent-watchdog` is a small, dependency-free
Python library that inspects a proposed action *before* it runs and returns one
of three verdicts: **ALLOW**, **BLOCK**, or **ASK a human**.

Its design principle is *rules + AI + human, never AI alone*. Three layers are
consulted in order: (1) a deterministic rule engine that pattern-matches known
dangerous actions; (2) a pluggable AI "second opinion" that scores novel or
obfuscated dangers the rules do not cover; and (3) a human approver that resolves
any uncertain case. Crucially, a language model is never the sole gate on a
destructive action. The library runs entirely on the Python standard library —
no model download, no API key — so the safety mechanism itself has no external
point of failure. An optional open-weights local model can be enabled for the AI
layer, but no proprietary API is ever required.

# Statement of need

The rapid deployment of autonomous coding agents has outpaced the tooling to keep
them safe. Existing safeguards tend to fall into two camps, each with a gap that
`agent-watchdog` targets.

First, **allowlist/denylist wrappers** built into individual agent frameworks are
typically deterministic and hard-coded, catching textbook commands such as
`rm -rf /` while missing semantically equivalent but syntactically novel ones —
`find . -delete`, a `shutil.rmtree` one-liner, `aws s3 rm --recursive`,
`kubectl delete namespace`, or in-place truncation via `> file`. Because they are
embedded in a specific tool, they are also difficult to audit, reuse, or
benchmark independently.

Second, **model-based guardrails** delegate the safety judgment to another
language model. This catches more novel cases, but makes the guard itself
non-deterministic, opaque, dependent on a paid API, and — most importantly —
vulnerable to the same prompt-injection and jailbreak failures it is meant to
prevent. A guard that can be talked out of blocking is not a reliable guard.

`agent-watchdog` addresses both gaps with a layered architecture that is
explicit about what each layer can and cannot do. The deterministic layer
provides a reliable, auditable backbone that no model can override. The AI layer
adds coverage of novel dangers but is confined to *raising* concern (escalating
to a human), never to silently permitting an action. The human layer provides the
final judgment precisely where automated methods are least trustworthy. The whole
system is a standalone, framework-agnostic library with a public benchmark, so
its accuracy can be measured and improved in the open rather than hidden inside a
product.

The project is aimed at three audiences: developers building or operating coding
agents who need a drop-in pre-execution check; researchers studying agent safety
who need a reproducible, extensible baseline; and educators who need a small,
readable example of defense-in-depth for autonomous systems.

# Functionality

The core object is `Watchdog`, which exposes two methods. `review(command,
user_request)` returns the *machine* decision (ALLOW/ASK/BLOCK) without human
involvement; `enforce(command, user_request)` additionally routes any ASK to a
human approver, yielding a terminal ALLOW or BLOCK. Two modes support direct
comparison: `rules_only` (Layer 1 only, the baseline) and `hybrid` (all three
layers).

**Layer 1 — rules.** Layer 1 is a data-driven list of regular-expression rules,
each paired with a verdict and a plain-English reason. BLOCK is reserved for
obviously unrecoverable destruction (filesystem wipes, `mkfs`, `dd` to a disk,
fork bombs, `DROP`/`TRUNCATE`/`DELETE`-without-`WHERE`); ASK is used for
dangerous-but-sometimes-intended actions (`git push --force`, `git reset --hard`,
`chmod 777`, `kill -9`, power control, `curl | bash`, and reads of `~/.ssh` or
`.env`). The layer is pure and deterministic: the same input always yields the
same verdict, which is the property one wants from a safety backbone.

**Layer 2 — AI second opinion.** Layer 2 is defined by a one-method interface,
`AIJudge.assess`, and ships with two implementations. `HeuristicJudge` (the
default) is a transparent, model-free scorer: it sums weighted keyword and
pattern signals — programmatic deletion, recursive cloud/cluster deletes, history
rewriting, redirection-based truncation, exfiltration, reverse shells — and flags
an action risky above a tunable threshold, reporting every signal that
contributed. It also applies a small "out-of-scope" nudge when a destructive
command shares no vocabulary with the stated user request. `LocalLLMJudge`
implements the same interface using an open-weights instruction-tuned model via
`transformers`; it is optional and lazily imported, so the package works with
zero machine-learning dependencies.

**Layer 3 — human.** A human approver is any callable mapping a `Decision` to an
ALLOW/BLOCK verdict. The library ships an interactive CLI approver that prints the
command, the flagging layer, and the reason, then prompts the operator, failing
safe (BLOCK) on any non-affirmative or missing input. Test and automation helpers
(`always_allow`, `always_block`, `scripted_approver`) allow the human step to be
simulated deterministically.

Every decision carries a full audit trail and can be appended to a JSON-lines log,
recording the command, verdict, deciding layer, reason, and any rule name or risk
score.

**Evaluation.** A labeled benchmark (`benchmark/commands.csv`) tags each command
as `safe`, `known` (dangerous, rule-covered), or `novel` (dangerous, not in the
rules). `evaluate.py` runs both modes over it and reports catch rate (recall on
dangerous commands), false-alarm rate (safe commands wrongly flagged), and catch
rate broken down by category — then prints an honest list of dangerous commands
the hybrid system still misses. On the bundled benchmark, adding the AI layer
raises the catch rate from 51% (rules only) to 100% (novel-danger recall from 0%
to 100%) with no increase in false alarms. We caution that a perfect score on a
project's own benchmark is weak evidence: because coverage is added whenever a
miss is found, the benchmark converges to 100% by construction. The more
demanding evidence is `stress_test.py`, an adversarial harness of 162 curated
cases plus whitespace and combinatorial fuzzers (~500 evaluations) covering
obfuscation, evasion, novel dangers, false-alarm traps, and edge cases. It holds
at 100% on every category the guard can inspect and 0 false alarms, while
deliberately exhibiting two boundaries. First, an `inherent` class of
runtime-assembled commands: where the indirection is *detectable* (`eval`,
`bash -c "$(…)"`, a command that is wholly a substitution) the guard flags it as
unanalyzable and escalates to a human, but a command assembled purely from
variable expansion with no execution primitive (`p=r;c=m;${p}${c} -rf /`)
contains no dangerous token at all and is the irreducible ceiling of text
inspection. Second, a small `mention` class of safe commands that merely name a
dangerous literal and are conservatively over-flagged. Reporting
these boundaries is deliberate: the tool reduces risk rather than eliminating it,
and its central limitation — that a text guard cannot control what an executed
command actually does — is documented prominently. This is precisely why the
human layer, and out-of-band controls such as sandboxing and least privilege,
remain essential.

# Acknowledgements

This project builds on the broader open-source AI-safety and secure-shell
communities and welcomes contributions of new rules, benchmark cases, and,
especially, bypasses.

# References
