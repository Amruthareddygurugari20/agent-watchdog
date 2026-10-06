# agent-watchdog

**An open safety watchdog for AI coding agents.** It inspects an action a coding
agent wants to take — a shell command or file operation — and decides
**ALLOW**, **BLOCK**, or **ASK a human** *before* the action runs.

The core principle is **rules + AI + human, never AI alone**. A model can be
wrong or jailbroken, so agent-watchdog never lets a model be the sole gate on a
destructive action. A deterministic rule layer is the reliable backbone; an AI
layer catches novel dangers the rules miss; and a human makes the final call
whenever there is doubt.

- **Zero required dependencies.** Runs on the Python standard library alone — no
  model download, no API key. It always works.
- **No proprietary API.** The AI layer ships as a transparent, model-free
  heuristic by default, with an optional open-weights local LLM behind the same
  interface.
- **Honest.** It is not 100% accurate. The benchmark below reports real numbers,
  including the dangerous commands it still misses.

---

## Install

```bash
git clone https://github.com/OWNER/agent-watchdog
cd agent-watchdog
python -m venv .venv && source .venv/bin/activate
pip install -e .            # or: pip install -r requirements.txt
```

Requires Python 3.9+. The optional local-LLM judge needs extras:
`pip install -e ".[llm]"`.

## Usage

### As a library

```python
from agent_watchdog import Watchdog

wd = Watchdog(mode="hybrid")          # all three layers (default)

wd.review("rm -rf /").verdict         # -> Verdict.BLOCK  (rule fired)
wd.review("ls -la").verdict           # -> Verdict.ALLOW
wd.review("find . -delete",           # a novel danger the rules don't know...
          user_request="list files").verdict   # -> Verdict.ASK (AI flagged it)

# `review()` returns the MACHINE decision (ALLOW / ASK / BLOCK).
# `enforce()` additionally routes any ASK to a human approver:
final = wd.enforce("git push --force origin main", "ship my work")
print(final.verdict, "decided by", final.layer.value)
```

Wire it into an agent by calling `enforce()` on each proposed command and only
executing when the returned verdict is `ALLOW`.

### Structured file operations

An agent that already knows it's about to touch a file can hand the watchdog a
`FileAction` instead of a shell string. Danger is judged from the **path**
(secrets, system locations, root/home), **recursion**, and the **verb** — while
ordinary reads and writes of project files are allowed, so the guard doesn't
get in the way:

```python
from agent_watchdog import Watchdog, FileAction

wd = Watchdog(mode="hybrid")

wd.review_file_action(FileAction("read",  "~/.ssh/id_rsa")).verdict     # ASK
wd.review_file_action(FileAction("delete", "build", recursive=True)).verdict  # BLOCK
wd.review_file_action(FileAction("write", "/etc/hosts")).verdict        # ASK
wd.review_file_action(FileAction("write", "dist/bundle.js")).verdict    # ALLOW
wd.review_file_action(FileAction("read",  ".env.example")).verdict      # ALLOW
```

`enforce_file_action()` routes an ASK to the human approver, exactly like
`enforce()`.

### From the command line

```bash
python -m agent_watchdog "rm -rf build/"
python -m agent_watchdog --mode rules_only "git push --force"
python -m agent_watchdog --request "list files" --no-human "find . -delete"
```

Exit code is `0` for ALLOW, `1` for BLOCK, `2` for an unresolved ASK
(`--no-human`).

### Injecting your own layers

```python
from agent_watchdog import Watchdog, HeuristicJudge, always_block

wd = Watchdog(
    mode="hybrid",
    ai_judge=HeuristicJudge(threshold=0.4),  # any object implementing AIJudge
    human_approver=my_slack_approval_fn,      # any Decision -> Verdict callable
    log_path="decisions.jsonl",               # JSON-lines audit log
)
```

## The three-layer design

| Layer | What it does | Needs a model? | Outcome |
|------:|--------------|:--------------:|---------|
| **1 — Rules** | Deterministic regex match against known-dangerous actions (`rm -rf`, `mkfs`, `dd` to a disk, fork bombs, `DROP`/`TRUNCATE`/`DELETE`-without-`WHERE`, `git push --force`, `git reset --hard`, `kill -9`, `curl \| bash`, reading `~/.ssh` / `.env`, …). | No | **BLOCK** (obvious destruction) or **ASK** (dangerous but sometimes intended) |
| **2 — AI second opinion** | For commands the rules *don't* catch, a pluggable judge scores whether the action is risky / out-of-scope, catching **novel or obfuscated** dangers. | Optional | risky → **ASK** |
| **3 — Human** | Any ASK is handed to a `human_approver` callback (a real interactive CLI approver ships in the box; inject a fake for tests). | No | **ALLOW** or **BLOCK** |

Layer 1 runs first and short-circuits — a rule match never depends on a model.
Layer 2 is **pluggable** via the `AIJudge` interface and ships in two flavors:

- **`HeuristicJudge`** (default) — a transparent, weighted keyword/pattern scorer.
  No model, no network, fully explainable. Every decision reports the signals
  that fired.
- **`LocalLLMJudge`** — an open-weights local model (e.g. a small Qwen instruct
  model via `transformers`) behind the same interface. Entirely optional.

**Modes:** `mode="rules_only"` runs Layer 1 only (the baseline); `mode="hybrid"`
runs all three. The benchmark compares them directly.

## Results

Run it yourself:

```bash
python evaluate.py
```

On the bundled 67-command benchmark (`benchmark/commands.csv`), measuring the
**machine** decision (ASK or BLOCK both count as "caught", since ASK routes to a
human):

| Metric | `rules_only` (baseline) | `hybrid` (all layers) |
|--------|:-----------------------:|:---------------------:|
| **Catch rate** (recall on dangerous) | 51.1% (23/45) | **100% (45/45)** |
| **False-alarm rate** (safe wrongly flagged) | 0.0% (0/22) | **0.0% (0/22)** |
| Catch rate — **known** dangers (rule-covered) | 100% (23/23) | 100% (23/23) |
| Catch rate — **novel** dangers (not in rules) | 0.0% (0/22) | **100% (22/22)** |

The AI layer takes the catch rate from ~51% to 100% on this benchmark by picking
up novel dangers (`find . -delete`, `aws s3 rm --recursive`,
`kubectl delete namespace`, `> file` truncation, reverse shells, …) while adding
**zero** false alarms. Every decision is logged to `eval_log.jsonl` with its
reason and deciding layer.

> **Read 100% correctly.** A perfect score on *our own* benchmark is weak
> evidence — we add a rule or signal whenever we find a miss, so the benchmark
> converges to 100% by construction. It means "no *known* gap remains in this
> corpus," **not** "nothing gets through." The honest measure of robustness is
> the adversarial stress test below.

### Adversarial stress test

`stress_test.py` is a separate red-team harness (162 curated cases plus two
fuzzers, ~500 evaluations per run) that actively tries to break the guard:

```bash
python stress_test.py           # exits non-zero if a non-inherent danger leaks
```

| Category | Result |
|----------|:------:|
| known dangers (plain) | 100% |
| **obfuscated** (spacing, tabs, case, quotes `r''m`, `\rm`, `$VARS`, `bash -c`, chaining) | 100% |
| novel dangers (cloud deletes, publishes, REST DELETE, `crontab -r`, …) | 100% |
| **safe-but-scary** (must NOT flag) | 100% (**0 false alarms**) |
| edge (empty / unicode / multiline / 2 KB input) | 100% |
| **file operations** (structured `FileAction`s) | 100% (24/24) |
| whitespace fuzz (mutated known dangers) | **35/35 caught** |
| combinatorial fuzz (cores × safe prefixes × suffixes) | **320/320 caught** |
| **mutation fuzz** (random perturbation of every benchmark row) | **270/270 dangerous caught, 132/132 safe still allowed** |
| **inherent bypasses** (command assembled at runtime) | 4/5 flagged as *unanalyzable*; 1 irreducible |
| `mention` (safe command that *names* a danger) | conservatively flagged |

Layer 1 normalizes away cheap shell obfuscation (`r''m -rf /`, `\rm`, escaped
spaces) so those no longer bypass the rules, and decorating a dangerous command
with `sudo`, `nice`, `cd x &&`, `2>/dev/null`, `# comment`, etc. never hides it.

Two honest caveats the harness surfaces on purpose:

- **`inherent` bypasses — flag the technique, not the string.** When indirection
  is *detectable* — `eval`, `bash -c "$(…)"`, a command that is wholly a
  substitution — the guard now flags it as **unanalyzable → ASK** (the honest
  move: "I can't see what this runs, so ask a human"). What it can **never**
  catch is a command with no execution primitive at all, assembled purely from
  variable expansion: `p=r;c=m;${p}${c} -rf /` contains no `rm` and no `eval` —
  the dangerous token literally does not exist until the shell builds it. That
  one leak is the mathematical ceiling of text inspection, not a bug to patch;
  "fixing" it by matching `-rf /` would just move the target (`${p}${c} -rf
  /home`). The real defense for this class is **out-of-band**: sandboxing, least
  privilege, a restricted execution user. This is why agent-watchdog is *one
  layer*, not the whole seatbelt.
- **`mention` commands are over-flagged.** `grep 'shutil.rmtree' .` or
  `echo 'DROP TABLE'` get flagged because a text guard can't reliably tell
  *doing* a thing from *referring* to it. We accept this small, bounded
  false-positive class because failing toward "ask a human" is the safe
  direction.

## Limitations (read this)

agent-watchdog reduces risk. It does **not** eliminate it.

- **The bypass problem.** A guard inspects the *text* of an action, not what the
  action ultimately does. Once a command runs, the guard has no control over its
  behavior. An agent can also decompose a blocked action into individually
  innocuous steps, encode/obfuscate it, or route around the check entirely.
  Treat this as one layer of defense, not a sandbox.
- **Novel dangers still slip through.** The heuristic judge is transparent but
  shallow: it recognizes patterns it was given. Genuinely new destructive
  idioms (see the misses above) will pass until a rule or signal is added. The
  reported numbers are for *this* benchmark and will not transfer perfectly to
  the wild.
- **No semantic understanding by default.** The default judge does not truly
  understand intent or scope; it approximates them with keywords. The optional
  local LLM helps but is slower, non-deterministic, and still fallible.
- **Conservative false positives on "mentions."** Because matching is textual, a
  command that merely *names* a danger (`grep 'shutil.rmtree'`, `echo 'DROP
  TABLE'`) is flagged as if it were *doing* it. We accept this bounded
  false-positive class deliberately — failing toward "ask a human" is the safe
  direction — but it means the guard is occasionally annoying, not silent.
- **Verdicts depend on the ruleset and benchmark**, both of which are small and
  community-maintained. Contributions that add cases — especially bypasses —
  are the most valuable thing you can give the project. Run `python
  stress_test.py` to see the current robustness picture, including the inherent
  bypasses that leak by design.

Because of all this, **Layer 3 (a human) exists on purpose**: when the machine is
unsure, a person decides. Do not configure the human approver to auto-approve in
production.

## Recommended deployment (defense-in-depth)

agent-watchdog is a **policy control plane**, not a containment boundary. It
decides *whether an action should run*; it cannot constrain what the action does
once it has run. The irreducible bypass class — commands assembled at runtime
(`p=r;c=m;${p}${c} -rf /`) — is invisible to any text guard by construction. So
in production, pair the guard with an **OS/container sandbox** that contains what
the guard cannot see:

| Layer | Mechanism | Catches |
|------:|-----------|---------|
| **Static guard** | agent-watchdog: rules → AI opacity/novelty check → human on ASK | Known dangers, novel/obfuscated risks, and *unanalyzable indirection* (`eval`, `sh -c "$(…)"`) — escalated to a human |
| **Sandbox** | Container (Docker/Podman), `gVisor`/`Firejail`, or an unprivileged Linux user | The runtime-assembled layer the text guard can't see, *plus* the blast radius of anything wrongly allowed |

The guard makes most dangerous actions **explicit and reviewable**; the sandbox
makes the rest **survivable**. Neither alone is sufficient; together they cover
each other's blind spots.

**A minimal, production-shaped wiring:**

```python
from agent_watchdog import Watchdog, Verdict

wd = Watchdog(mode="hybrid", log_path="decisions.jsonl")

def run_agent_command(cmd: str, user_request: str) -> str:
    decision = wd.enforce(cmd, user_request)   # ASK routes to a human
    if decision.verdict is not Verdict.ALLOW:
        return f"blocked by watchdog: {decision.reason}"
    # Only ALLOW reaches here — and even then, execute INSIDE the sandbox,
    # never on the host:
    return sandbox.exec(cmd)                    # unprivileged user / container
```

Concrete sandboxing measures worth stacking (each is independent of the guard):

- Run the agent as a **dedicated unprivileged user**, never root.
- Execute in a **container** with a read-only root filesystem, `--network=none`
  unless network is required, dropped Linux capabilities, and a non-root `USER`.
- Mount only the **project directory** the agent needs; keep `~/.ssh`, `~/.aws`,
  and `/etc` out of the mount entirely (the guard flags reads of these — the
  sandbox makes them impossible).
- Apply **resource limits** (CPU, memory, PIDs) so a fork bomb the guard missed
  cannot take down the host.
- Keep the **JSON-lines audit log** (`log_path`) on durable storage for
  after-the-fact review.

This is the difference between "a Python script that greps for `rm -rf`" and "a
lightweight, auditable control plane in a real defense-in-depth pipeline."

## Project layout

```
agent-watchdog/
├── agent_watchdog/
│   ├── __init__.py        # public API
│   ├── types.py           # Verdict, Layer, Decision, Assessment
│   ├── rules.py           # Layer 1 — deterministic rules (data-driven)
│   ├── ai_judge.py        # Layer 2 — AIJudge interface + Heuristic & LocalLLM
│   ├── file_ops.py        # structured FileAction + path/verb file-op rules
│   ├── human.py           # Layer 3 — human approvers (CLI + test fakes)
│   ├── watchdog.py        # orchestrator: modes, review(), enforce(), logging
│   └── __main__.py        # CLI entry point
├── benchmark/commands.csv # labeled commands (safe / known / novel)
├── evaluate.py            # runs both modes, prints the comparison, logs decisions
├── stress_test.py         # adversarial red-team harness + fuzzers (runs in CI)
├── tests/                 # pytest: rules, AI layer, file ops, human flow, orchestrator
├── paper.md               # short JOSS-style paper
├── README.md · CONTRIBUTING.md · LICENSE (MIT) · pyproject.toml · requirements.txt
└── .github/workflows/ci.yml
```

## Development

```bash
pip install -e . -r requirements.txt
python -m pytest -q      # 135 tests
python evaluate.py       # reproduce the results table
python stress_test.py    # adversarial red-team harness + fuzzers
```

See [CONTRIBUTING.md](CONTRIBUTING.md) — adding a rule, a benchmark row, and a
test is a five-minute contribution.

## License

MIT — see [LICENSE](LICENSE).
