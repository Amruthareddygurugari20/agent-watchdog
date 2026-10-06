# Contributing to agent-watchdog

Thanks for helping make AI coding agents safer. This project is deliberately
small, dependency-free, and easy to read — please keep it that way.

## Ground rules

- **No proprietary APIs in the default path.** The tool must always run with just
  the Python standard library. Anything model-based (e.g. the local LLM judge)
  goes behind the pluggable `AIJudge` interface and stays optional.
- **Be honest about accuracy.** This is a safety tool; overclaiming is worse than
  a visible gap. If you improve the catch rate, update the numbers in the README
  from a real `evaluate.py` run — don't hand-edit them.
- **Rules are data.** Layer 1 lives in `agent_watchdog/rules.py` as a list of
  `Rule` objects. Prefer adding a well-commented rule over cleverness.

## Development setup

```bash
git clone https://github.com/OWNER/agent-watchdog
cd agent-watchdog
python -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements.txt
```

## Running the checks

```bash
python -m pytest -q      # unit tests (rules, AI judge, human flow, orchestrator)
python evaluate.py       # benchmark: rules_only vs hybrid, honest gaps
```

CI runs both on every push (see `.github/workflows/ci.yml`). A PR should keep the
tests green and should not regress the catch rate or introduce false alarms
without explanation.

## How to add a new dangerous pattern

1. **Is it clearly, unrecoverably destructive?** Add a `Rule` to `RULES` in
   `rules.py` with verdict `BLOCK`. Dangerous-but-sometimes-intended → `ASK`.
2. Add a **benchmark row** to `benchmark/commands.csv`:
   - `label`: `safe` or `dangerous`
   - `category`: `safe`, `known` (covered by a rule), or `novel` (caught only by
     Layer 2, if at all).
3. Add a **test** in `tests/test_rules.py` (or `test_ai_judge.py` for heuristic
   signals) asserting the expected verdict.
4. Run `python evaluate.py` and, if the headline numbers change, update the
   README results table.

## Improving Layer 2 (the AI judge)

- Extend `_SIGNALS` in `ai_judge.py` (keep each signal commented with its
  rationale and weight), or
- Implement a new judge that subclasses `AIJudge` and returns an `Assessment`.

Watch the **false-alarm rate** when adding signals — flagging safe commands
erodes trust as fast as missing dangerous ones.

## Code style

Plain, readable, well-commented Python. No new required dependencies. Keep
functions pure where you can — determinism is a feature in a safety tool.

## Reporting security issues

If you find a bypass (a dangerous command the tool waves through), please open an
issue with a reproducing command and, ideally, a benchmark row and a rule/signal
that would catch it.
