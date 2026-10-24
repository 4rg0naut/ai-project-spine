# ai-project-spine

Download, execute, get a project skeleton that carries its own rules —
with citations, dates, and a tamper-evident trail. Tool-agnostic: works
with any agent harness (OpenFox, Codex, Copilot, Cursor, Claude Code) or
with none.

## One-line start

```bash
curl -sL https://raw.githubusercontent.com/4rg0naut/ai-project-spine/main/spine.py -o spine.py
python3 spine.py init --name "MyProject"
```

Standard library only. Python 3.9+. No dependencies, no build.

## What lands in your project

```
AGENTS.md            short start-here signpost (size-capped, gate-enforced)
STATE.md             resume file; always ends with the literal next command
TODO.md              disposable intentions with decaying confidence
DECISIONS.md         append-only numbered decisions (D00 = "spine rules bind")
BUGS.md              bugs as gate-demanding records, [invariant]/[domain]
CLAIMS.md            human index; machine truth is the ledger
LESSONS/README.md    lessons need claim_ref + evidence or don't exist
claims/claims.jsonl  hash-chained ledger: rules R1-R6 (with citations +
                     as-of dates) + hash attestation of every file
tools/spine.py       the gate itself, copied in — yours forever
tests/run.sh         one-command gate
```

Your harness rule to add (one line in the fleet-level agent file):

> New project? Run `python3 path/to/spine.py init --name "X"`, then read
> its AGENTS.md. Never hand-write the skeleton.

## The verbs (v0.3.1)

Exit codes: `0` ok · `1` a gate failed (verify/conform/selftest) ·
`2` usage or validation refused (unknown/ambiguous claim ref, cap hit,
overwrite without --force, model_check above 0.6) — refused writes never
touch the ledger.

- `init --name NAME [--dir DIR] [--force]` — generate the skeleton, seed
  rule claims (cited + dated), attest every file.
- `verify` — the loud one: ledger chain intact? every file hash matches?
  any spine file touched outside the gate → `UNATTESTED` + exit 1.
  Also enforces: AGENTS.md length cap, STATE.md keeps its next-command.
- `sign [files...] --by WHO --reason "why"` — attestation for authorized
  hand edits. Hand edits stay legal; they just stop being invisible.
  No args → auto-detects drifted files.
- `claim emit|verify|dispute|retract|query|chain|conform` — real claims in
  native OpenClaims v0.1 events. `conform` self-tests the built-in
  canonicalizer against embedded spec fixtures: the 4 valid reference
  digests must match byte-exactly, the 5 invalid must be rejected. Rules
  and attestations are themselves spec-native claims, so the fleet's `ocl`
  CLI reads a spine-written ledger unmodified (interop proven both ways).
- `todo add|done|drop` — intentions as ledger claims, capped at 3 items,
  each with what/why/what-kills-it. TODO.md is regenerated and re-signed
  on every change (the gate writes; humans read).
- `loop --close [--touch ID...]` — the end-of-batch ritual: untouched
  items decay ×0.9, touched items re-grade (model_check is capped at 0.6:
  the loop that wrote an item cannot be its own judge), items below 0.2
  auto-expire with a retraction event, and a numbered loop marker lands
  in the chain. The report tells you per item: execute / re-probe /
  defer / expired.
- `selftest` — the whole tool proven in a temp dir in ~1 second: init →
  todo add → endorse the id copied from TODO.md TEXT (not from code
  variables) → loop refresh vs decay → phantom ref rejected exit 2 with
  byte-identical ledger → ambiguous prefix refused with candidates named
  → gate green. Every check walks the path a human actually copies; this
  is the gate that v0.3 lacked. Included in generated `tests/run.sh`.

Claim refs (v0.3.1): a `clm_` id given to `claim verify|dispute|retract`
or `todo done|drop` must resolve — exact id, or unique prefix; unknown or
ambiguous refs exit 2 and name candidates. TODO.md shows full ids, so
what you see is what you copy.

`mcp` (same verbs as MCP tools for agent harnesses) is v0.4 — thin
mechanical hat over the existing CLI.

## The confidence loop, in one story

Agent proposes "Vendor MathJax" (conf 0.55; agent-written items start
≤0.6). Two loops of other work: 0.55 → 0.49 → 0.44, action drifts toward
defer. Human confirms classroom dropout logs: human_review 0.85 →
execute. Nobody had to remember anything, and nothing stale executed just
because it was written down. That is rule R4, made mechanical.

## Why the skeleton looks like this

Every choice is a dated, cited event in the generated ledger — read it in
any project with `python3 tools/spine.py ledger`. Highlights:

| rule | one-line why | source (true as of) |
|------|--------------|---------------------|
| R1 hub+pointer | tiny AGENTS.md pointing at rule-bearing files is the dominant cross-tool pattern | arXiv 2602.14690 (2026-02) |
| R2 small context | small context files measurably cut agent runtime/tokens; ~150–200 instruction budget | arXiv 2601.20404; Humanlayer (2026) |
| R3 staleness gate | stale docs poison agents that re-read them every request → enforce, don't trust | AI Hero, Addy Osmani (2026) |
| R4 plan-not-order | LLMs escalate commitment on prior-investment framing; decaying TODO scores make stale tasks sink by default | arXiv 2508.01545; Masicampo & Baumeister 2011 |
| R5 small surface | deep mechanisms (skills/hooks) see shallow adoption; build after the customer does | arXiv 2602.14690 (2026-02) |
| R6 attest-not-forbid | tamper-visibility beats tamper-resistance; chain makes drift loud | OpenClaims v0.1 (fleet) |

## Provenance

Built 2026-10-21 from the working practice of the OpenFox fleet
(Cahier project, Harness² × OpenClaims hygiene spine). Zero telemetry.
MIT.
