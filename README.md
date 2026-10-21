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

## The three verbs (v0.1)

- `init --name NAME [--dir DIR] [--force]` — generate the skeleton, seed
  rule claims, attest every file.
- `verify` — the loud one: ledger chain intact? every file hash matches?
  any spine file touched outside the gate → `UNATTESTED` + exit 1.
  Also enforces: AGENTS.md length cap, STATE.md keeps its next-command.
- `sign [files...] --by WHO --reason "why"` — attestation for authorized
  hand edits. Hand edits stay legal; they just stop being invisible.
  No args → auto-detects drifted files.

`loop` (confidence decay engine) and `mcp` (same verbs as MCP tools) are
v0.2 — deliberately unbuilt until a real project has used `init` long
enough to deserve them (rule R5).

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
