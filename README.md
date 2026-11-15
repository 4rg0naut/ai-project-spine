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
harness.md           step-zero ritual + deny-paths (which files verbs own)
TODO.md              disposable intentions with decaying confidence
DECISIONS.md         append-only numbered decisions (D00 = "spine rules bind")
BUGS.md              bugs as gate-demanding records, [invariant]/[domain]
CLAIMS.md            human index; machine truth is the ledger
LESSONS/README.md    lessons need claim_ref + evidence or don't exist
claims/claims.jsonl  hash-chained ledger: rules R1-R7 (with citations +
                     as-of dates) + hash attestation of every file
data/db/records.jsonl clerk database (append-only snapshots, schema-checked)
data/measurements.jsonl measured results: value+unit+command+observed,
                     re-runnable (`measure audit`)
data/kindex.jsonl    derived knowledge index (`index build`); search ranks
                     measured > linked > asserted
vault/               notes that cite machine facts (fact:<id>)
tools/REGISTRY.md    every tool registered: path | status | purpose
tools/spine.py       the gate itself, copied in — yours forever (uchg-locked)
tests/run.sh         one-command gate
```

Your harness rule to add (one line in the fleet-level agent file):

> New project? Run `python3 path/to/spine.py init --name "X"`, then
> `python3 spine.py hooks install --dir DIR` (git repo needed), then read
> its AGENTS.md - and refuse to launch the first session on an unverified
> skeleton (`verify` must exit 0). Never hand-write the skeleton.

## The verbs (v0.5)

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
- `preflight "QUERY" [--reason WHY] [--artifacts F...]` — rule R7, search
  before you build: greps the claims ledger, TODO.md and the artifacts
  index (default README/STATE/TODO/DECISIONS/BUGS/CLAIMS, extendable via
  `SPINE_ARTIFACTS` env + `--artifacts`), prints dated hits, records the
  search as a ledger event. Hits exit 2 until you re-run with `--reason`
  — the "I feel this was already done" gate, generalized from a measured
  47-vs-30 divergent-branch incident.
- `close [--supersedes ID,ID] [--note "..."]` — session/task close-out:
  dated tail line in STATE.md + claim event naming what it supersedes
  (claim refs must resolve or exit 2, STATE untouched). STATE.md is
  re-attested by the verb, so the gate stays green.
- `verify` (v0.4 additions): flags `ORPHAN-COVERAGE` — issued claims
  referenced by nothing (informational, never blocks, rule R6) — and
  fails `BUGS.md` entries that discard/downgrade a result without a
  `retest:` field: discards must carry their re-measure obligation.
- Producer standardization: with `OPENFOX_SESSION_ID` set and no explicit
  `SPINE_PRODUCER_ID`, every event's `producer.agent_id` becomes
  `urn:session:<id>` — ledger rows trace to the session that wrote them.
- `sessions ingest FILES... [--into DIR]` — OPT-IN convention for pulling
  harness conversation records (chat DBs, transcripts) into the repo as
  attested files with a provenance header (`source`, `sha256`, `observed`,
  `by`, `mode=read-only`). Sources are only ever opened read-only — the
  recorded digest is re-checked after each copy, so the guarantee is
  mechanical, not a promise. Harness-specific paths stay configuration:
  you pass the files (e.g. a dump produced from `sessions.db` opened
  `mode=ro`, like AI_dev's `session_mine.py` contract).
- `init --with-golden` — OPT-IN capture-before-structural-change ritual:
  drops an executable `tools/golden.sh` (`capture` / `check` against
  `tools/golden.conf`, one `name|command` per line) plus a D00g DECISIONS
  seed. Default `init` output is unchanged except the version stamp and
  the R7/retest template lines (verified by diffing v0.3.1 vs v0.4
  skeletons).

Claim refs (v0.3.1): a `clm_` id given to `claim verify|dispute|retract`
or `todo done|drop` must resolve — exact id, or unique prefix; unknown or
ambiguous refs exit 2 and name candidates. TODO.md shows full ids, so
what you see is what you copy.

v0.5 adds the knowledge layer — the machine that remembers what it
measured, what it merely asserts, and where each number came from:

- `claim emit --kind measured|linked|asserted` — trust tiers stamped at
  birth (default `asserted`, so old ledgers load unchanged);
  `claim query --kind measured` filters; `claim export --kinds
  measured,linked` emits JSONL fit for training input — asserted-only
  rows never masquerade as data.
- `db add|get|link|supersede|list` — clerk verbs over
  `data/db/records.jsonl`: schema-validated (a malformed line exits 2 and
  the file stays byte-identical), append-only snapshots, every accepted
  write attests + prints a receipt sha, `verify` re-runs after each
  write, and a failing gate voids the fresh record with a retraction
  event instead of letting it stand uncounted.
- `measure append --command CMD --unit U --source-claim ID` — records
  `{value, unit, source_claim, command, observed}`; the claimed value
  must equal what the command prints right now or the append is refused.
  `measure audit` re-runs every row: OK / DRIFT, exit 1 on drift. A
  number without its command is decoration, not measurement.
- `index build` / `search QUERY [--budget N] [--explain]` — derived
  knowledge index over measurements + db records + vault notes; results
  carry trust labels, STALE flags and source pointers, budgeted in
  tokens; `--explain` shows the score and why a note is stale.
- `archive` — moves dated STATE.md blocks to `docs/STATE-LOG.md`
  byte-exact, keeps the next-command block last, re-attests. `verify`
  reports STATE weight; over 120 lines it WARNs until DECISIONS.md
  carries `state-cap: strict`, then it fails.
- `hooks install|status|unlock --reason WHY` — git pre-commit gate (fast
  verify; bypass only via `LEDGER_HOOK_BYPASS="why"`, logged to
  `hooks-bypass.log`) plus real prevention: `uchg` on the ledger,
  `tools/REGISTRY.md`, derived views and the project's `spine.py` copy.
  Verbs unlock-write-relock; `hooks status` reports flag state.
- `adopt [--dry-run]` — in-place upgrade of an older skeleton: pre-existing
  files stay byte-identical (proven by hash), new parts land as new
  signed files, STATE.md is not touched, old claim ids still resolve.
- `promote CLAIM_ID --to spine` — append the claim to the spine repo's
  `INBOX.md` review queue (unresolved refs exit 2).
- `dayreport [--date YYYY-MM-DD]` — the morning verdict for unattended
  runs: gate tally, bypass/unlock events with reasons, stale views with
  their re-derive commands, lock state.
- `vault init --volume P | mirror | rehydrate | status` — record vault on
  a volume: a volume that ignores unix ownership is a hard error
  (IGNORED-OWNERSHIP), mirror/rehydrate proven byte-identical.
- `db … / preflight … --server URL` — fleet mode: calls to another
  machine's `mcp --http` server; unreachable servers spool the write
  locally and replay on next contact; preflight queries the whole fleet.
- `mcp [--http PORT]` — native tool surface (stdio JSON-RPC, or HTTP at
  `/mcp`) exposing verify/preflight/db/measure/loop/search/dayreport;
  exit-2 semantics survive the round-trip (`exit_code` in every result).
  `tools/difftest.py` runs the same scenarios against the Rust keeper
  (`keeper/`) — byte-parity on the subset is the gate before keeper
  replaces the Python hot path.

`verify` also warns (never fails, v0.5) about unregistered executables
in `tools/` and STALE derived views whose sources moved; the warning
names the re-derive command.

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
