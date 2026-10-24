# Bugs & known risks - append-only

Scopes: [invariant] = agent/process flaw recurring across projects;
[domain] = project-specific. Closing a bug needs a verification record
naming the validator (python3 tools/spine.py claim verify REF --result
supported --method human_review|model_check|source_attestation|consensus|
formal_proof ...). Statuses: open|probing|resolved|disputed|retracted|
inconclusive. Gates are added only where a failure demanded one.

---

B01 | 2026-10-21 | [invariant] open -> resolved
Truncated claim ids + unvalidated refs: v0.3 rendered TODO.md ids as
`clm_` + 11 hex (15 chars). A human copying the visible id got a silent
no-op `claim verify` at exit 0 - the endorsement evaporated and the honest
loop expired the item. Unknown refs were accepted the same way, recording
real-looking verdicts pointing at nothing. Third manifestation of the
fleet's BUG-002 family: tests only walk the paths they were written to
walk; the broken path was TEXT copy-paste, and no test read text.
Resolution: full ids everywhere (v0.3.1), refs must resolve or exit 2 with
the ledger byte-unchanged, unique-prefix convenience kept, and a `selftest`
gate that parses ids out of TODO.md text exactly like a human does - the
test that reads text. Verified by lesson claim L01
(claim query: kind=lesson) and 10/10 selftest; validator: chris
(human_review) in the 2026-10-21 external review session + builder
session gate run 2026-10-21.
