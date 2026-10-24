# init --force wipes human-owned sections

claim_ref: lesson-init-force-wipes-human-state

Evidence (this repo, 2026-10-24, during the v0.4 dogfood): regenerating
the skeleton over the live repo overwrote the hand-written STATE.md
Purpose + Phase (replaced by the "written by a human, here" placeholder)
and re-dated DECISIONS D00 from 2026-10-21 to 2026-10-24 — silently
editing append-only history. Only `git diff` before committing caught it.

Rule for every future skeleton regeneration over a live project:

1. Run the regen into a scratch dir first and `diff` per file (this is
   how the C58 default-skeleton invariant is proven).
2. If regenerating in place, `git diff` immediately and restore every
   human-owned section (STATE Purpose/Phase, DECISIONS entries, TODO
   items) before signing.
3. Tool-side retest obligation (BUGS B01): a future `init --force` that
   cannot preserve those sections must say so in its own output.
