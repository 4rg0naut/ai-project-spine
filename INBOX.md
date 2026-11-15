# Spine inbox - promoted candidate mechanisms

What campaigns earn, the spine reviews. Rows arrive via
`spine.py promote CLAIM_ID --to spine` from any project; each row is a
claim id + date + origin project + text. The maintainer reads this before
cutting a version; promoted mechanisms ship only with a selftest case and
a named incident (see docs/v0.5-spec.md for the format).

claim_id | date | origin | text
