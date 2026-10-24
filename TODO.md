# TODO - disposable intentions

One line per item, max 3.
`- [ ] what | why | kills-it-if | conf 0.0-1.0 | last-touch YYYY-MM-DD`

Rules (rule claims R1-R6 are in the ledger: claim query):
- Items are hypotheses, not orders. First act of a session: delete what
  no longer earns its place.
- Conf decays x0.9 per untouched loop; >=0.7 execute; 0.4-0.7 re-probe
  first (cheapest relevant gate); <0.4 needs a human ruling.
- The loop that wrote an item cannot raise its conf above 0.6 alone;
  crossing 0.6 needs human or pipeline evidence (claim verify).

(empty - a human or the first justified session fills this)
