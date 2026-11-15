# Vault - notes with receipts

One markdown note per fact-cluster. Front-matter fields the index uses:
    name: short handle            source: repo-relative path (optional)
    source_sha: sha256 of source  (optional; verify flags STALE on drift)
Cite measured numbers as fact:<m_id> (from data/measurements.jsonl); an
uncited number in a note is asserted, not measured (rule R6).
`index build` folds vault notes + measurements + db records into
data/kindex.jsonl; `search` ranks measured > linked > asserted.
