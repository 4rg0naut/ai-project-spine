# State

Project: ai-project-spine. Created 2026-10-21 by ai-project-spine 0.3.1.
Purpose: the fleet's project skeleton generator - one stdlib file you
download and execute; it lands a rule-bearing starter kit (AGENTS.md,
STATE.md, decaying TODO.md, decisions/bugs/lessons) plus a self-contained
OpenClaims v0.1 ledger gate. This repo is self-hosted: it carries its own
spine ledger since 2026-10-21.

- Phase: v0.5-live - knowledge layer in-tree + supervised keeper LaunchDaemon running live trust tiers, db
  clerk, measure+audit, kindex+search, archive+STATE cap, hooks+uchg,
  adopt, promote, mcp (stdio+http+spool), dayreport, vault, keeper full
  verb surface (difftest 40/40 parity, byte-identical init seeds,
  daemon mode), spec at docs/v0.5-spec.md. Selftest
  54/54 incl. keeper difftest + daemon + mirror outage-resume; keeper unit tests green.
  Not yet committed or released (awaiting human call).
- Open risks: none recorded yet (see BUGS.md).

Next command:
    python3 tools/spine.py verify
    - then bash tests/run.sh (verify + conform + selftest).

Resume rule: this file ends with the literal next command. Any session
(quota death, power cut, new agent) restarts from this file alone.

Closed 2026-11-14T17:41:44Z by ai-project-spine 0.5.0: supersedes (nothing) - v0.5 built in-tree: 49/49 selftest, keeper difftest 12/12, Zelda3_port adopted in scratch (dry-run + full, STATE cap fired live at 752 lines); awaiting human release call + commit

Closed 2026-11-14T17:55:30Z by ai-project-spine 0.5.0: supersedes (nothing) - v0.5.0 knowledge layer complete in-tree: 51/51 selftest (48 = harness path, criterion 16), tests/run.sh green, keeper difftest 12/12, Zelda3 adopt + real golden measurement proven; awaiting human release call + commit

Closed 2026-11-14T20:47:01Z by ai-project-spine 0.5.0: supersedes (nothing) - criterion 21 closed: keeper full verb surface + byte-identical init seeds + difftest 40/40 + daemon mode live (keeper-overnight, /tmp/keeper-overnight/vault/daemon.jsonl); selftest 52/52

Closed 2026-11-14T21:32:37Z by ai-project-spine 0.5.0: supersedes (nothing) - criterion 19 live half: launchd agent ran 10min verify+mirror cycles exit 0; IGNORED-OWNERSHIP refusal proven live on HUB (Owners: Disabled); vault init green on DEV (Owners: Enabled); _spinekeeper LaunchDaemon install = pending human sudo

Closed 2026-11-14T22:03:16Z by ai-project-spine 0.5.0: supersedes (nothing) - 54/54 selftest; vault mirror outage-resume-identical-hashes automated (case 51); LaunchDaemon install + logout span remain human admin steps (blocks A-D provided)

Closed 2026-11-14T22:10:43Z by ai-project-spine 0.5.0: supersedes (nothing) - plists rebuilt after plutil -extract clobbered ProgramArguments (launchd bootstrap 5); retry block handed to human

Closed 2026-11-14T22:25:50Z by ai-project-spine 0.5.0: supersedes (nothing) - criterion 19 live: LaunchDaemon com.openfox.spine-keeper running as _spinekeeper (pid 39040), 300s cycles exit 0 drifts 0, mirror byte-identical on /Volumes/DEV/spine-vault (vault status 0 differ)

Closed 2026-11-14T22:30:46Z by ai-project-spine 0.5.0: supersedes (nothing) - criterion 19 closed live: launchd supervision respawn proven (kill 39040 -> new pid 49067 as _spinekeeper, log continuous exit 0); live rehydrate byte-identical from /Volumes/DEV/spine-vault; IGNORED-OWNERSHIP caught live on HUB; logout-span rides the next natural boot in /var/log/spine-keeper/daemon.jsonl

Closed 2026-11-15T09:22:07Z by ai-project-spine 0.5.0: supersedes (nothing) - v0.5.0 pushed to public origin a5d2410 (tag v0.5.0); clone gates green; public bootstrap verified
