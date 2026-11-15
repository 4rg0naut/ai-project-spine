#!/usr/bin/env python3
"""ai-project-spine - download, execute, get a rule-bearing project skeleton.

One stdlib-only file. `init` generates a skeleton whose rules are ledger-
backed claims (citations + as-of dates). After init, the file IS an
OpenClaims v0.1 ledger writer/verifier: `claim emit|verify|dispute|retract|
query|chain|conform` speak the same vocabulary the fleet's ocl speaks, and
`verify` is the gate: chain intact, every spine file hash-attested, caps
enforced. Writes outside the gate are legal but signed or screamed about.

Canonicalization: RFC 8785-style JCS, byte-compatible with the OpenClaims
v0.1 reference (proven by `claim conform` against embedded fixtures that
must reproduce their reference digests).

v0.3.1: same surface, less lying - claim refs must resolve (exact id or
unique prefix, else exit 2 and the ledger stays byte-identical), full ids
everywhere so copy-paste cannot silently no-op, and a `selftest` gate that
walks the exact paths a human copies.

v0.4: the mechanisms a live campaign earned (AI_dev, 2026-10-24):
`preflight` (search-before-build gate, rule R7), orphan-coverage in verify
(unreferenced claims flagged), BUGS.md `retest:` enforcement for discarded
results, `close --supersedes` (STATE tail + claim event), and session ids
standardized into the signature producer (OPENFOX_SESSION_ID honored).
v0.5: the knowledge layer. Trust tiers on claims (measured/linked/
asserted), a clerk database (`db`), measurement ledger + audit (`measure`),
derived-view freshness in verify, `search` over a knowledge index, STATE
weight cap + `archive`, git `hooks install` with uchg locks and a logged
bypass, harness.md step-zero wiring, `adopt` for in-place upgrades,
`promote` to the spine inbox, `mcp` (stdio + --http) with offline spool,
`dayreport` for unattended accountability, privilege-boundary checks, and
a Rust keeper subset proven by `tools/difftest.py`.
"""
import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zlib
from decimal import Decimal

VERSION = "0.5.0"
LEDGER = os.path.join("claims", "claims.jsonl")
DB_DIR = os.path.join("data", "db")
DB_RECORDS = os.path.join(DB_DIR, "records.jsonl")
DB_SPOOL = os.path.join(DB_DIR, "spool.jsonl")
MEASURED = os.path.join("data", "measurements.jsonl")
KINDEX = os.path.join("data", "kindex.jsonl")
STATE_LOG = os.path.join("docs", "STATE-LOG.md")
SPEC_VERSION = "0.1.0"
SCHEMA_URL = "https://openclaims.org/schemas/openclaims/0.1/ClaimEvent.schema.json"

EVENT_TYPES = {"claim.emitted", "claim.verified", "claim.disputed",
               "claim.retracted"}
CLAIM_TYPES = {"factual", "calculation", "inference", "recommendation",
               "prediction"}
SUPPORT_TYPES = {"supports_directly", "supports_partially", "computed_from",
                 "contradicts", "context_only", "provenance_only"}
VERIFICATION_RESULTS = {"supported", "contradicted", "inconclusive"}
VERIFICATION_METHODS = {"human_review", "model_check", "source_attestation",
                        "consensus", "formal_proof"}
CLAIM_STATUSES = {"active", "disputed", "retracted"}
SELECTOR_TYPES = {"text_span", "page_span", "json_pointer", "table_cell",
                  "uri_fragment", "byte_range"}
AGENT_TYPES = {"human", "organization", "service", "model", "pipeline"}
DATE_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

PARAMS = {"agents_md_max_lines": 25, "todo_max_items": 3,
          "state_md_max_lines": 120}

TRUST_KINDS = {"measured", "linked", "asserted"}
DB_STATUSES = {"active", "superseded", "void"}
TXLOG = os.path.join("data", "txlog.jsonl")
HOOKS_LOG = "hooks-bypass.log"
LOCKED_ON_INSTALL = [LEDGER, "tools/REGISTRY.md", KINDEX]


def refuse(msg):
    """Usage/validation refusal: stderr + exit 2 (the contract says 2 is
    'refused', 1 is 'a gate judged failure' - keep them distinct)."""
    sys.stderr.write(msg.rstrip() + "\n")
    raise SystemExit(2)


def has_flags():
    return hasattr(os.stat(__file__), "st_flags")


def is_locked(path):
    return has_flags() and os.path.exists(path) and bool(
        os.stat(path).st_flags & getattr(stat, "UF_IMMUTABLE", 1))


def set_lock(path, on):
    if not has_flags() or not os.path.exists(path):
        return False
    st_mode = getattr(stat, "UF_IMMUTABLE", 1)
    cur = os.stat(path).st_flags
    want = st_mode if on else 0
    if cur != want:
        os.chflags(path, want)
    return True


class unlocked(object):
    """Unlock-write-relock context: the verb path around protected writes.

    Direct writes to a locked file fail (uchg); verbs pass through here and
    restore the flag after, so the lock state is never silently degraded.
    """

    def __init__(self, *paths):
        self.paths = [(p, is_locked(p)) for p in paths if os.path.exists(p)]

    def __enter__(self):
        for p, _ in self.paths:
            set_lock(p, False)
            os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR)
        return self

    def __exit__(self, *exc):
        for p, was in self.paths:
            if was:
                set_lock(p, True)
        return False


def txlog(root, tool, exit_code, note=""):
    """Every transaction (cli or mcp) lands in data/txlog.jsonl."""
    path = os.path.join(root, TXLOG)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": now(), "tool": tool, "exit": exit_code,
                            "note": note, "by": producer()["name"],
                            "pid": os.getpid()}, sort_keys=True) + "\n")


def expect_owner(root):
    conf = os.path.join(root, ".spine-owner")
    if os.path.exists(conf):
        return open(conf, encoding="utf-8").read().strip() or None
    return None


def import_stat():
    pass

RULES = [
    ("R1-hub-pointer", "One small AGENTS.md pointing at files that already "
     "hold the rules; hub+pointer is the dominant cross-tool pattern.",
     "https://arxiv.org/abs/2602.14690", "2026-02-16"),
    ("R2-small-context", "AGENTS.md capped at N lines: small context files "
     "cut agent runtime/tokens; past ~150-200 instructions rules get "
     "ignored, not obeyed.",
     "https://arxiv.org/abs/2601.20404 ; "
     "https://www.humanlayer.dev/blog/writing-a-good-claude-md", "2026-02"),
    ("R3-staleness-gate", "Stale docs poison agents that re-read them every "
     "request; enforce size and pointer integrity, do not trust prose.",
     "https://www.aihero.dev/a-complete-guide-to-agents-md ; "
     "https://addyo.substack.com/p/audit-your-agent-files", "2026-01/08"),
    ("R4-plan-not-order", "TODO items are hypotheses whose confidence decays "
     "when untouched: LLMs escalate commitment under prior-investment "
     "framing; written plans discharge open-loop load (human side).",
     "https://arxiv.org/abs/2508.01545 ; "
     "https://pubmed.ncbi.nlm.nih.gov/21688924/", "2025-08 / 2011"),
    ("R5-small-surface", "Ship few verbs; deep mechanisms (skills/hooks/"
     "subagents) see shallow real adoption, add executable depth only after "
     "a customer earns it.", "https://arxiv.org/abs/2602.14690", "2026-02-16"),
    ("R6-attest-not-forbid", "Tamper-visibility beats tamper-resistance: "
     "hand edits are legal, but unsigned drift is loud via the hash chain.",
     "OpenClaims v0.1 event model (openclaims.org spec 0.1)", "2026-10"),
    ("R7-preflight-search", "Search before you build: every idea feels "
     "novel; re-deriving settled work is the dominant project-killer, so "
     "grep claims + TODO + the artifacts index before funding work "
     "(`preflight`). Born of a measured incident: two main branches held "
     "47-vs-30 divergent commits and each side re-derived the other's "
     "settled work; origin report 'I feel this was already done'.",
     "AI_dev ncm-run/docs/incidents.md BUG-BRANCH-BLINDNESS (2026-10-24)",
     "2026-10-24"),
]


def producer():
    aid = os.environ.get("SPINE_PRODUCER_ID")
    if not aid:                                  # standardize session ids
        sid = os.environ.get("OPENFOX_SESSION_ID")
        aid = "urn:session:" + sid if sid else "urn:tool:ai-project-spine"
    return {"agent_id": aid,
            "agent_type": os.environ.get("SPINE_PRODUCER_TYPE", "service"),
            "name": os.environ.get("SPINE_PRODUCER_NAME",
                                   "ai-project-spine " + VERSION)}


def now():
    pin = os.environ.get("SPINE_TEST_NOW")
    if pin:
        if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", pin):
            refuse("SPINE_TEST_NOW must look like "
                   "2026-01-01T00:00:00Z (parity harness pin)")
        return pin
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_id(prefix):
    return "%s_%s" % (prefix, uuid.uuid4().hex[:26])


# --------------------------------------------------------------------- JCS
def _code_units(s):
    units = []
    for ch in s:
        cp = ord(ch)
        if cp < 0x10000:
            units.append(cp)
        else:
            v = cp - 0x10000
            units.append(0xD800 + (v >> 10))
            units.append(0xDC00 + (v & 0x3FF))
    return units


_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n",
        "\r": "\\r", "\t": "\\t"}


def _json_string(s):
    out = ['"']
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _float_to_js(n):
    sign, digits, exp = Decimal(repr(n)).normalize().as_tuple()
    digits = "".join(map(str, digits))
    k = len(digits) + exp
    prefix = "-" if sign else ""
    if -6 < k <= 0:
        return "%s0.%s%s" % (prefix, "0" * -k, digits)
    if 0 < k <= 21:
        if k >= len(digits):
            return "%s%s%s" % (prefix, digits, "0" * (k - len(digits)))
        return "%s%s.%s" % (prefix, digits[:k], digits[k:])
    mant = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")
    return "%s%se%s%d" % (prefix, mant, "+" if k > 0 else "-", abs(k - 1))


def _json_number(n):
    if isinstance(n, bool):
        raise TypeError("bool is not a number")
    if not math.isfinite(n):
        raise TypeError("non-finite number")
    if isinstance(n, int):
        return str(n)
    if n == int(n) and abs(n) < 1e21:
        return str(int(n))
    return _float_to_js(n)


def canonicalize(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _json_number(value)
    if isinstance(value, str):
        return _json_string(value)
    if isinstance(value, (list, tuple)):
        return "[%s]" % ",".join(canonicalize(v) for v in value)
    if isinstance(value, dict):
        entries = [(k, v) for k, v in value.items() if v is not None]
        entries.sort(key=lambda kv: _code_units(kv[0]))
        return "{%s}" % ",".join(
            "%s:%s" % (_json_string(k), canonicalize(v))
            for k, v in entries)
    raise TypeError("cannot canonicalize %s" % type(value).__name__)


def sha256_b64u(text):
    d = hashlib.sha256(text.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(d).decode("ascii").rstrip("=")


def digest_value(value):
    return {"algorithm": "sha256", "encoding": "base64url",
            "value": sha256_b64u(canonicalize(value))}


def event_digest(event):
    return digest_value({k: v for k, v in event.items() if k != "digest"})


def verify_digest(event):
    return bool(event.get("digest")) and (
        event["digest"] == event_digest(event))


# --------------------------------------------------------------- validator
def validate_event(ev, check_digest=True):
    errs = []

    def req(obj, keys, path):
        for k in keys:
            if obj.get(k) in (None, "", [], {}):
                errs.append("%s missing %s" % (path or "/", k))

    def agent(a, path):
        if not isinstance(a, dict):
            errs.append("%s: producer/validator must be object" % path)
            return
        req(a, ["agent_id", "agent_type", "name"], path)
        if a.get("agent_type") not in AGENT_TYPES:
            errs.append("%s: unknown agent_type" % path)

    def digest(d, path):
        if not isinstance(d, dict):
            errs.append("%s: digest must be object" % path)
            return
        if d.get("algorithm") != "sha256" or d.get("encoding") != "base64url"\
                or not d.get("value"):
            errs.append("%s: digest must be sha256/base64url/value" % path)

    req(ev, ["event_id", "event_type", "event_time", "spec_version",
             "schema_url", "producer", "digest"], "")
    if ev.get("event_type") not in EVENT_TYPES:
        errs.append("unknown event_type")
    if not ev.get("claim") and not ev.get("claim_ref"):
        errs.append("event requires claim or claim_ref")
    agent(ev.get("producer") or {}, "/producer")
    et = ev.get("event_type")
    c = ev.get("claim")
    if et == "claim.emitted":
        if not c:
            errs.append("/claim: claim.emitted requires claim")
        else:
            req(c, ["claim_id", "text", "claim_type", "asserted_at"], "/claim")
            if c.get("claim_type") not in CLAIM_TYPES:
                errs.append("/claim/claim_type: unknown")
            if c.get("asserted_at") and not DATE_TIME_RE.match(
                    str(c["asserted_at"])):
                errs.append("/claim/asserted_at: not date-time")
    if et == "claim.verified":
        req(ev, ["claim_ref", "verification"], "")
        v = ev.get("verification") or {}
        req(v, ["verification_result", "verification_method", "claim_status",
                "verified_at"], "/verification")
        if v.get("verification_result") not in VERIFICATION_RESULTS:
            errs.append("/verification/verification_result: unknown")
        if v.get("verification_method") not in VERIFICATION_METHODS:
            errs.append("/verification/verification_method: unknown")
        if v.get("claim_status") not in CLAIM_STATUSES:
            errs.append("/verification/claim_status: unknown")
        agent(v.get("validator") or {}, "/verification/validator")
    if et == "claim.disputed":
        req(ev, ["claim_ref"], "")
        if not ev.get("dispute_rationale") and not ev.get(
                "contradicting_evidence"):
            errs.append("claim.disputed requires dispute_rationale or "
                        "contradicting_evidence")
    if et == "claim.retracted":
        req(ev, ["claim_ref", "retracted_at"], "")
    for i, e in enumerate(ev.get("evidence") or []):
        req(e, ["evidence_id", "source_ref", "claim_ref", "selector",
                "support_type"], "/evidence/%d" % i)
        if e.get("support_type") not in SUPPORT_TYPES:
            errs.append("/evidence/%d/support_type: unknown" % i)
        if (e.get("selector") or {}).get("type") not in SELECTOR_TYPES:
            errs.append("/evidence/%d/selector: unknown type" % i)
    for i, e in enumerate(ev.get("contradicting_evidence") or []):
        req(e, ["evidence_id", "claim_ref", "selector", "support_type"],
            "/contradicting_evidence/%d" % i)
        if e.get("support_type") not in SUPPORT_TYPES:
            errs.append("/contradicting_evidence/%d/support_type: unknown" % i)
    for i, s in enumerate(ev.get("sources") or []):
        req(s, ["source_id", "uri"], "/sources/%d" % i)
        if s.get("digest"):
            digest(s["digest"], "/sources/%d/digest" % i)
    if ev.get("digest"):
        digest(ev["digest"], "/digest")
        if check_digest and not verify_digest(ev):
            errs.append("/digest: event digest mismatch")
    return errs


# ---------------------------------------------------------------- ledger
def read_events(root):
    out, path = [], os.path.join(root, LEDGER)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    return out


def append_event(root, event):
    path = os.path.join(root, LEDGER)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    prev = (read_events(root) or [None])[-1]
    if prev:
        event["auditable_trace"] = {"event_ids": [prev["event_id"]],
                                    "hash_chain": [prev["digest"]["value"]]}
    event["digest"] = event_digest(event)
    errs = validate_event(event)
    if errs:
        sys.stderr.write("reject: %s\n" % "; ".join(errs))
        raise SystemExit(2)
    with unlocked(path):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def base_event(etype):
    return {"event_id": new_id("evt"), "event_type": etype, "event_time":
            now(), "spec_version": SPEC_VERSION, "schema_url": SCHEMA_URL,
            "producer": producer()}


def chain_check(events):
    prev_id = prev_dig = None
    for i, ev in enumerate(events):
        if not verify_digest(ev):
            return False, "digest mismatch at event %d (%s)" % (
                i, ev.get("event_id"))
        trace = ev.get("auditable_trace") or {}
        ids, chain = trace.get("event_ids") or [], trace.get("hash_chain") or []
        if prev_id is None:
            if ids or chain:
                return False, "first event must be unlinked (%d)" % i
        elif ids != [prev_id] or chain != [prev_dig]:
            return False, "broken link at event %d (%s)" % (i,
                                                            ev.get("event_id"))
        prev_id, prev_dig = ev["event_id"], ev["digest"]["value"]
    return True, "chain ok (%d events)" % len(events)


# ------------------------------------------------------------ claim refs
def issued_claim_ids(root):
    ids = []
    for ev in read_events(root):
        cid = (ev.get("claim") or {}).get("claim_id")
        if cid:
            ids.append(cid)
    return ids


def resolve_claim_ref(root, ref):
    """Exact id wins; else unique prefix; else refuse (exit 2, no write).

    Silent no-op verdicts were the v0.3 disease: a truncated or invented
    ref recorded a real-looking verdict pointing at nothing (BUG-002).
    """
    ids = issued_claim_ids(root)
    if ref in ids:
        return ref
    hits = [i for i in ids if i.startswith(ref)]
    if len(set(hits)) == 1:
        return hits[0]
    if not hits:
        sys.stderr.write(
            "reject: unknown claim ref %s - no issued claim carries it; "
            "full ids are in TODO.md and `claim query` (rule R6: refuse "
            "loud, never silently no-op)\n" % ref)
    else:
        seen, order = set(), []
        for i in reversed(hits):
            if i not in seen:
                seen.add(i)
                order.append(i)
        sys.stderr.write(
            "reject: ambiguous claim ref %s - %d claims match, give more "
            "characters (most recent first):%s\n" % (
                ref, len(seen),
                "".join("\n  " + h for h in order[:8]) +
                ("\n  ... and %d more" % (len(seen) - 8)
                 if len(seen) > 8 else "")))
    raise SystemExit(2)


# ------------------------------------------------------------- claim verbs
def sel_from_spec(spec):
    parts = (spec or "uri_fragment:full").split(":")
    kind = parts[0]
    if kind in ("text_span", "byte_range"):
        return {"type": kind, "start": int(parts[1]), "end": int(parts[2])}
    if kind == "page_span":
        return {"type": kind, "page": int(parts[1]), "start": int(parts[2]),
                "end": int(parts[3])}
    if kind == "json_pointer":
        return {"type": kind, "path": spec.split(":", 1)[1]}
    if kind == "uri_fragment":
        return {"type": kind, "fragment": spec.split(":", 1)[1]}
    raise SystemExit("unsupported selector: %s" % spec)


def cmd_claim_emit(args, root):
    claim = {"claim_id": args.claim_id or new_id("clm"), "text": args.text,
             "claim_type": args.type, "asserted_at": now()}
    if getattr(args, "kind", None):
        claim["trust"] = args.kind
    if args.context:
        claim["context"] = json.loads(args.context)
    ev = base_event("claim.emitted")
    ev["claim"] = claim
    ev["sources"], ev["evidence"] = [], []
    if args.source_uri:
        sid = new_id("src")
        ev["sources"].append({"source_id": sid, "uri": args.source_uri,
                              "observed_at": now()})
        ev["evidence"].append({"evidence_id": new_id("ev"),
                               "source_ref": sid,
                               "claim_ref": claim["claim_id"],
                               "selector": sel_from_spec(args.selector),
                               "support_type": args.support,
                               "observed_at": now()})
    ev = append_event(root, ev)
    print(json.dumps({"ok": True, "event_id": ev["event_id"],
                      "claim_id": claim["claim_id"]}))


def cmd_claim_verdict(args, root, kind):
    args.claim_ref = resolve_claim_ref(root, args.claim_ref)
    ev = base_event("claim." + kind)
    ev["claim_ref"] = args.claim_ref
    if kind == "verified":
        if args.method == "model_check" and args.confidence > 0.6:
            sys.stderr.write(
                "reject: model_check cannot grade above 0.6 - the loop that "
                "wrote an item cannot be its own judge (rule R4); use "
                "human_review/pipeline/formal_proof with evidence "
                "(exit 2: validation refused)\n")
            raise SystemExit(2)
        v = {"verification_id": new_id("ver"),
             "verification_result": args.result,
             "verification_method": args.method,
             "claim_status": args.status,
             "validator": {"agent_id": args.by or producer()["agent_id"],
                           "agent_type": args.by_type,
                           "name": args.by or producer()["name"]},
             "verified_at": now(), "confidence": args.confidence}
        ev["verification"] = v
    elif kind == "disputed":
        ev["dispute_rationale"] = args.reason
    elif kind == "retracted":
        ev["retracted_at"] = now()
        ev["retraction_reason"] = args.reason
    ev = append_event(root, ev)
    if kind == "verified":
        todo_ids = [cid for cid, it in todo_state(root)[0].items()
                    if cid == args.claim_ref]
        if todo_ids:
            write_todo_md(root)
            attest_claim(root, "TODO.md", "spine claim", "verdict refresh")
    print(json.dumps({"ok": True, "event_id": ev["event_id"],
                      "claim_ref": args.claim_ref}))


def claim_state(root):
    state = {}
    for ev in read_events(root):
        t = ev["event_type"]
        if t == "claim.emitted":
            c = ev["claim"]
            state[c["claim_id"]] = {"type": c["claim_type"],
                                    "status": "active", "result": "-",
                                    "trust": c.get("trust", "asserted"),
                                    "text": c["text"][:64]}
        elif t == "claim.verified":
            v = ev["verification"]
            s = state.get(ev["claim_ref"])
            if s:
                s["status"] = v["claim_status"]
                s["result"] = "%s/%s" % (v["verification_result"],
                                         v["verification_method"])
        elif t == "claim.disputed":
            if ev["claim_ref"] in state:
                state[ev["claim_ref"]]["status"] = "disputed"
        elif t == "claim.retracted":
            if ev["claim_ref"] in state:
                state[ev["claim_ref"]]["status"] = "retracted"
    return state


def cmd_claim_query(args, root):
    state = claim_state(root)
    for cid, s in sorted(state.items()):
        if getattr(args, "kind", None) and s["trust"] != args.kind:
            continue
        print("%s  %-9s %-10s %-8s %-28s %s" % (cid, s["type"], s["status"],
                                                s["trust"], s["result"],
                                                s["text"]))


def cmd_claim_export(args, root):
    """Training-set export: only claims whose trust tier was earned."""
    kinds = set(args.kinds.split(","))
    bad = kinds - TRUST_KINDS
    if bad:
        refuse("claim export: unknown kind(s): %s (have: %s)"
                 % (", ".join(sorted(bad)), ", ".join(sorted(TRUST_KINDS))))
    n = 0
    for ev in read_events(root):
        if ev["event_type"] != "claim.emitted":
            continue
        c = ev["claim"]
        if c.get("trust", "asserted") not in kinds:
            continue
        print(json.dumps({"claim_id": c["claim_id"], "text": c["text"],
                          "claim_type": c["claim_type"],
                          "trust": c.get("trust", "asserted"),
                          "asserted_at": c["asserted_at"]}, sort_keys=True))
        n += 1
    sys.stderr.write("claim export: %d claim(s) of kind(s) %s\n"
                     % (n, ",".join(sorted(kinds))))


# ------------------------------------------------------- todo + loop (v0.3)
def action_for(conf):
    if conf >= 0.7:
        return "execute"
    if conf >= 0.4:
        return "re-probe"
    if conf >= 0.2:
        return "defer"
    return "expired"


def todo_state(root):
    """Effective view of TODO items: conf = last verdict, decay applied."""
    items, loop_index = {}, 0
    for ev in read_events(root):
        c = ev.get("claim") or {}
        sp = (c.get("context") or {}).get("spine") or {}
        t = ev["event_type"]
        if t == "claim.emitted" and sp.get("kind") == "todo":
            items[c["claim_id"]] = {"what": sp["what"], "why": sp["why"],
                                    "kills": sp["kills"],
                                    "conf": sp["conf"], "status": "active",
                                    "touched": ev["event_time"][:10]}
        elif t == "claim.emitted" and sp.get("kind") == "loop":
            loop_index = max(loop_index, sp["index"])
        cid = ev.get("claim_ref")
        if cid in items:
            if t == "claim.verified":
                v = ev["verification"]
                conf = v["confidence"]
                if v["verification_method"] == "model_check":
                    conf = min(conf, 0.6)
                items[cid]["conf"] = conf
                items[cid]["touched"] = ev["event_time"][:10]
            elif t == "claim.disputed":
                items[cid]["conf"] = min(items[cid]["conf"], 0.2)
            elif t == "claim.retracted":
                items[cid]["status"] = "retracted"
    return items, loop_index


def write_todo_md(root):
    items, loop_index = todo_state(root)
    head = render(TPL["TODO.md"], "TODO").split("(empty")[0]
    lines = [head.rstrip(), "", ""]
    active = {k: v for k, v in items.items() if v["status"] == "active"}
    if not active:
        lines.append("(empty - a human or the first justified session fills "
                     "this)")
    for cid, it in sorted(active.items(), key=lambda kv: -kv[1]["conf"]):
        lines.append("- [ ] %s (%s) | why: %s | kills-it-if: %s | conf %.2f "
                     "| last-touch %s" % (it["what"], cid, it["why"],
                                          it["kills"], it["conf"],
                                          it["touched"]))
    lines.append("")
    lines.append("# loop %d | actions: >=0.70 execute | 0.40-0.69 re-probe | "
                 "0.20-0.39 defer | <0.20 expired" % loop_index)
    with open(os.path.join(root, "TODO.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return items, loop_index


def cmd_todo(args, root):
    if args.action == "add":
        if len([1 for _, it in todo_state(root)[0].items()
                if it["status"] == "active"]) >= PARAMS["todo_max_items"]:
            sys.exit("todo: cap %d reached - retire something first "
                     "(disposable by rule R4)"
                     % PARAMS["todo_max_items"])
        ev = base_event("claim.emitted")
        ev["claim"] = {"claim_id": new_id("clm"),
                       "text": "TODO: %s | why: %s | kills-it-if: %s"
                               % (args.what, args.why, args.kills),
                       "claim_type": "recommendation", "asserted_at": now(),
                       "context": {"spine": {"kind": "todo",
                                             "what": args.what,
                                             "why": args.why,
                                             "kills": args.kills,
                                             "conf": args.conf}}}
        append_event(root, ev)
        print("added:", ev["claim"]["claim_id"])
    elif args.action in ("done", "drop"):
        args.claim_ref = resolve_claim_ref(root, args.claim_ref)
    if args.action == "done":
        ev = base_event("claim.verified")
        ev["claim_ref"] = args.claim_ref
        ev["verification"] = {"verification_id": new_id("ver"),
                              "verification_result": "supported",
                              "verification_method": "human_review",
                              "claim_status": "active",
                              "validator": {"agent_id": "urn:human:" +
                                            args.by, "agent_type": "human",
                                            "name": args.by},
                              "verified_at": now(), "confidence": 0.95}
        append_event(root, ev)
        print("done (human attested):", args.claim_ref)
    elif args.action == "drop":
        ev = base_event("claim.retracted")
        ev["claim_ref"] = args.claim_ref
        ev["retracted_at"] = now()
        ev["retraction_reason"] = args.reason
        append_event(root, ev)
        print("dropped:", args.claim_ref)
    write_todo_md(root)
    attest_claim(root, "TODO.md", "spine todo", args.action)


def cmd_loop_close(args, root):
    items, loop_index = todo_state(root)
    idx = loop_index + 1
    touch = set(args.touch or [])
    report = []
    for cid, it in sorted(items.items()):
        if it["status"] != "active":
            continue
        ev = base_event("claim.verified")
        ev["claim_ref"] = cid
        if cid in touch:
            conf = args.touch_conf
            result = "supported"
        else:
            conf = round(it["conf"] * 0.9, 3)
            result = "inconclusive"
        conf = min(conf, 0.6) if args.method == "model_check" else conf
        ev["verification"] = {"verification_id": new_id("ver"),
                              "verification_result": result,
                              "verification_method": args.method,
                              "claim_status": "active",
                              "validator": {"agent_id":
                                            "urn:tool:ai-project-spine",
                                            "agent_type": "pipeline",
                                            "name": "spine loop " + VERSION},
                              "verified_at": now(), "confidence": conf}
        append_event(root, ev)
        report.append((cid, it["what"][:40], conf, action_for(conf)))
        if conf < 0.2:
            ev = base_event("claim.retracted")
            ev["claim_ref"] = cid
            ev["retracted_at"] = now()
            ev["retraction_reason"] = ("expired: conf %.2f < 0.2 after loop "
                                       "%d" % (conf, idx))
            append_event(root, ev)
            report[-1] = (cid, it["what"][:40], conf, "EXPIRED+retracted")
    ev = base_event("claim.emitted")
    ev["claim"] = {"claim_id": new_id("clm"),
                   "text": "loop %d closed: %d items updated" % (idx,
                                                                 len(report)),
                   "claim_type": "factual", "asserted_at": now(),
                   "context": {"spine": {"kind": "loop", "index": idx}}}
    append_event(root, ev)
    write_todo_md(root)
    attest_claim(root, "TODO.md", "spine loop", "loop %d" % idx)
    print("loop %d closed:" % idx)
    for cid, what, conf, act in report:
        print("  %-30s %-42s conf %.2f  -> %s" % (cid, what, conf, act))
    if not report:
        print("  (no active items)")


# ------------------------------------------------------------- preflight
ARTIFACT_INDEX_DEFAULT = ["README.md", "STATE.md", "TODO.md", "DECISIONS.md",
                          "BUGS.md", "CLAIMS.md"]


def cmd_preflight(args, root):
    """Rule R7: search the house before funding work. Read + one audit
    event; never mutates project files. Exit 2 on hits unless --reason."""
    if getattr(args, "server", None):
        global SPINE_SERVER_URL
        SPINE_SERVER_URL = args.server
        resp = db_server_call(args, "preflight",
                              {"query": args.query, "reason": args.reason})
        if resp is None:
            return
        res = resp.get("result") or {}
        for part in res.get("content") or []:
            print(part.get("text", ""), end="")
        sys.exit(res.get("exit_code", 0))
    terms = [t for t in re.split(r"[^a-z0-9_]+", args.query.lower())
             if len(t) >= 4]
    if not terms:
        sys.exit("preflight: query needs >=1 word of 4+ chars")
    hits = []
    for ev in read_events(root):
        text = ((ev.get("claim") or {}).get("text") or "")
        low = text.lower()
        if any(t in low for t in terms):
            hits.append(("ledger", ev.get("event_time", "?"),
                         text[:100].replace("\n", " ")))
    index = list(ARTIFACT_INDEX_DEFAULT) + (args.artifacts or [])
    extra = os.environ.get("SPINE_ARTIFACTS", "")
    if extra:
        index += [p for p in extra.split(os.pathsep) if p]
    if "tools/REGISTRY.md" not in index:
        index.append("tools/REGISTRY.md")
    data_dirs = os.environ.get("SPINE_DATA_DIRS", "data")
    for d in [x for x in data_dirs.split(os.pathsep) if x] + ["vault"]:
        droot = os.path.join(root, d)
        for dirpath, _, files in os.walk(droot):
            for f in sorted(files):
                if f.endswith((".jsonl", ".json", ".md", ".txt", ".csv")):
                    index.append(os.path.relpath(os.path.join(dirpath, f),
                                                 root))
    for rel in sorted(index):
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            continue
        d = time.strftime("%Y-%m-%d", time.gmtime(os.path.getmtime(p)))
        for ln in open(p, encoding="utf-8", errors="replace"):
            low = ln.lower()
            if any(t in low for t in terms):
                hits.append((rel, d, ln.strip()[:100]))
    shown = hits[:12]
    for src, d, txt in shown:
        print("  [%s %s] %s" % (src, d, txt))
    ev = base_event("claim.emitted")
    ev["claim"] = {"claim_id": new_id("clm"),
                   "text": "preflight \"%s\": %d hit(s)" % (args.query,
                                                            len(hits)),
                   "claim_type": "factual", "asserted_at": now(),
                   "context": {"spine": {"kind": "preflight",
                                         "query": args.query,
                                         "hits": len(hits)}}}
    append_event(root, ev)
    if hits and not args.reason:
        print("PREFLIGHT: %d prior-art hit(s) - read them, then re-run "
              "with --reason '<why proceed>'" % len(hits))
        sys.exit(2)
    print("PREFLIGHT: %s" % ("clean" if not hits else
                             "PROCEED (reason logged): " + args.reason))


# ------------------------------------------------------------------ close
def cmd_close(args, root):
    """Session/task close-out: STATE.md tail line + claim event naming what
    this closes/supersedes (generalizes night_index SUPERSEDES rows)."""
    resolved = []
    try:
        for ref in (args.supersedes or "").split(","):
            ref = ref.strip()
            if ref:
                resolved.append(resolve_claim_ref(root, ref))
    except SystemExit:
        raise
    except Exception as e:
        sys.exit("close: %s" % e)
    who = producer()["name"]
    line = ("Closed %s by %s: supersedes %s%s"
            % (now(), who, ", ".join(resolved) or "(nothing)",
               (" - " + args.note) if args.note else ""))
    with open(os.path.join(root, "STATE.md"), "a", encoding="utf-8") as fh:
        fh.write("\n%s\n" % line)
    ev = base_event("claim.emitted")
    ev["claim"] = {"claim_id": new_id("clm"), "text": line,
                   "claim_type": "factual", "asserted_at": now(),
                   "context": {"spine": {"kind": "close",
                                         "supersedes": resolved}}}
    append_event(root, ev)
    attest_claim(root, "STATE.md", "spine close", "close-out")
    print("closed:", line)


# --------------------------------------------------------- sessions ingest
def cmd_sessions_ingest(args, root):
    """Opt-in convention: pull harness conversation records into the repo
    as attested files with provenance headers. Sources are opened READ-ONLY
    (the tool never writes to them; the recorded sha256 is the proof).
    Harness-specific source paths stay configuration - pass them here."""
    into = args.into.strip("/") or "sessions"
    dest_dir = os.path.join(root, into)
    os.makedirs(dest_dir, exist_ok=True)
    who = producer()["name"]
    for src in args.files:
        raw = open(src, "rb").read()               # read-only, never w+
        h = hashlib.sha256(raw).hexdigest()
        dest = os.path.join(dest_dir, os.path.basename(src))
        rel = os.path.relpath(dest, root)
        hdr = ("<!-- spine sessions ingest: source=%s sha256=%s "
               "observed=%s by=%s mode=read-only -->\n"
               % (os.path.abspath(src), h, now(), who))
        with open(dest, "wb") as fh:
            fh.write(hdr.encode("utf-8") + raw)
        if hashlib.sha256(open(src, "rb").read()).hexdigest() != h:
            sys.exit("sessions ingest: source mutated during ingest: %s"
                     % src)
        attest_claim(root, rel, "spine sessions ingest", src)
        print("ingested:", rel, "sha256=" + h[:16])


# ------------------------------------------------------------------ clerk db
DB_REQUIRED = ("record_id", "key")


def validate_record(r):
    errs = []
    if not isinstance(r, dict):
        return ["record must be object"]
    for k in DB_REQUIRED:
        if not r.get(k):
            errs.append("missing %s" % k)
    if r.get("status") not in DB_STATUSES:
        errs.append("status %r not in %s" % (r.get("status"),
                                             sorted(DB_STATUSES)))
    if r.get("trust") not in TRUST_KINDS:
        errs.append("trust %r not in %s" % (r.get("trust"),
                                            sorted(TRUST_KINDS)))
    if not isinstance(r.get("links", []), list):
        errs.append("links must be a list")
    return errs


def read_records(root):
    """Every line is schema-checked BEFORE anything acts: one malformed
    line stops the verb and the file stays byte-identical (exit 2)."""
    path = os.path.join(root, DB_RECORDS)
    out = []
    if os.path.exists(path):
        for n, line in enumerate(open(path, encoding="utf-8"), 1):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                refuse("db: %s line %d is not valid JSON - repair "
                         "first (file untouched)" % (DB_RECORDS, n))
            errs = validate_record(r)
            if errs:
                refuse("db: %s line %d malformed: %s (file untouched)"
                         % (DB_RECORDS, n, "; ".join(errs)))
            out.append(r)
    return out


def db_state(root):
    eff, order = {}, []
    for r in read_records(root):
        if r["record_id"] not in eff:
            order.append(r["record_id"])
        eff[r["record_id"]] = r
    return eff, order


def append_record(root, rec):
    path = os.path.join(root, DB_RECORDS)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = json.dumps(rec, sort_keys=True) + "\n"
    with unlocked(path):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def emit_record_claim(root, rec):
    """Every accepted record also issues a claim (claim_id = record_id):
    the ledger speaks claims, so a later void/retroaction can retract
    something issued - otherwise the phantom gate (BUG-002) bites."""
    ev = base_event("claim.emitted")
    ev["claim"] = {"claim_id": rec["record_id"],
                   "text": "db record %s: %s = %s"
                           % (rec["record_id"], rec["key"], rec["value"]),
                   "claim_type": "factual", "asserted_at": now(),
                   "trust": rec.get("trust", "asserted"),
                   "context": {"spine": {"kind": "db-record",
                                         "key": rec["key"]}}}
    return append_event(root, ev)


def db_write_finish(root, rid, note):
    """Post-write contract (criterion 6): attest + receipt sha + verify
    re-run; a failing gate voids the record loudly instead of silently."""
    attest_claim(root, DB_RECORDS, "spine db", note)
    eff, _ = db_state(root)
    fails, warns, lines, _ = run_verify(root)
    for ln in lines:
        print(ln)
    if fails:
        r = dict(eff.get(rid) or {})
        r["record_id"] = rid
        r["status"] = "void"
        r["void_reason"] = "gate failed after write: %s" % "; ".join(fails)
        append_record(root, r)
        ev = base_event("claim.retracted")
        ev["claim_ref"] = rid
        ev["retracted_at"] = now()
        ev["retraction_reason"] = r["void_reason"]
        append_event(root, ev)
        attest_claim(root, DB_RECORDS, "spine db",
                     "void %s re-attest" % rid)
        print("db: GATE FAILED after write - record %s marked VOID: %s"
              % (rid, r["void_reason"]))
        txlog(root, "db", 1, "voided %s" % rid)
        sys.exit(1)
    txlog(root, "db", 0, note)


def db_server_call(args, tool, params):
    """Cross-machine call with offline spool (criterion 20)."""
    import urllib.request
    import urllib.error
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": params}})
    try:
        req = urllib.request.Request(args.server.rstrip("/") + "/mcp",
                                     body.encode(),
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        path = os.path.join(args.dir, DB_SPOOL)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": now(), "tool": tool,
                                 "arguments": params}, sort_keys=True) + "\n")
        print("db: %s unreachable (%s) - call spooled to %s; "
              "replays on next successful contact"
              % (args.server, e, DB_SPOOL))
        return None


def db_replay(root):
    path = os.path.join(root, DB_SPOOL)
    if not os.path.exists(path):
        return
    pending = [l for l in open(path, encoding="utf-8") if l.strip()]
    if not pending:
        return
    import urllib.request
    done = []
    for line in pending:
        call = json.loads(line)
        try:
            body = json.dumps({"jsonrpc": "2.0", "id": 1,
                               "method": "tools/call", "params": call})
            req = urllib.request.Request(
                SPINE_SERVER_URL.rstrip("/") + "/mcp", body.encode(),
                {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
            done.append(call)
        except Exception:
            break
    if done:
        with unlocked(path):
            rest = pending[len(done):]
            with open(path, "w", encoding="utf-8") as fh:
                fh.writelines(rest)
        print("db: replayed %d spooled call(s)" % len(done))


SPINE_SERVER_URL = ""


def cmd_db(args, root):
    global SPINE_SERVER_URL
    if getattr(args, "server", None):
        SPINE_SERVER_URL = args.server
        params = {k: v for k, v in vars(args).items()
                  if k not in ("cmd", "server", "dir")}
        resp = db_server_call(args, "db", params)
        if resp is None:
            return
        db_replay(root)
        print(json.dumps(resp.get("result", resp), sort_keys=True))
        code = resp.get("result", {}).get("exit_code", 0)
        sys.exit(0 if code == 0 else 1)
    if args.action == "add":
        eff, _ = db_state(root)
        for ref in (args.link or "").split(","):
            if ref and ref.strip() and ref.strip() not in eff:
                refuse("db add: link target %s not a known record_id "
                         "(exit 2, nothing written)" % ref.strip())
        rec = {"record_id": new_id("rec"), "key": args.key,
               "value": args.value,
               "trust": args.trust or "asserted",
               "source": args.source or "",
               "links": [l.strip() for l in (args.link or "").split(",")
                         if l.strip()],
               "status": "active", "supersedes": None, "created": now()}
        sha = append_record(root, rec)
        emit_record_claim(root, rec)
        db_write_finish(root, rec["record_id"], "add %s" % args.key)
        print(json.dumps({"ok": True, "record_id": rec["record_id"],
                          "sha256": sha}, sort_keys=True))
    elif args.action == "get":
        eff, _ = db_state(root)
        r = eff.get(args.ref)
        if not r:
            hits = [v for k, v in eff.items() if v["key"] == args.ref]
            if len(hits) == 1:
                r = hits[0]
        if not r:
            refuse("db get: no record %s (exact record_id or unique key)"
                     % args.ref)
        print(json.dumps(r, sort_keys=True))
    elif args.action == "link":
        eff, _ = db_state(root)
        if args.ref not in eff:
            refuse("db link: no record %s" % args.ref)
        if args.to not in eff:
            refuse("db link: link target %s not a known record_id"
                     % args.to)
        r = dict(eff[args.ref])
        r["links"] = sorted(set(r.get("links", []) + [args.to]))
        r["linked_at"] = now()
        append_record(root, r)
        db_write_finish(root, args.ref, "link %s->%s" % (args.ref, args.to))
        print(json.dumps({"ok": True, "record_id": args.ref,
                          "links": r["links"]}, sort_keys=True))
    elif args.action == "supersede":
        eff, _ = db_state(root)
        if args.ref not in eff:
            refuse("db supersede: no record %s" % args.ref)
        new = {"record_id": new_id("rec"), "key": eff[args.ref]["key"],
               "value": args.value, "trust": args.trust or "asserted",
               "source": args.source or "", "links": [], "status": "active",
               "supersedes": args.ref, "created": now()}
        append_record(root, new)
        emit_record_claim(root, new)
        old = dict(eff[args.ref])
        old["status"] = "superseded"
        old["superseded_by"] = new["record_id"]
        append_record(root, old)
        db_write_finish(root, new["record_id"], "supersede %s" % args.ref)
        print(json.dumps({"ok": True, "new": new["record_id"],
                          "supersedes": args.ref}, sort_keys=True))
    elif args.action == "list":
        eff, order = db_state(root)
        n = 0
        for rid in order:
            r = eff[rid]
            if args.key and r["key"] != args.key:
                continue
            if args.status and r["status"] != args.status:
                continue
            print("%s  %-9s %-11s %-24s %s"
                  % (rid, r["trust"], r["status"], r["key"],
                     str(r.get("value", ""))[:60]))
            n += 1
        sys.stderr.write("db: %d record(s) visible\n" % n)


# ------------------------------------------------------------ measurements
def cmd_measure(args, root):
    if args.action == "append":
        cid = resolve_claim_ref(root, args.source_claim)
        proc = subprocess.run(["sh", "-c", args.command],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            refuse("measure: command exited %d - refusing to record "
                     "a failed measurement (stderr: %s)"
                     % (proc.returncode, proc.stderr[:200]))
        observed = proc.stdout.rstrip("\n")
        if not observed:
            refuse("measure: command exited 0 with empty stdout - a "
                   "measurement must observe something; refusing (exit 2)")
        value = args.value if args.value is not None else observed
        if value != observed:
            refuse("measure: claimed value %r != observed %r - measured "
                     "means reproduced, refusal is the point (exit 2)"
                     % (value[:60], observed[:60]))
        rec = {"m_id": new_id("msr"), "ts": now(), "command": args.command,
               "value": value, "unit": args.unit, "observed": observed,
               "source_claim": cid, "by": producer()["name"]}
        em = base_event("claim.emitted")
        em["claim"] = {"claim_id": rec["m_id"],
                       "text": "measured %s %s via: %s" % (value,
                                                           args.unit,
                                                           args.command),
                       "claim_type": "calculation", "asserted_at": now(),
                       "trust": "measured",
                       "context": {"spine": {"kind": "measurement",
                                             "m_id": rec["m_id"],
                                             "source_claim": cid}}}
        append_event(root, em)
        path = os.path.join(root, MEASURED)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        line = json.dumps(rec, sort_keys=True) + "\n"
        with unlocked(path):
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
        attest_claim(root, MEASURED, "spine measure", rec["m_id"])
        txlog(root, "measure", 0, "append %s" % rec["m_id"])
        print(json.dumps({"ok": True, "m_id": rec["m_id"],
                          "sha256": hashlib.sha256(
                              open(path, "rb").read()).hexdigest()},
                         sort_keys=True))
    elif args.action == "audit":
        path = os.path.join(root, MEASURED)
        if not os.path.exists(path):
            refuse("measure audit: no %s - nothing has been measured yet"
                   % MEASURED)
        bad = 0
        n = 0
        for line in open(path, encoding="utf-8"):
            if not line.strip():
                continue
            rec = json.loads(line)
            n += 1
            proc = subprocess.run(["sh", "-c", rec["command"]],
                                  capture_output=True, text=True)
            observed = proc.stdout.rstrip("\n")
            if proc.returncode != 0 or observed != rec["observed"]:
                bad += 1
                print("DRIFT %s: was %r now %r (exit %d)"
                      % (rec["m_id"], rec["observed"][:50],
                         observed[:50], proc.returncode))
            else:
                print("OK   %s  %s %s" % (rec["m_id"], rec["value"][:40],
                                          rec["unit"]))
        print("measure audit: %d/%d reproduced" % (n - bad, n))
        sys.exit(1 if bad else 0)


# ------------------------------------------------------- knowledge index
TRUST_WEIGHT = {"measured": 3, "linked": 2, "asserted": 1}
VAULT_NOTE_RE = re.compile(r"^(---\n.*?\n---\n)", re.S)


def vault_notes(root):
    vdir = os.path.join(root, "vault")
    notes = []
    if not os.path.isdir(vdir):
        return notes
    for rel in sorted(os.listdir(vdir)):
        if not rel.endswith(".md") or rel == "README.md":
            continue
        text = open(os.path.join(vdir, rel), encoding="utf-8").read()
        meta = {"path": "vault/" + rel}
        m = VAULT_NOTE_RE.match(text)
        body = text
        if m:
            body = text[m.end():]
            for ln in m.group(1).splitlines():
                if ":" in ln and not ln.startswith(" "):
                    k, _, v = ln.partition(":")
                    meta[k.strip()] = v.strip()
        facts = re.findall(r"fact:([\w.-]+)", text)
        notes.append({"meta": meta, "facts": facts,
                      "text": (meta.get("name", rel) + ". "
                               + body.strip())[:400]})
    return notes


def cmd_index_digest(args, root):
    """Spec fingerprint shared with the keeper (criterion 21): sha256 over
    the same canonical JSON the generator ships as keeper/src/generated.rs.
    Byte-fidelity between the two binaries is one comparison away."""
    spec = {"version": VERSION,
            "params": dict(sorted(PARAMS.items())),
            "files": list(FILES),
            "new_in_v05": list(NEW_IN_V05),
            "rules": [[r[0], r[1], r[2], r[3]] for r in RULES],
            "tpl": {k: TPL[k] for k in sorted(TPL)}}
    print(hashlib.sha256(json.dumps(spec, sort_keys=True).encode())
          .hexdigest())


def cmd_index_build(args, root):
    entries, sources = [], {}
    mpath = os.path.join(root, MEASURED)
    if os.path.exists(mpath):
        sources[MEASURED] = sha_file(mpath)
        for line in open(mpath, encoding="utf-8"):
            if not line.strip():
                continue
            m = json.loads(line)
            entries.append({"id": m["m_id"], "trust": "measured",
                            "source": MEASURED,
                            "text": "%s %s [%s] via: %s"
                                    % (m["value"], m["unit"], m["m_id"],
                                       m["command"])})
    eff, order = db_state(root)
    if os.path.exists(os.path.join(root, DB_RECORDS)):
        sources[DB_RECORDS] = sha_file(os.path.join(root, DB_RECORDS))
    for rid in order:
        r = eff[rid]
        if r["status"] != "active":
            continue
        entries.append({"id": rid, "trust": r["trust"], "source": DB_RECORDS,
                        "text": "%s: %s" % (r["key"], r["value"])})
    for note in vault_notes(root):
        sha = note["meta"].get("source_sha", "")
        src = note["meta"].get("source", "")
        if src:
            p = os.path.join(root, src)
            sources[src] = sha_file(p) if os.path.exists(p) else "missing"
        e = {"id": "vault:" + note["meta"]["path"],
             "trust": "asserted", "source": note["meta"]["path"],
             "facts": note["facts"], "source_sha": sha,
             "text": note["text"]}
        if src:
            e["note_source"] = src
        entries.append(e)
    entries.sort(key=lambda e: e["id"])
    path = os.path.join(root, KINDEX)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with unlocked(path):
        with open(path, "w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(json.dumps(e, sort_keys=True) + "\n")
    derived = {"view": KINDEX,
               "command": "python3 tools/spine.py index build",
               "sources": sources, "built": now()}
    dpath = os.path.join(root, "data", "derived.json")
    with open(dpath, "w", encoding="utf-8") as fh:
        json.dump(derived, fh, indent=1, sort_keys=True)
        fh.write("\n")
    attest_claim(root, KINDEX, "spine index", "build")
    txlog(root, "index", 0, "build %d entries" % len(entries))
    print("index: %d entries (%d measured, %d asserted) -> %s"
          % (len(entries),
             sum(1 for e in entries if e["trust"] == "measured"),
             sum(1 for e in entries if e["trust"] == "asserted"), KINDEX))


def derived_stale(root):
    """Re-derive freshness (criterion 12): WARNING + command, never fails."""
    dpath = os.path.join(root, "data", "derived.json")
    if not os.path.exists(dpath):
        return [], {}
    d = json.load(open(dpath, encoding="utf-8"))
    stale = []
    for rel, want in (d.get("sources") or {}).items():
        p = os.path.join(root, rel)
        have = sha_file(p) if os.path.exists(p) else "missing"
        if have != want:
            stale.append(rel)
    return stale, d


def _stale_map(root):
    """Which kindex entries are STALE (criterion 22): a derived source
    moved (derived.json), or a note's own source_sha no longer matches,
    or it cites a fact whose entry is itself stale."""
    dpath = os.path.join(root, "data", "derived.json")
    stale_sources = []
    if os.path.exists(dpath):
        d = json.load(open(dpath, encoding="utf-8"))
        for rel, want in (d.get("sources") or {}).items():
            p = os.path.join(root, rel)
            have = sha_file(p) if os.path.exists(p) else "missing"
            if have != want:
                stale_sources.append(rel)
    kpath = os.path.join(root, KINDEX)
    out = {}
    if not os.path.exists(kpath):
        return out, stale_sources
    for line in open(kpath, encoding="utf-8"):
        if not line.strip():
            continue
        e = json.loads(line)
        why = None
        if e.get("source") in stale_sources or \
                e.get("note_source") in stale_sources:
            why = "source moved"
        if not why and e.get("source_sha") and e.get("note_source"):
            p = os.path.join(root, e["note_source"])
            if not os.path.exists(p) or sha_file(p) != e["source_sha"]:
                why = "source_sha mismatch"
        if why:
            out[e["id"]] = why
    changed = True
    while changed:
        changed = False
        for line in open(kpath, encoding="utf-8"):
            if not line.strip():
                continue
            e = json.loads(line)
            if e["id"] in out:
                continue
            hit = None
            for f in e.get("facts") or []:
                if f in out or "vault:" + f in out:
                    hit = f
                    break
            if hit:
                out[e["id"]] = "cites stale fact:%s" % hit
                changed = True
    return out, stale_sources


def cmd_search(args, root):
    if not os.path.exists(os.path.join(root, KINDEX)):
        refuse("search: no knowledge index - run index build first")
    terms = [t for t in re.split(r"[^a-z0-9_]+", args.query.lower()) if t]
    stale, _ = _stale_map(root)
    scored = []
    for line in open(os.path.join(root, KINDEX), encoding="utf-8"):
        if not line.strip():
            continue
        e = json.loads(line)
        low = e["text"].lower()
        tf = sum(low.count(t) for t in terms)
        if not tf:
            continue
        is_stale = e["id"] in stale
        score = tf * TRUST_WEIGHT.get(e["trust"], 1) * (0.4 if is_stale
                                                        else 1.0)
        scored.append((score, e, is_stale))
    scored.sort(key=lambda x: (-x[0], x[1]["id"]))
    budget = args.budget
    total, shown = 0, 0
    for score, e, is_stale in scored:
        tags = "[%s%s]" % (e["trust"], " STALE" if is_stale else "")
        line = "%s %s: %s" % (tags, e["id"], e["text"][:120])
        if args.explain:
            why = stale.get(e["id"], "")
            line += "   (score %.1f%s)" % (
                score, ("; stale: %s" % why) if is_stale else "")
        cost = len(line) // 4 + 1
        if budget and total + cost > budget:
            print("... budget %d tokens reached after %d result(s)"
                  % (budget, shown))
            break
        total += cost
        shown += 1
        print(line)
    if not shown:
        print("search: no match for %r" % args.query)


# ------------------------------------------------------------------ archive
DATED_BLOCK_RE = re.compile(r"^(Closed \d{4}-\d{2}-\d{2}|"
                           r"#{1,6} *\(?\d{4}-\d{2}-\d{2})")


def split_dated_blocks(lines):
    keep, blocks, cur = [], [], None
    for ln in lines:
        if DATED_BLOCK_RE.match(ln):
            if cur:
                blocks.append(cur)
            cur = [ln]
        elif cur is not None and ln.startswith("    "):
            cur.append(ln)
        else:
            if cur:
                blocks.append(cur)
                cur = None
            keep.append(ln)
    if cur:
        blocks.append(cur)
    return keep, blocks


def cmd_archive(args, root):
    """Move dated STATE blocks to docs/STATE-LOG.md byte-exact, keeping
    the literal next-command last (NCM STATE-LOG supersession pattern)."""
    sp = os.path.join(root, "STATE.md")
    lines = open(sp, encoding="utf-8").read().splitlines(True)
    keep, blocks = split_dated_blocks(lines)
    if not blocks:
        print("archive: no dated blocks in STATE.md")
        return
    kept = "".join(keep)
    if "Next command:" not in kept:
        refuse("archive: refusing - next-command block would be lost "
                 "(exit 2, STATE.md untouched)")
    lp = os.path.join(root, STATE_LOG)
    os.makedirs(os.path.dirname(lp), exist_ok=True)
    header = "" if os.path.exists(lp) else "# STATE-LOG - archived history\n"
    moved = "".join("".join(b) for b in blocks)
    with open(lp, "a", encoding="utf-8") as fh:
        fh.write(header + moved)
    with unlocked(sp):
        with open(sp, "w", encoding="utf-8") as fh:
            fh.write(kept.rstrip("\n") + "\n")
    attest_claim(root, "STATE.md", "spine archive", "%d block(s) moved"
                 % len(blocks))
    attest_claim(root, STATE_LOG, "spine archive", "appended")
    txlog(root, "archive", 0, "%d block(s)" % len(blocks))
    print("archive: %d dated block(s) moved to %s byte-exact; "
          "STATE.md now %d lines" % (len(blocks), STATE_LOG,
                                     len(open(sp, encoding="utf-8"
                                              ).read().splitlines())))


# --------------------------------------------------------------------- hooks
HOOK_SCRIPT = """#!/bin/bash
# spine pre-commit gate (fast: verify only). Bypass, logged:
#   LEDGER_HOOK_BYPASS="why" git commit ...
set -u
cd "$(git rev-parse --show-toplevel)"
if python3 tools/spine.py verify > /tmp/spine-hook-verify.log 2>&1; then
  exit 0
fi
if [ -n "${LEDGER_HOOK_BYPASS:-}" ]; then
  echo "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) bypass: ${LEDGER_HOOK_BYPASS}" \\
    >> hooks-bypass.log
  echo "spine hook: BYPASSED (logged to %s): ${LEDGER_HOOK_BYPASS}"
  exit 0
fi
echo "spine hook: BLOCKED - verify failed (see /tmp/spine-hook-verify.log)"
echo "spine hook: escape hatch: LEDGER_HOOK_BYPASS=\\"one-line-why\\" ..."
exit 1
"""


def lock_targets(root):
    return [os.path.join(root, rel) for rel in
            LOCKED_ON_INSTALL + ["tools/spine.py"]]


def cmd_hooks(args, root):
    if args.action == "install":
        gitd = os.path.join(root, ".git")
        if not os.path.isdir(gitd):
            refuse("hooks install: %s is not a git repo (exit 2)" % root)
        hp = os.path.join(gitd, "hooks", "pre-commit")
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        with open(hp, "w", encoding="utf-8") as fh:
            fh.write(HOOK_SCRIPT % HOOKS_LOG)
        os.chmod(hp, 0o755)
        locked = []
        for p in lock_targets(root):
            if os.path.exists(p):
                set_lock(p, True)
                locked.append(os.path.relpath(p, root))
        ev = base_event("claim.emitted")
        ev["claim"] = {"claim_id": new_id("clm"),
                       "text": "hooks install: pre-commit gate + uchg on %s"
                               % ", ".join(locked),
                       "claim_type": "factual", "asserted_at": now(),
                       "context": {"spine": {"kind": "hooks",
                                             "action": "install",
                                             "locked": locked}}}
        append_event(root, ev)
        txlog(root, "hooks", 0, "install")
        print("hooks: pre-commit installed; locked: %s"
              % (", ".join(locked) or "(none present)"))
    elif args.action == "status":
        for p in lock_targets(root):
            rel = os.path.relpath(p, root)
            if not os.path.exists(p):
                print("  %-24s absent" % rel)
            else:
                mode = oct(stat.S_IMODE(os.stat(p).st_mode))[2:]
                print("  %-24s %s mode %s" % (rel, "LOCKED(uchg)"
                                              if is_locked(p) else "writable",
                                              mode))
        hp = os.path.join(root, ".git", "hooks", "pre-commit")
        print("  pre-commit hook: %s"
              % ("installed" if os.path.exists(hp) else "NOT installed"))
    elif args.action == "unlock":
        if not args.reason:
            refuse("hooks unlock: --reason required (accountability, "
                     "rule R6)")
        freed = []
        for p in lock_targets(root):
            if is_locked(p):
                set_lock(p, False)
                freed.append(os.path.relpath(p, root))
        with open(os.path.join(root, HOOKS_LOG), "a", encoding="utf-8") as f:
            f.write("%s unlock: %s (%s)\n" % (now(), args.reason,
                                              ", ".join(freed)))
        txlog(root, "hooks", 0, "unlock: %s" % args.reason)
        print("hooks: unlocked %s (reason logged)"
              % (", ".join(freed) or "(nothing was locked)"))


# --------------------------------------------------------------------- adopt
NEW_IN_V05 = ["harness.md", "tools/REGISTRY.md", "docs/measurement-schema.md",
              "vault/README.md"]


def seed_new_files(root, name, force=False):
    """Seed v0.5 parts that a v0.4 skeleton lacks. Existing files are
    never rewritten (adopt contract: pre-existing bytes stay put)."""
    added = []
    for rel in NEW_IN_V05:
        dest = os.path.join(root, rel)
        if os.path.exists(dest) and not force:
            continue
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(render(TPL[rel], name))
        added.append(rel)
    for d in (os.path.join(root, DB_DIR), os.path.join(root, "docs")):
        os.makedirs(d, exist_ok=True)
    return added


def cmd_adopt(args, root):
    """In-place upgrade of a v0.4 skeleton (criterion 3): the ledger and
    every human file stay byte-identical; v0.5 parts arrive as NEW signed
    files; STATE.md is not touched."""
    if not os.path.exists(os.path.join(root, LEDGER)):
        refuse("adopt: no ledger in %s - this is not a spine project"
                 % root)
    name = args.name or root
    plan = []
    old_copy = os.path.join(root, "tools", "spine.py")
    if os.path.exists(old_copy):
        ver = ""
        for ln in open(old_copy, encoding="utf-8"):
            m = re.match(r'VERSION = "([0-9.]+)"', ln)
            if m:
                ver = m.group(1)
                break
        plan.append("replace tools/spine.py (%s -> %s)" % (ver, VERSION))
    for rel in NEW_IN_V05:
        if not os.path.exists(os.path.join(root, rel)):
            plan.append("add %s (new, signed)" % rel)
    for rel in ("data/db", "docs"):
        if not os.path.isdir(os.path.join(root, rel)):
            plan.append("mkdir %s" % rel)
    if args.dry_run:
        print("adopt --dry-run for %s:" % root)
        for p in plan:
            print("  " + p)
        print("  (ledger, STATE.md, TODO.md and all human files: "
              "byte-identical)")
        return
    if not plan:
        print("adopt: already at v0.5 - nothing to do")
        return
    before = {rel: (sha_file(os.path.join(root, rel))
                    if os.path.exists(os.path.join(root, rel)) else None)
              for rel in FILES + ["STATE.md", "TODO.md", "AGENTS.md"]}
    with unlocked(old_copy):
        shutil.copy2(os.path.abspath(__file__), old_copy)
    added = seed_new_files(root, name)
    attest_claim(root, "tools/spine.py", "spine " + VERSION, "adopt")
    for rel in added:
        attest_claim(root, rel, "spine " + VERSION, "adopt")
    set_lock(old_copy, True)
    for rel, h in before.items():
        now_h = (sha_file(os.path.join(root, rel))
                 if os.path.exists(os.path.join(root, rel)) else None)
        if h != now_h:
            sys.exit("adopt: pre-existing file %s changed during adopt "
                     "(expected byte-identical) - aborting loudly" % rel)
    txlog(root, "adopt", 0, "%d new file(s)" % len(added))
    print("adopt: upgraded to %s - tools/spine.py replaced, %d new signed "
          "file(s), all pre-existing files byte-identical"
          % (VERSION, len(added)))
    print("adopt: next -> python3 tools/spine.py verify ; read harness.md")


# ------------------------------------------------------------------- promote
def cmd_promote(args, root):
    cid = resolve_claim_ref(root, args.claim_id)
    if args.to != "spine":
        refuse("promote: only --to spine exists (exit 2)")
    home = os.environ.get("SPINE_HOME") or os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))
    inbox = os.path.join(home, "INBOX.md")
    text = ""
    for ev in read_events(root):
        c = ev.get("claim") or {}
        if c.get("claim_id") == cid:
            text = c["text"]
    header = "" if os.path.exists(inbox) else "# Spine inbox - promoted " \
        "candidate mechanisms\n\nclaim_id | date | origin | text\n"
    with open(inbox, "a", encoding="utf-8") as fh:
        fh.write(header + "%s | %s | %s | %s\n"
                 % (cid, now()[:10], root, text[:200]))
    txlog(root, "promote", 0, cid)
    print("promote: %s appended to %s" % (cid, inbox))


# ----------------------------------------------------------------- dayreport
def cmd_dayreport(args, root):
    day = args.date or time.strftime("%Y-%m-%d")
    print("DAYREPORT %s (%s)" % (day, root))
    gates = {"pass": 0, "fail": 0}
    txp = os.path.join(root, TXLOG)
    by_tool = {}
    if os.path.exists(txp):
        for line in open(txp, encoding="utf-8"):
            if not line.strip():
                continue
            t = json.loads(line)
            if not t["ts"].startswith(day):
                continue
            by_tool[t["tool"]] = by_tool.get(t["tool"], 0) + 1
            if t["tool"] == "verify":
                gates["pass" if t["exit"] == 0 else "fail"] += 1
    print("GATES: %d verify pass / %d fail | transactions: %s"
          % (gates["pass"], gates["fail"],
             ", ".join("%s=%d" % kv for kv in sorted(by_tool.items()))
             or "none"))
    print("BYPASSES/UNLOCKS:")
    hp = os.path.join(root, HOOKS_LOG)
    lines = [l.rstrip("\n") for l in open(hp, encoding="utf-8")
             if l.startswith(day)] if os.path.exists(hp) else []
    for l in lines:
        print("  " + l)
    if not lines:
        print("  (none)")
    print("STALE VIEWS:")
    stale_notes, stale_sources = _stale_map(root)
    for rel in stale_sources:
        print("  STALE: %s (re-derive: python3 tools/spine.py index build)"
              % rel)
    for eid, why in sorted(stale_notes.items()):
        print("  STALE-VIA %s: %s" % (eid, why))
    if not stale_sources and not stale_notes:
        print("  (all derived views fresh)")
    print("LOCKS:")
    for p in lock_targets(root):
        rel = os.path.relpath(p, root)
        if os.path.exists(p):
            print("  %-24s %s" % (rel, "locked" if is_locked(p)
                                  else "writable"))
    sys.exit(0)


# --------------------------------------------------------------------- vault
DISKUTIL_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
	<key>MountPoint</key>
	<string>/Volumes/BACKUP</string>
	<key>IgnoreOwnership</key>
	<true/>
</dict>
</plist>
"""


def parse_diskutil_ownership(plist_text):
    """Return True if ownership is IGNORED on the volume (FAT/exFAT).
    A vault whose ownership is ignored cannot hold the privilege
    boundary - that is a hard error, not a warning."""
    keys = re.findall(r"<key>\s*(IgnoreOwnership|OwnershipIgnored)"
                      r"\s*</key>\s*<(true/>|false/>)", plist_text)
    for _, v in keys:
        if v == "true/>":
            return True
    m = re.search(r"Owners:\s*(Enabled|Disabled)", plist_text)
    if m:
        return m.group(1) == "Disabled"
    return False


def vol_vault_dir(dest):
    """Volume-side dir holding the vault files: dest/vault/ when the
    keeper daemon hierarchy (multi-project volume root) is present,
    else dest itself (plain vault mirror layout)."""
    sub = os.path.join(dest, "vault")
    return sub if os.path.isdir(sub) else dest


def cmd_vault(args, root):
    import shutil as _sh
    vol = getattr(args, "volume", None)
    dest = os.path.join(vol, "spine-vault") if vol else None
    if args.action == "init":
        os.makedirs(os.path.join(root, "vault"), exist_ok=True)
        if dest:
            if vol.startswith("/Volumes/") and shutil.which("diskutil"):
                out = subprocess.run(["diskutil", "info", "-plist", vol],
                                     capture_output=True, text=True).stdout
                if "Owner" not in out:
                    out += "\n" + subprocess.run(
                        ["diskutil", "info", vol], capture_output=True,
                        text=True).stdout
                if parse_diskutil_ownership(out):
                    refuse("IGNORED-OWNERSHIP: %s ignores unix ownership "
                             "(FAT/exFAT?) - privilege boundary impossible"
                             " (exit 2)" % vol)
            os.makedirs(dest, exist_ok=True)
        print("vault: ready (project vault/ %s)"
              % ("+ volume " + dest if dest else "- no volume yet"))
    elif args.action == "mirror":
        src = os.path.join(root, "vault")
        if not dest or not os.path.isdir(dest):
            refuse("vault mirror: run vault init --volume PATH first")
        vdir = vol_vault_dir(dest)
        if os.path.isdir(vdir):
            _sh.rmtree(vdir)
        _sh.copytree(src, vdir)
        n, bad = 0, []
        for rel in sorted(os.listdir(vdir)):
            p = os.path.join(vdir, rel)
            q = os.path.join(src, rel)
            if os.path.isfile(p) and sha_file(p) != sha_file(q):
                bad.append(rel)
            n += 1
        txlog(root, "vault", 0, "mirror %d file(s)" % n)
        print("vault mirror: %d file(s) -> %s%s"
              % (n, dest, "" if not bad else " DRIFT: " + ", ".join(bad)))
        sys.exit(1 if bad else 0)
    elif args.action == "rehydrate":
        if not dest or not os.path.isdir(dest):
            refuse("vault rehydrate: volume copy missing at %s" % dest)
        src = os.path.join(root, "vault")
        if os.path.isdir(src):
            _sh.rmtree(src)
        _sh.copytree(vol_vault_dir(dest), src)
        print("vault rehydrate: restored %s from %s" % (src, dest))
    elif args.action == "status":
        src = os.path.join(root, "vault")
        local = {}
        if os.path.isdir(src):
            for rel in sorted(os.listdir(src)):
                p = os.path.join(src, rel)
                if os.path.isfile(p):
                    local[rel] = sha_file(p)
        remote = {}
        if dest and os.path.isdir(dest):
            for rel in sorted(os.listdir(vol_vault_dir(dest))):
                p = os.path.join(vol_vault_dir(dest), rel)
                if os.path.isfile(p):
                    remote[rel] = sha_file(p)
        drift = [k for k in set(local) | set(remote)
                 if local.get(k) != remote.get(k)]
        print("vault status: %d local, %d on volume, %d differ%s"
              % (len(local), len(remote), len(drift),
                 ": " + ", ".join(sorted(drift)[:6]) if drift else ""))


# ----------------------------------------------------------------------- mcp
MCP_TOOLS = [
    {"name": "verify", "description": "run the gate; exit_code 1 = gate "
                                      "failed", "schema": {}},
    {"name": "preflight", "description": "rule R7 prior-art search; "
                                         "exit_code 2 = hits, need reason",
     "schema": {"query": "string", "reason": "string?"}},
    {"name": "db", "description": "clerk verbs: add/get/link/supersede/"
                                 "list",
     "schema": {"action": "add|get|link|supersede|list", "key": "string?",
                "value": "string?", "ref": "string?", "to": "string?",
                "trust": "measured|linked|asserted?", "source": "string?",
                "link": "string?", "status": "string?"}},
    {"name": "measure", "description": "append/audit measurements",
     "schema": {"action": "append|audit", "command": "string?",
                "value": "string?", "unit": "string?",
                "source_claim": "string?"}},
    {"name": "loop", "description": "close a loop over TODO items",
     "schema": {"method": "string?"}},
    {"name": "search", "description": "query the knowledge index",
     "schema": {"query": "string", "budget": "int?", "explain": "bool?"}},
    {"name": "dayreport", "description": "unattended accountability "
                                         "digest", "schema": {}},
]


def tool_dispatch(root, name, params):
    """MCP tool call -> (exit_code, text). Same code paths as the CLI."""
    params = params or {}
    import io
    import contextlib
    code, buf = 0, io.StringIO()
    try:
        if name == "verify":
            ns = argparse.Namespace(dir=root)
            with contextlib.redirect_stdout(buf):
                cmd_verify(ns)
        elif name == "preflight":
            ns = argparse.Namespace(query=params.get("query", ""),
                                    reason=params.get("reason"),
                                    artifacts=[], server=None, dir=root)
            with contextlib.redirect_stdout(buf):
                cmd_preflight(ns, root)
        elif name == "db":
            ns = argparse.Namespace(action=params.get("action", "list"),
                                    key=params.get("key"),
                                    value=params.get("value"),
                                    ref=params.get("ref"),
                                    to=params.get("to"),
                                    trust=params.get("trust"),
                                    source=params.get("source"),
                                    link=params.get("link"),
                                    status=params.get("status"),
                                    server=None, dir=root)
            with contextlib.redirect_stdout(buf):
                cmd_db(ns, root)
        elif name == "measure":
            ns = argparse.Namespace(action=params.get("action", "append"),
                                    command=params.get("command"),
                                    value=params.get("value"),
                                    unit=params.get("unit"),
                                    source_claim=params.get("source_claim"),
                                    dir=root)
            with contextlib.redirect_stdout(buf):
                cmd_measure(ns, root)
        elif name == "loop":
            ns = argparse.Namespace(close=True, touch=[], touch_conf=0.6,
                                    method=params.get("method",
                                                      "model_check"),
                                    dir=root)
            with contextlib.redirect_stdout(buf):
                cmd_loop_close(ns, root)
        elif name == "search":
            ns = argparse.Namespace(query=params.get("query", ""),
                                    budget=int(params.get("budget") or 0),
                                    explain=bool(params.get("explain")),
                                    dir=root)
            with contextlib.redirect_stdout(buf):
                cmd_search(ns, root)
        elif name == "dayreport":
            ns = argparse.Namespace(date=params.get("date"), dir=root)
            with contextlib.redirect_stdout(buf):
                try:
                    cmd_dayreport(ns, root)
                except SystemExit as e:
                    code = e.code or 0
        else:
            code, buf = 2, io.StringIO("unknown tool: %s" % name)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if not e.code else 1)
    except Exception as e:
        code, buf = 1, io.StringIO("tool error: %s: %s" % (type(e).__name__,
                                                           e))
    text = buf.getvalue()
    txlog(root, "mcp:" + name, code, "tool-call")
    return code, text


def mcp_handle(root, req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ai-project-spine",
                               "version": VERSION}}
    if method == "tools/list":
        return {"tools": MCP_TOOLS}
    if method == "tools/call":
        p = req.get("params") or {}
        code, text = tool_dispatch(root, p.get("name"),
                                   p.get("arguments"))
        return {"content": [{"type": "text", "text": text}],
                "isError": code != 0, "exit_code": code}
    return None


def cmd_mcp(args):
    root = args.dir
    if args.http:
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    req = json.loads(self.rfile.read(n).decode())
                    res = mcp_handle(root, req)
                    body = json.dumps({"jsonrpc": "2.0",
                                       "id": req.get("id"),
                                       "result": res}).encode()
                except Exception as e:
                    body = json.dumps({"jsonrpc": "2.0", "id": None,
                                       "error": {"code": -32700,
                                                 "message": str(e)}
                                       }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = HTTPServer(("127.0.0.1", args.http), H)
        print("spine mcp http: http://127.0.0.1:%d/mcp (dir=%s)"
              % (args.http, root), flush=True)
        srv.serve_forever()
    else:
        print('{"jsonrpc":"2.0","method":"notice","params":{"msg":"spine '
              'mcp stdio ready: send one JSON-RPC request per line"}}',
              flush=True)
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                res = mcp_handle(root, req)
                out = {"jsonrpc": "2.0", "id": req.get("id"),
                       "result": res}
            except Exception as e:
                out = {"jsonrpc": "2.0", "id": None,
                       "error": {"code": -32700, "message": str(e)}}
            print(json.dumps(out, sort_keys=True), flush=True)


# ------------------------------------------------------------- selftest
def _st(root, *rest, env=None, input=None):
    e = dict(os.environ)
    e.pop("SPINE_TEST_NOW", None)
    if env:
        e.update(env)
    return subprocess.run([sys.executable, os.path.abspath(__file__),
                           *rest, "--dir", root], capture_output=True,
                          text=True, env=e, input=input)


def cmd_selftest(args):
    """End-to-end gate in a temp dir: walks the exact paths a human copies.

    Origin (2026-10-21 review): truncated ids in TODO.md silently defeated
    `claim verify` for copy-paste users; phantom refs were accepted. Tests
    only walk the paths they were written to walk - this walks the TEXT.
    """
    tmp = tempfile.mkdtemp(prefix="spine-selftest-")
    proj = os.path.join(tmp, "selftest-proj")
    checks = []

    def check(name, cond, detail=""):
        checks.append(bool(cond))
        print("%s  %s%s" % ("PASS" if cond else "FAIL", name,
                            "" if cond else "   <- " + detail))

    def todo_md():
        with open(os.path.join(proj, "TODO.md"), encoding="utf-8") as fh:
            return fh.read()

    def ledger_bytes():
        with open(os.path.join(proj, LEDGER), "rb") as fh:
            return fh.read()

    try:
        r = _st(proj, "init", "--name", "selftest")
        check("1 init builds a skeleton (exit 0)", r.returncode == 0,
              (r.stderr or r.stdout)[:200])

        r = _st(proj, "todo", "add", "--what", "Fix auth redirect",
                "--why", "login loop reported", "--kills", "probe shows ok")
        m = re.search(r"clm_[0-9a-f]+", r.stdout)
        issued = m.group(0) if m else ""
        check("2 todo add issues a full id (exit 0, clm_ + 26 hex)",
              r.returncode == 0 and len(issued) == 30,
              (r.stdout + r.stderr)[:200])
        _st(proj, "todo", "add", "--what", "Cache headers",
            "--why", "slow first paint", "--kills", "trace shows origin")

        line = next((l for l in todo_md().splitlines()
                     if "Fix auth redirect" in l), "")
        shown = re.search(r"clm_[0-9a-f]+", line)
        copied = shown.group(0) if shown else ""
        check("3 TODO.md renders the FULL id (what you see is what you "
              "copy)", copied == issued,
              "issued %s but TODO.md shows %s" % (issued, copied))

        r = _st(proj, "claim", "verify", copied, "--result", "supported",
                "--method", "human_review", "--confidence", "0.85")
        check("4 the copied id endorses to conf 0.85 (roundtrip from text)",
              r.returncode == 0 and "| conf 0.85" in todo_md(),
              "exit %d; md line: %s" % (r.returncode, next(
                  (l for l in todo_md().splitlines()
                   if "Fix auth redirect" in l), "?")))

        r = _st(proj, "loop", "--close", "--method", "source_attestation")
        md = todo_md()
        endorsed = next((l for l in md.splitlines()
                         if "Fix auth redirect" in l), "")
        other = next((l for l in md.splitlines() if "Cache headers" in l), "")
        check("5 loop refreshes the endorsed item (0.85 -> 0.765, still "
              "execute) while the untouched one decays (0.55 -> 0.495)",
              "| conf 0.77" in endorsed and "| conf 0.49" in other,
              "endorsed: %s | other: %s" % (endorsed[-60:], other[-60:]))

        before = ledger_bytes()
        r = _st(proj, "claim", "verify", "clm_DOESNOTEXIST", "--result",
                "supported", "--method", "human_review")
        check("6 phantom claim ref rejected exit 2, ledger byte-unchanged",
              r.returncode == 2 and ledger_bytes() == before,
              "exit %d" % r.returncode)

        before = ledger_bytes()
        r = _st(proj, "todo", "done", "clm_NOPE", "--by", "chris")
        check("7 todo done with phantom ref rejected exit 2, ledger "
              "untouched", r.returncode == 2 and ledger_bytes() == before,
              "exit %d" % r.returncode)

        r = _st(proj, "claim", "verify", issued[:-1], "--result",
                "supported", "--method", "human_review",
                "--confidence", "0.85")
        check("8 unique prefix (full id minus last char) resolves and "
              "endorses", r.returncode == 0 and "| conf 0.85" in todo_md(),
              "exit %d %s" % (r.returncode, r.stderr[:120]))

        r = _st(proj, "claim", "verify", "clm_", "--result", "supported",
                "--method", "human_review")
        named = re.findall(r"clm_[0-9a-f]+", r.stderr)
        check("9 ambiguous prefix rejected exit 2, candidates named",
              r.returncode == 2 and issued in named,
              "exit %d; named %d candidates" % (r.returncode, len(named)))

        r = _st(proj, "verify")
        check("10 gate still green end-to-end (verify exit 0, reports "
              "claims line)", r.returncode == 0 and "claims:" in r.stdout,
              (r.stdout + r.stderr)[-200:])

        # --- v0.4 checks: preflight / close / retest / orphans / session ---
        r = _st(proj, "preflight", "auth redirect")
        check("11 preflight finds prior work (exit 2, TODO+ledger hits "
              "named)", r.returncode == 2 and "prior-art hit" in r.stdout,
              "exit %d %s" % (r.returncode, r.stdout[:150]))

        r = _st(proj, "preflight", "auth redirect", "--reason", "extending")
        check("12 preflight --reason proceeds (exit 0, PROCEED logged)",
              r.returncode == 0 and "PROCEED" in r.stdout,
              "exit %d %s" % (r.returncode, r.stdout[:150]))

        r = _st(proj, "preflight", "zzqqxxyyward")
        check("13 preflight clean query exits 0",
              r.returncode == 0 and "clean" in r.stdout,
              "exit %d %s" % (r.returncode, r.stdout[:150]))

        todo_id = re.search(r"clm_[0-9a-f]+", todo_md()).group(0)
        r = _st(proj, "close", "--supersedes", todo_id, "--note", "shipped")
        state = open(os.path.join(proj, "STATE.md"),
                     encoding="utf-8").read()
        check("14 close writes dated STATE tail + attests (supersedes id)",
              r.returncode == 0 and "Closed" in state and todo_id in state,
              (r.stdout + r.stderr)[:200])

        before = open(os.path.join(proj, "STATE.md"), "rb").read()
        r = _st(proj, "close", "--supersedes", "clm_PHANTOM")
        check("15 close with phantom ref refused exit 2, STATE untouched",
              r.returncode == 2 and open(
                  os.path.join(proj, "STATE.md"), "rb").read() == before,
              "exit %d" % r.returncode)

        with open(os.path.join(proj, "BUGS.md"), "a",
                  encoding="utf-8") as fh:
            fh.write("\nB01 | %s | probe results discarded after tool "
                     "crash\n" % time.strftime("%Y-%m-%d"))
        _st(proj, "sign", "BUGS.md", "--by", "selftest",
            "--reason", "add entry")
        r = _st(proj, "verify")
        check("16 BUGS.md discard without retest: fails the gate",
              r.returncode == 1 and "retest:" in r.stdout,
              "exit %d %s" % (r.returncode, r.stdout[-150:]))
        with open(os.path.join(proj, "BUGS.md"), "a",
                  encoding="utf-8") as fh:
            fh.write("retest: rerun probe from saved artifacts, 2026-11-01\n")
        _st(proj, "sign", "BUGS.md", "--by", "selftest",
            "--reason", "add retest field")
        r = _st(proj, "verify")
        check("17 retest: field satisfies the gate (verify green again)",
              r.returncode == 0, (r.stdout + r.stderr)[-150:])

        r = _st(proj, "claim", "emit", "--text", "orphan probe note",
                "--type", "factual")
        r2 = _st(proj, "verify")
        check("18 orphan-coverage flags unreferenced claims without "
              "blocking", r2.returncode == 0 and "ORPHAN-COVERAGE"
              in r2.stdout, "exit %d %s" % (r2.returncode, r2.stdout[-150:]))

        r = _st(proj, "claim", "emit", "--text", "session stamp probe",
                "--type", "factual",
                env={"OPENFOX_SESSION_ID": "sess_TEST1234",
                     "SPINE_PRODUCER_ID": ""})
        last = read_events(proj)[-1]
        check("19 OPENFOX_SESSION_ID standardized into producer agent_id",
              r.returncode == 0 and last["producer"]["agent_id"]
              == "urn:session:sess_TEST1234",
              "got %s" % last["producer"].get("agent_id"))

        r = _st(proj, "verify")
        check("20 gate green after all v0.4 mutations (close/BUGS/orphan)",
              r.returncode == 0, (r.stdout + r.stderr)[-150:])

        # --- v0.4 opt-in surfaces: --with-golden + sessions ingest ---
        proj2 = os.path.join(tmp, "golden-proj")
        _st(proj2, "init", "--name", "gold")
        has_g = os.path.exists(os.path.join(proj2, "tools", "golden.sh"))
        r = _st(proj, "init", "--name", "again", "--force", "--with-golden")
        ok_g = (os.path.exists(os.path.join(proj, "tools", "golden.sh"))
                and os.path.exists(os.path.join(proj, "tools",
                                                "golden.conf"))
                and "D00g" in open(os.path.join(proj, "DECISIONS.md"),
                                   encoding="utf-8").read())
        check("21 default init has no golden files; --with-golden drops "
              "stub+conf+DECISIONS seed", not has_g and r.returncode == 0
              and ok_g, (r.stdout + r.stderr)[:150])

        g = subprocess.run(["bash", os.path.join(proj, "tools",
                                                 "golden.sh"), "capture"],
                           capture_output=True, text=True)
        g2 = subprocess.run(["bash", os.path.join(proj, "tools",
                                                  "golden.sh"), "check"],
                            capture_output=True, text=True)
        check("22 golden.sh runs standalone in a scratch dir (capture "
              "then check -> OK, exit 0)", g.returncode == 0
              and g2.returncode == 0 and "OK selfcheck" in g2.stdout,
              (g.stdout + g.stderr + g2.stdout)[-150:])

        src = os.path.join(tmp, "conv-001.md")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write("user: hello\nassistant: hi (conversation record)\n")
        src_sha = hashlib.sha256(open(src, "rb").read()).hexdigest()
        r = _st(proj, "sessions", "ingest", src)
        dest = os.path.join(proj, "sessions", "conv-001.md")
        head = open(dest, encoding="utf-8").readline() if \
            os.path.exists(dest) else ""
        check("23 sessions ingest writes attested provenance-headered "
              "copy, source byte-unchanged (mode=ro)",
              r.returncode == 0 and "spine sessions ingest" in head
              and src_sha == hashlib.sha256(
                  open(src, "rb").read()).hexdigest(),
              (r.stdout + r.stderr)[:150])

        r = _st(proj, "verify")
        check("24 gate green with golden + sessions files attested "
              "(opt-in surfaces obey R6)", r.returncode == 0,
              (r.stdout + r.stderr)[-150:])

        # --- v0.5 checks: compat / trust tiers / db / measure / index /
        # archive / registry / promote / hooks / mcp / dayreport / vault ---
        proj5 = os.path.join(tmp, "v05-proj")
        _st(proj5, "init", "--name", "v05")
        reg_ok = (os.path.exists(os.path.join(proj5, "harness.md"))
                  and os.path.exists(os.path.join(proj5, "tools",
                                                  "REGISTRY.md"))
                  and os.path.exists(os.path.join(proj5, "vault",
                                                  "README.md"))
                  and os.path.exists(os.path.join(proj5, "docs",
                                                  "measurement-schema.md"))
                  and os.path.isdir(os.path.join(proj5, "data", "db")))
        r5 = _st(proj5, "verify")
        check("25 v0.5 init seeds harness/REGISTRY/vault/schema/data and "
              "is green without a manual step (criterion 16)",
              reg_ok and r5.returncode == 0 and "state: " in r5.stdout,
              (r5.stdout + r5.stderr)[:200])
        tampered = os.path.join(proj5, "tools", "spine.py")
        direct_fail = False
        try:
            with open(tampered, "a") as fh:
                fh.write("# tamper\n")
        except OSError:
            direct_fail = True
        _st(proj5, "hooks", "unlock", "--reason", "selftest tamper test")
        with open(tampered, "a") as fh:
            fh.write("# tamper\n")
        r5 = _st(proj5, "verify")
        check("26 project spine.py copy is locked at init; tampering is "
              "caught by attestation (criterion 16)",
              direct_fail and r5.returncode == 1
              and "UNATTESTED: tools/spine.py" in r5.stdout,
              "direct-write-failed=%s exit %d" % (direct_fail,
                                                  r5.returncode))
        _st(proj5, "sign", "tools/spine.py", "--by", "selftest",
            "--reason", "restore")

        r = _st(proj, "claim", "emit", "--text", "measured latency 12ms",
                "--type", "factual", "--kind", "measured")
        mid = re.search(r"clm_[0-9a-f]+", r.stdout).group(0)
        _st(proj, "claim", "emit", "--text", "asserted hunch",
            "--type", "recommendation")
        r = _st(proj, "claim", "query", "--kind", "measured")
        r2 = _st(proj, "claim", "export", "--kinds", "measured,linked")
        exp = [json.loads(l) for l in r2.stdout.splitlines() if l.strip()]
        check("27 trust tiers: emit --kind measured; query --kind filters; "
              "export --kinds yields JSONL with trust field (criterion 5)",
              mid in r.stdout and "asserted hunch" not in r.stdout
              and r2.returncode == 0 and len(exp) == 1
              and exp[0]["claim_id"] == mid and exp[0]["trust"]
              == "measured",
              (r.stdout + r2.stdout + r2.stderr)[:200])

        def last_json(text):
            for ln in reversed(text.splitlines()):
                if ln.startswith("{"):
                    return json.loads(ln)
            return {}

        r = _st(proj, "db", "add", "--key", "rom.sha256", "--value",
                "ab12", "--trust", "measured", "--source", "shasum")
        rec1 = last_json(r.stdout).get("record_id", "")
        r = _st(proj, "db", "add", "--key", "patch.target", "--value",
                "head.bin", "--link", rec1)
        rec2 = last_json(r.stdout).get("record_id", "")
        r = _st(proj, "db", "link", rec2, "--to", rec1)
        r = _st(proj, "db", "supersede", rec2, "--value", "head2.bin")
        rec3 = last_json(r.stdout).get("new", "")
        r = _st(proj, "db", "get", rec1)
        got = last_json(r.stdout)
        r2 = _st(proj, "db", "list", "--status", "superseded")
        check("28 db clerk: add/get/link/supersede/list roundtrip on "
              "data/db/records.jsonl (criterion 6)",
              rec1 and rec3 and got.get("key") == "rom.sha256"
              and rec2 in r2.stdout,
              (r.stdout + r.stderr + r2.stdout)[:200])
        recp = os.path.join(proj, DB_RECORDS)
        before = open(recp, "rb").read()
        with unlocked(recp):
            with open(recp, "a") as fh:
                fh.write("{not json\n")
        r = _st(proj, "db", "list")
        still = open(recp, "rb").read() == before + b"{not json\n"
        with unlocked(recp):
            with open(recp, "wb") as fh:
                fh.write(before)
        check("29 malformed record line: db verb exits 2 naming line, "
              "file untouched (exit-2 contract)",
              r.returncode == 2 and "line" in r.stderr and still,
              "exit %d %s" % (r.returncode, r.stderr[:120]))

        with open(os.path.join(proj, "TODO.md"), "a",
                  encoding="utf-8") as fh:
            fh.write("unsigned drift poisons the gate\n")
        r = _st(proj, "db", "add", "--key", "doomed", "--value", "x")
        recp2 = os.path.join(proj, DB_RECORDS)
        voided = ("VOID" in r.stdout and r.returncode == 1
                  and any(json.loads(l).get("status") == "void"
                          and json.loads(l).get("record_id", "").startswith(
                              "rec_") and json.loads(l).get("key")
                          == "doomed"
                          for l in open(recp2, encoding="utf-8")
                          if l.strip()))
        rets = [e for e in read_events(proj)
                if e["event_type"] == "claim.retracted"
                and e.get("claim_ref", "").startswith("rec_")]
        check("29b gate failure after db write: record marked VOID with a "
              "retraction event, exit nonzero, append-only preserved "
              "(criterion 6)",
              voided and len(rets) >= 1,
              "exit %d voided=%s retracted=%d"
              % (r.returncode, voided, len(rets)))
        _st(proj, "sign", "TODO.md", "--by", "selftest", "--reason",
            "clear the planted drift")

        r = _st(proj, "todo", "add", "--what", "Measure patch latency",
                "--why", "numbers stale", "--kills", "audit green")
        tcid = re.search(r"clm_[0-9a-f]+", r.stdout).group(0)
        r = _st(proj, "measure", "append", "--command",
                "python3 -c \"print('12.5')\"", "--unit", "ms",
                "--source-claim", tcid)
        ok_ms = r.returncode == 0 and "msr_" in r.stdout
        r2 = _st(proj, "measure", "audit")
        r3 = _st(proj, "measure", "append", "--command",
                 "python3 -c \"print('12.5')\"", "--value", "99",
                 "--unit", "ms", "--source-claim", tcid)
        msz = os.path.getsize(os.path.join(proj, MEASURED))
        r3b = _st(proj, "measure", "append", "--command",
                  "python3 -c \"pass\"", "--unit", "ms",
                  "--source-claim", tcid)
        check("30 measure append records {value,unit,source_claim,"
              "command,observed}, audit re-runs green; claimed value "
              "mismatch refused exit 2; empty stdout refused exit 2 "
              "file untouched (criterion 9)",
              ok_ms and r2.returncode == 0 and "1/1 reproduced"
              in r2.stdout and r3.returncode == 2 and r3b.returncode == 2
              and os.path.getsize(os.path.join(proj, MEASURED)) == msz,
              (r.stdout + r2.stdout + r3.stderr + r3b.stderr)[:200])

        vnote = os.path.join(proj, "vault", "patch-latency.md")
        msha = sha_file(os.path.join(proj, MEASURED))
        mid_real = json.loads(open(os.path.join(proj, MEASURED),
                                   encoding="utf-8").read()
                              .splitlines()[-1])["m_id"]
        with open(vnote, "w", encoding="utf-8") as fh:
            fh.write("---\nname: patch latency\nsource: %s\nsource_sha: "
                     "%s\n---\nLatency is fact:%s per the measurement.\n"
                     % (MEASURED, msha, mid_real))
        r = _st(proj, "index", "build")
        r2 = _st(proj, "search", "ms latency", "--explain")
        has_meas = "[measured" in r2.stdout and "[asserted" in r2.stdout
        with open(vnote, "a", encoding="utf-8") as fh:
            fh.write("note drift\n")
        msha2 = sha_file(os.path.join(proj, MEASURED))
        if msha2 == msha:
            with unlocked(os.path.join(proj, MEASURED)):
                with open(os.path.join(proj, MEASURED), "a") as fh:
                    fh.write("")
        with open(os.path.join(proj, MEASURED), "a",
                  encoding="utf-8") as fh:
            fh.write("\n")
        _st(proj, "sign", MEASURED, "--by", "selftest", "--reason",
            "drift source for stale test")
        r3 = _st(proj, "search", "ms latency")
        r4 = _st(proj, "verify")
        check("31 index build + search rank measured over asserted with "
              "trust labels; moved source marks citing note STALE and "
              "verify WARNs without failing (criterion 12+22)",
              r.returncode == 0 and has_meas and "(score"
              in r2.stdout and "STALE" in r3.stdout
              and r4.returncode == 0 and "STALE derived view"
              in r4.stdout,
              "b%d m%d s%s v%d: %s" % (r.returncode, has_meas,
                                       r3.returncode, r4.returncode,
                                       (r3.stdout + r4.stdout)[:150]))
        r = _st(proj, "index", "build")
        r2 = _st(proj, "search", "ms latency", "--budget", "12")
        check("32 re-derive clears STALE; search --budget N caps results "
              "with token accounting (criterion 22)",
              r.returncode == 0 and "budget" in r2.stdout
              and "STALE" not in r2.stdout,
              (r.stdout + r2.stdout)[:200])

        tool = os.path.join(proj, "tools", "probe.sh")
        with open(tool, "w") as fh:
            fh.write("#!/bin/sh\necho probe\n")
        os.chmod(tool, 0o755)
        r = _st(proj, "verify")
        check("33 unregistered executable in tools/ WARNs, never fails "
              "(criterion 8)", r.returncode == 0 and "UNREGISTERED tool: "
              "tools/probe.sh" in r.stdout,
              "exit %d %s" % (r.returncode, r.stdout[-120:]))
        reg = os.path.join(proj, "tools", "REGISTRY.md")
        with open(reg, "a", encoding="utf-8") as fh:
            fh.write("| tools/probe.sh | duplicate | re-probes latency "
                     "baseline (dup of golden.sh) |\n")
        _st(proj, "sign", "tools/REGISTRY.md", "--by", "selftest",
            "--reason", "register duplicate tool")
        dnote = os.path.join(proj, "data", "notes")
        os.makedirs(dnote, exist_ok=True)
        with open(os.path.join(dnote, "cache-latency.md"), "w",
                  encoding="utf-8") as fh:
            fh.write("dup probe note: latency probe done in v0.4\n")
        r = _st(proj, "preflight", "latency probe", "--reason",
                "registry row")
        check("33b preflight finds the duplicate tool (via REGISTRY.md) "
              "AND the duplicate data note by name, PROCEED logged "
              "(criterion 7)",
              r.returncode == 0 and "tools/REGISTRY.md" in r.stdout
              and "data/notes/cache-latency.md" in r.stdout
              and "PROCEED" in r.stdout,
              (r.stdout)[-250:])

        close_id = re.search(r"clm_[0-9a-f]+", todo_md()).group(0)
        _st(proj, "close", "--supersedes", close_id, "--note", "dated tail")
        st_before = open(os.path.join(proj, "STATE.md"), encoding="utf-8"
                         ).read()
        r = _st(proj, "archive")
        st_after = open(os.path.join(proj, "STATE.md"), encoding="utf-8"
                        ).read() if os.path.exists(
                            os.path.join(proj, "STATE.md")) else ""
        log = open(os.path.join(proj, STATE_LOG), encoding="utf-8"
                   ).read() if os.path.exists(os.path.join(proj, STATE_LOG))\
            else ""
        moved = [l for l in st_before.splitlines()
                 if l.startswith("Closed ") and l not in st_after]
        exact = all(l in log.splitlines() for l in moved) and bool(moved)
        lines_after = st_after.rstrip().splitlines()
        nxt = st_after.find("Next command:")
        tail = st_after[nxt:] if nxt >= 0 else ""
        check("34 archive moves dated blocks byte-exact to docs/STATE-LOG"
              ".md, next-command stays last, gate green (criterion 4)",
              r.returncode == 0 and exact and "Closed" not in st_after
              and "Next command:" in st_after
              and "Closed" not in tail.split("Resume rule")[-1],
              "moved=%d exact=%s exit %d" % (len(moved), exact,
                                             r.returncode))

        long_lines = "\n".join("Closed 2026-11-%02dT00:00:00Z by filler: "
                               "supersedes x - padding line %d" % (i % 28 + 1,
                                                                  i)
                               for i in range(140))
        sfull = os.path.join(proj, "STATE.md")
        with open(sfull, "a", encoding="utf-8") as fh:
            fh.write("\n" + long_lines + "\n")
        _st(proj, "sign", "STATE.md", "--by", "selftest", "--reason",
            "flood state")
        r = _st(proj, "verify")
        warned = r.returncode == 0 and "WARN: STATE.md" in r.stdout \
            and "state: " in r.stdout
        dcp = os.path.join(proj, "DECISIONS.md")
        with open(dcp, "a", encoding="utf-8") as fh:
            fh.write("\nD99 | %s | state-cap: strict for this project"
                     " -> cap becomes a gate.\n" % time.strftime("%Y-%m-%d"))
        _st(proj, "sign", "DECISIONS.md", "--by", "selftest", "--reason",
            "opt in")
        r2 = _st(proj, "verify")
        check("35 STATE weight cap: >120 lines reports count + WARN; "
              "DECISIONS.md 'state-cap: strict' turns it into FAIL "
              "(criterion 4)",
              warned and r2.returncode == 1 and "FAIL: STATE.md"
              in r2.stdout,
              "warn=%s strict exit %d" % (warned, r2.returncode))
        _st(proj, "archive")

        r = _st(proj, "promote", tcid, "--to", "spine",
                env={"SPINE_HOME": tmp})
        inbox = os.path.join(tmp, "INBOX.md")
        r2 = _st(proj, "promote", "clm_PHANTOM", "--to", "spine",
                 env={"SPINE_HOME": tmp})
        check("36 promote writes the claim row to the spine INBOX.md; "
              "unresolved ref exits 2 (criterion 10)",
              r.returncode == 0 and os.path.exists(inbox)
              and tcid in open(inbox, encoding="utf-8").read()
              and r2.returncode == 2,
              "exit %d/%d" % (r.returncode, r2.returncode))

        d = "data/measurements.jsonl"
        owner_conf = os.path.join(proj, ".spine-owner")
        with open(owner_conf, "w", encoding="utf-8") as fh:
            fh.write("nobody\n")
        r = _st(proj, "verify")
        os.remove(owner_conf)
        check("37 privilege boundary: .spine-owner mismatch yields "
              "PERMISSION-DRIFT fail (criterion 18)",
              r.returncode == 1 and "PERMISSION-DRIFT" in r.stdout,
              "exit %d %s" % (r.returncode, r.stdout[-150:]))
        ro = os.path.join(proj, MEASURED)
        os.chmod(ro, 0o444)
        direct_eac = False
        try:
            with open(ro, "a") as fh:
                fh.write("x\n")
        except OSError:
            direct_eac = True
        os.chmod(ro, 0o644)
        check("38 read-only physics: direct write to a 0444 record file "
              "is refused (EACCES), verbs own the write path "
              "(criterion 18)", direct_eac, "direct write succeeded")

        git_proj = os.path.join(tmp, "git-proj")
        _st(git_proj, "init", "--name", "githook")
        subprocess.run(["git", "init", "-q", git_proj],
                       capture_output=True)
        r = _st(git_proj, "hooks", "install")
        st_p = os.path.join(git_proj, "STATE.md")
        led_p = os.path.join(git_proj, LEDGER)
        lock_state = is_locked(led_p) and is_locked(
            os.path.join(git_proj, "tools", "REGISTRY.md"))
        direct_blocked = False
        try:
            with open(led_p, "a") as fh:
                fh.write("x\n")
        except OSError:
            direct_blocked = True
        with open(st_p, "a", encoding="utf-8") as fh:
            fh.write("drift without signature\n")
        ra = subprocess.run(["git", "-C", git_proj, "-c", "user.name=t",
                             "-c", "user.email=t@x", "add", "-A"],
                            capture_output=True)
        rb = subprocess.run(["git", "-C", git_proj, "-c", "user.name=t",
                             "-c", "user.email=t@x", "commit", "-m",
                             "drift"], capture_output=True, text=True)
        rc = subprocess.run(["git", "-C", git_proj, "-c", "user.name=t",
                             "-c", "user.email=t@x", "commit", "-m",
                             "bypassed"], capture_output=True, text=True,
                            env=dict(os.environ,
                                     LEDGER_HOOK_BYPASS="selftest window"))
        hlog = os.path.join(git_proj, HOOKS_LOG)
        check("39 hooks install: uchg on ledger+registry, direct ledger "
              "write FAILS, commit blocked on drift, bypass commit lands "
              "and is logged with reason (criterion 13+15)",
              r.returncode == 0 and lock_state and direct_blocked
              and rb.returncode != 0 and rc.returncode == 0
              and os.path.exists(hlog) and "selftest window"
              in open(hlog, encoding="utf-8").read(),
              "lock=%s blocked=%s bypass=%d log=%s"
              % (lock_state, rb.returncode, rc.returncode,
                 os.path.exists(hlog)))
        r = _st(git_proj, "hooks", "status")
        r2 = _st(git_proj, "hooks", "unlock", "--reason", "selftest done")
        check("40 hooks status reports flag state; unlock --reason frees "
              "and logs (criterion 15)", r.returncode == 0
              and "LOCKED(uchg)" in r.stdout and r2.returncode == 0
              and not is_locked(led_p),
              (r.stdout + r2.stdout)[:180])

        lines_in = "\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "verify"}}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                        "params": {"name": "preflight", "arguments":
                                   {"query": "patch latency"}}})])
        r = _st(proj, "mcp", input=lines_in)
        docs = {}
        for ln in r.stdout.splitlines():
            try:
                d2 = json.loads(ln)
                if "id" in d2 and d2.get("id"):
                    docs[d2["id"]] = d2
            except ValueError:
                pass
        tools_list = (docs.get(2, {}).get("result") or {}).get("tools", [])
        vres = (docs.get(3, {}).get("result") or {})
        pres = (docs.get(4, {}).get("result") or {})
        check("41 mcp stdio roundtrip: initialize, tools/list (7 native "
              "tools), verify exit_code 0, preflight hit keeps exit_code "
              "2 semantics (criterion 14)",
              "serverInfo" in json.dumps(docs.get(1, {}))
              and {t["name"] for t in tools_list} >= {"verify", "preflight",
                                                      "db", "measure",
                                                      "loop", "search",
                                                      "dayreport"}
              and vres.get("exit_code") == 0 and pres.get("exit_code") == 2
              and pres.get("isError") is True,
              (r.stdout + r.stderr)[:250])

        port = 8371 + (os.getpid() % 400)
        url = "http://127.0.0.1:%d" % port
        srv = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "mcp",
             "--http", str(port), "--dir", proj],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            srv.stdout.readline()
            r = _st(proj, "db", "list", "--server", url)
            r4 = _st(proj, "preflight", "patch latency", "--server", url)
            r2 = _st(proj, "db", "get", "--server", "http://127.0.0.9:9",
                     rec1)
            spool = os.path.join(proj, DB_SPOOL)
            got_line = os.path.exists(spool) and "get" in open(
                spool, encoding="utf-8").read()
            r3 = _st(proj, "db", "list", "--server", url)
            replayed = os.path.exists(spool) and open(
                spool, encoding="utf-8").read().strip() == ""
            check("42 mcp --http + offline spool + cross-machine "
                  "preflight: remote db call lands, unreachable server "
                  "spools the call, next contact replays it, remote "
                  "preflight keeps exit-2 hit semantics (criterion 20)",
                  r.returncode == 0 and got_line and r3.returncode == 0
                  and "replayed" in r3.stdout and replayed
                  and r4.returncode == 2 and "prior-art hit" in r4.stdout,
                  "r%d/%d/%d/%d spool=%s r4=%s"
                  % (r.returncode, r2.returncode, r3.returncode,
                     r4.returncode, got_line, r4.stdout[:120]))
        finally:
            srv.terminate()

        r = _st(git_proj, "dayreport")
        check("43 dayreport: gate tally, bypass/unlock events with "
              "reasons, stale views, lock state from the day's "
              "transactions (criterion 17)",
              r.returncode == 0 and "GATES:" in r.stdout
              and "BYPASSES/UNLOCKS:" in r.stdout
              and "LOCKS:" in r.stdout and "selftest" in r.stdout,
              (r.stdout + r.stderr)[:200])

        _st(proj, "index", "build")
        with unlocked(os.path.join(proj, MEASURED)):
            with open(os.path.join(proj, MEASURED), "a",
                      encoding="utf-8") as fh:
                fh.write("\n")
        _st(proj, "sign", MEASURED, "--by", "selftest",
            "--reason", "plant stale source for dayreport")
        r = _st(proj, "dayreport")
        check("43b dayreport lists newly-stale derived views with the "
              "re-derive command (criteria 17+22)",
              r.returncode == 0 and "STALE:" in r.stdout
              and "index build" in r.stdout,
              (r.stdout + r.stderr)[-200:])
        _st(proj, "index", "build")

        vol = os.path.join(tmp, "FAKEVOL")
        os.makedirs(vol, exist_ok=True)
        r = _st(proj, "vault", "init", "--volume", vol)
        r2 = _st(proj, "vault", "mirror", "--volume", vol)
        vcopy = os.path.join(tmp, "FAKEVOL-copy")
        shutil.copytree(vol, vcopy)
        shutil.rmtree(os.path.join(vol, "spine-vault"))
        shutil.rmtree(os.path.join(proj, "vault"))
        r3 = _st(proj, "vault", "rehydrate", "--volume", vcopy)
        vs = vol_vault_dir(os.path.join(vcopy, "spine-vault"))
        same = os.path.exists(vs) and all(
            sha_file(os.path.join(proj, "vault", f))
            == sha_file(os.path.join(vs, f))
            for f in os.listdir(os.path.join(proj, "vault"))
            if os.path.isfile(os.path.join(proj, "vault", f)))
        bad_plist = (parse_diskutil_ownership(DISKUTIL_SAMPLE)
                     and parse_diskutil_ownership(
                         "   Owners:                    Disabled")
                     and not parse_diskutil_ownership(
                         "   Owners:                    Enabled")
                     and not parse_diskutil_ownership(
                         "no ownership line here"))
        good_plist = parse_diskutil_ownership(
            DISKUTIL_SAMPLE.replace("<true/>", "<false/>"))
        check("44 vault init/mirror/rehydrate: unplug + rehydrate is "
              "byte-identical; diskutil plist parser flags "
              "IGNORED-OWNERSHIP (criterion 19)",
              r.returncode == 0 and r2.returncode == 0
              and r3.returncode == 0 and same and bad_plist
              and not good_plist,
              "i%d m%d r%d same=%s plist=%s/%s"
              % (r.returncode, r2.returncode, r3.returncode, same,
                 bad_plist, good_plist))

        r = _st(proj, "verify")
        check("45 gate green after every v0.5 mutation (drift signed, "
              "locks sane)", r.returncode == 0,
              (r.stdout + r.stderr)[-250:])

        # --- criterion 2+3: the REAL v0.4.0 spine (embedded, deflated)
        # inits a skeleton that must verify clean under v0.5 unchanged,
        # and `adopt` upgrades it with byte-identity contracts.
        v04dir = os.path.join(tmp, "v04")
        os.makedirs(v04dir, exist_ok=True)
        v04py = os.path.join(v04dir, "spine.py")
        with open(v04py, "wb") as fh:
            fh.write(zlib.decompress(base64.b64decode(V04_SPINE_B64)))
        proj4 = os.path.join(v04dir, "oldproj")
        r = subprocess.run([sys.executable, v04py, "init", "--name",
                            "oldproj", "--dir", proj4],
                           capture_output=True, text=True)
        old_ledger = open(os.path.join(proj4, LEDGER), "rb").read()
        old_files = {}
        for dirpath, dirnames, files in os.walk(proj4):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for f in files:
                p = os.path.join(dirpath, f)
                old_files[os.path.relpath(p, proj4)] = sha_file(p)
        r_compat = _st(proj4, "verify")
        r_dry = _st(proj4, "adopt", "--dry-run")
        dry_ok = (r_dry.returncode == 0 and "replace tools/spine.py"
                  in r_dry.stdout and "harness.md" in r_dry.stdout
                  and open(os.path.join(proj4, LEDGER), "rb").read()
                  == old_ledger)
        r_ad = _st(proj4, "adopt", "--name", "oldproj")
        new_ledger = open(os.path.join(proj4, LEDGER), "rb").read()
        changed = sorted(rel for rel, h in old_files.items()
                         if rel != LEDGER
                         and (not os.path.exists(
                             os.path.join(proj4, rel))
                             or sha_file(os.path.join(proj4,
                                                      rel)) != h))
        rule_id = read_events(proj4)[0]["claim"]["claim_id"]
        r_end = _st(proj4, "verify")
        r_cl = _st(proj4, "claim", "verify", rule_id, "--result",
                   "supported", "--method", "human_review")
        check("46 backward compat: v0.4.0-init'd skeleton verifies clean "
              "under v0.5 (chain byte-unchanged); adopt --dry-run plans "
              "without writing; adopt leaves every pre-existing file "
              "byte-identical except tools/spine.py, STATE.md untouched, "
              "ledger append-only, old claim ids still resolve (criteria "
              "2+3)",
              r.returncode == 0 and r_compat.returncode == 0
              and dry_ok and r_ad.returncode == 0
              and new_ledger.startswith(old_ledger)
              and changed == ["tools/spine.py"]
              and os.path.exists(os.path.join(proj4, "harness.md"))
              and r_end.returncode == 0 and r_cl.returncode == 0,
              "init=%d compat=%d dry=%d ad=%d changed=%s verify=%d "
              "claim=%d %s" % (r.returncode, r_compat.returncode,
                               r_dry.returncode, r_ad.returncode,
                               changed[:4], r_end.returncode,
                               r_cl.returncode,
                               (r_end.stdout + r_end.stderr)[-120:]))

        hp = os.path.join(tmp, "harness-proj")
        os.makedirs(hp)
        rh1 = _st(hp, "init", "--name", "harnessed")
        subprocess.run(["git", "init", "-q", hp], capture_output=True)
        rh2 = _st(hp, "hooks", "install")
        rh3 = _st(hp, "verify")
        blocked = False
        try:
            with open(os.path.join(hp, "tools", "spine.py"), "a") as fh:
                fh.write("# hand tamper\n")
        except OSError:
            blocked = True
        rh4 = _st(hp, "verify")
        check("48 harness path: init + hooks install -> green verify with "
              "no manual step; hand tamper on spine.py copy caught "
              "(criterion 16)",
              rh1.returncode == 0 and rh2.returncode == 0
              and rh3.returncode == 0
              and (blocked or (rh4.returncode == 1 and "UNATTESTED: "
                               "tools/spine.py" in rh4.stdout)),
              "init=%d hooks=%d v=%d blocked=%s tamper=%d"
              % (rh1.returncode, rh2.returncode, rh3.returncode, blocked,
                 rh4.returncode))

        here = os.path.dirname(os.path.abspath(__file__))
        difftest = next((p for p in (
            os.path.join(here, "tools", "difftest.py"),   # repo root copy
            os.path.join(here, "difftest.py"),            # skeleton tools/
            os.path.join(os.path.dirname(here), "tools",
                         "difftest.py"))                   # tools/ layout
            if os.path.exists(p)), None)
        if difftest:
            r = subprocess.run([sys.executable, difftest, "--quiet"],
                               capture_output=True, text=True)
            check("47 keeper difftest: rust vs python full verb-surface parity "
                  "(criterion 21)", r.returncode == 0,
                  (r.stdout + r.stderr)[-250:])
        else:
            print("SKIP  47 keeper difftest (keeper ships with the spine "
                  "repo, not with skeletons)")

        keeper = next((p for p in (
            os.path.join(here, "keeper", "target", "release", "keeper"),
            os.path.join(here, "keeper", "target", "debug", "keeper"),
            os.path.join(os.path.dirname(here), "keeper", "target",
                         "release", "keeper"))
            if os.path.exists(p)), None)
        if keeper:
            droot = os.path.join(tmp, "daemon-proj")
            os.makedirs(droot, exist_ok=True)
            ri = subprocess.run([keeper, "init", "--name", "daemon-proj",
                                 "--dir", droot], capture_output=True,
                                text=True)
            dlog = os.path.join(droot, "vault", "daemon.jsonl")
            rd = subprocess.run(
                [keeper, "daemon", "--dir", droot, "--interval", "0",
                 "--iterations", "3", "--log", dlog],
                capture_output=True, text=True)
            lines = []
            try:
                lines = [json.loads(l) for l in
                         open(dlog, encoding="utf-8")]
            except OSError:
                pass
            ok_quiet = (rd.returncode == 0 and len(lines) == 3
                        and all(l["exit"] == 0 and l["drifts"] == 0
                                for l in lines))
            open(os.path.join(droot, "STATE.md"), "a",
                 encoding="utf-8").write("tamper\n")
            rt = subprocess.run(
                [keeper, "daemon", "--dir", droot, "--interval", "0",
                 "--iterations", "1", "--log", dlog],
                capture_output=True, text=True)
            drift = json.loads(open(dlog, encoding="utf-8")
                               .read().splitlines()[-1])
            check("49 keeper daemon: 3 green cycles logged, hand tamper "
                  "caught as drift (exit 3) (criterion 21)",
                  ok_quiet and rt.returncode == 3
                  and drift.get("drifts") == 1,
                  "init=%d quiet=%s rc=%d drift_rc=%d" % (
                      ri.returncode, ok_quiet, rd.returncode,
                      rt.returncode))
        else:
            print("SKIP  49 keeper daemon (binary not built)")

        if keeper:
            vroot = os.path.join(tmp, "vault-proj")
            os.makedirs(vroot, exist_ok=True)
            subprocess.run([keeper, "init", "--name", "vault-proj",
                            "--dir", vroot], capture_output=True,
                           text=True)
            vdest = os.path.join(tmp, "vol", "spine-vault")
            rv = subprocess.run(
                [keeper, "daemon", "--dir", vroot, "--interval", "0",
                 "--iterations", "1", "--mirror", vdest],
                capture_output=True, text=True)
            landed = (rv.returncode == 0
                      and os.path.isdir(os.path.join(vdest, "vault")))
            shutil.rmtree(os.path.join(tmp, "vol"), ignore_errors=True)
            os.chmod(tmp, 0o555)
            rvo = subprocess.run(
                [keeper, "daemon", "--dir", vroot, "--interval", "0",
                 "--iterations", "1",
                 "--mirror", os.path.join(tmp, "vol2", "spine-vault")],
                capture_output=True, text=True)
            os.chmod(tmp, 0o755)
            import json as _j
            derr = ("mirror_error" in (rvo.stdout or ""))
            check("50 keeper daemon --mirror: vault lands on volume, "
                  "absent volume logged as mirror_error (criterion 19)",
                  landed and derr,
                  "landed=%s err=%s" % (landed, derr))
        else:
            print("SKIP  50 keeper mirror (binary not built)")

        if keeper:
            proot = os.path.join(tmp, "resume-proj")
            os.makedirs(proot, exist_ok=True)
            subprocess.run([keeper, "init", "--name", "resume-proj",
                            "--dir", proot], capture_output=True,
                           text=True)
            rdest = os.path.join(tmp, "rvol", "spine-vault")
            rargs = [keeper, "daemon", "--dir", proot, "--interval",
                     "0", "--iterations", "1", "--mirror", rdest]

            def cyc(extra=None):
                a = list(rargs)
                if extra:
                    a[5:5] = extra
                return subprocess.run(a, capture_output=True, text=True)

            r1 = cyc()
            open(os.path.join(proot, "vault", "extra.txt"), "w",
                 encoding="utf-8").write("post-outage payload\n")
            leaf = os.path.join(rdest, "vault")
            os.chmod(leaf, 0o500)
            r2 = cyc()
            outage = ("mirror_error" in (r2.stdout or "")
                      and r2.returncode == 3)
            os.chmod(leaf, 0o755)
            r3 = cyc()
            same = all(
                sha_file(os.path.join(proot, "vault", f))
                == sha_file(os.path.join(rdest, "vault", f))
                for f in os.listdir(os.path.join(proot, "vault"))
                if os.path.isfile(os.path.join(proot, "vault", f)))
            check("51 daemon mirror resumes byte-identical after a "
                  "volume outage with identical hashes (criterion 19)",
                  r1.returncode == 0 and outage and r3.returncode == 0
                  and same and "extra.txt" in os.listdir(
                      os.path.join(rdest, "vault")),
                  "land=%d outage=%s resume=%d same=%s"
                  % (r1.returncode, outage, r3.returncode, same))
        else:
            print("SKIP  51 outage resume (binary not built)")

        bad = checks.count(False)
        print("SELFTEST: %s (%d/%d checks)" % ("PASS" if not bad else
                                               "FAIL", len(checks) - bad,
                                               len(checks)))
        sys.exit(0 if not bad else 1)
    finally:
        if args.keep:
            print("selftest: temp dir kept at %s" % tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------- conformance
# Fixtures from the fleet's vendored OpenClaims v0.1 conformance set,
# embedded verbatim (minified). Valid ones must reproduce reference digests
# with OUR canonicalizer; invalid ones must be rejected.
FIXTURES_VALID = [
    json.loads(r"""{"claim_ref":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","contradicting_evidence":[{"claim_ref":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","content_digest":{"algorithm":"sha256","encoding":"base64url","value":"U4J-eZojMJ4oF2VPmksmLNTBbxLlTTSLjpeWFBSKcXQ"},"evidence_id":"ev_contradiction_01","selector":{"end":260,"page":8,"start":200,"type":"page_span"},"source_ref":"src_kKpwK9CSqwxWQBeOYh3X7HNO15","support_type":"contradicts"}],"digest":{"algorithm":"sha256","encoding":"base64url","value":"4mk0724z5kMPM2xCsPwomk7X0UVTtuKvkpSotoNBOAo"},"dispute_rationale":"A newer policy revision states director approval is required.","event_id":"evt_QXnVXNWetJtVmyqQbO9FeNJ3I3","event_time":"2026-05-18T12:00:00Z","event_type":"claim.disputed","producer":{"agent_id":"urn:service:claim-verifier","agent_type":"service","name":"Claim Verifier"},"schema_url":"https://openclaims.org/schemas/openclaims/0.1/ClaimEvent.schema.json","spec_version":"0.1.0","verification":{"claim_status":"disputed","validator":{"agent_id":"urn:service:claim-verifier","agent_type":"service","name":"Claim Verifier"},"verification_id":"ver_02","verification_method":"source_attestation","verification_result":"contradicted","verified_at":"2026-05-18T12:00:00Z"}}"""),
    json.loads(r"""{"agents":[],"claim":{"asserted_at":"2026-05-17T19:30:00Z","claim_id":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","claim_type":"factual","context":{"output_id":"answer-001","tenant":"example-org"},"derived_from_claims":[],"relations":[],"text":"The internal travel policy requires manager approval for overnight trips."},"digest":{"algorithm":"sha256","encoding":"base64url","value":"EBJDl5B6wJUsVcZYdymtw7uklJ6LOB9W1FBV8N9XQUw"},"event_id":"evt_Sf-q0Zn3I4rIemSO-AQ8qvKjTO","event_time":"2026-05-17T19:30:01Z","event_type":"claim.emitted","evidence":[{"claim_ref":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","content_digest":{"algorithm":"sha256","encoding":"base64url","value":"vFSAf-fx8jwS-EB9d3R4l9imnsfFhTCoNv1jqohc1Yw"},"evidence_id":"ev_qe421sPb_tdAdKqrDBkOu6PIJc","selector":{"end":1310,"page":7,"start":1220,"type":"page_span"},"source_ref":"src_kKpwK9CSqwxWQBeOYh3X7HNO15","support_type":"supports_directly"}],"inferences":[],"producer":{"agent_id":"urn:service:assistant-api","agent_type":"service","name":"Assistant API"},"schema_url":"https://openclaims.org/schemas/openclaims/0.1/ClaimEvent.schema.json","sources":[{"digest":{"algorithm":"sha256","encoding":"base64url","value":"UIk_mVKHCXT_02AXyQd_c7WSqk22iKmsj4Tm0psxQhw"},"observed_at":"2026-05-17T19:29:41Z","source_id":"src_kKpwK9CSqwxWQBeOYh3X7HNO15","uri":"https://example.org/policies/travel.pdf","version":"sha256:8a4d"}],"spec_version":"0.1.0","tool_runs":[{"parameters_digest":{"algorithm":"sha256","encoding":"base64url","value":"QHQvjH_dBbRK0fPsDFfYAMj1aUHtws05Zkkpx0kXf-c"},"parameters_summary":{"k":5,"query_digest":{"algorithm":"sha256","encoding":"base64url","value":"GkFYn85jjRu57zRIie8HvY5kmm5_eHeSWSuL3eKmp14"}},"tool":{"model":"text-embedding-3-large","model_version":"2026-01","name":"policy-index-search","provider":"example","version":"0.1.0"},"tool_run_id":"run_pdf_retriever_784","tool_type":"retriever","trace_ref":"4bf92f3577b34da6a3ce929d0e0e4736/00f067aa0ba902b7"}]}"""),
    json.loads(r"""{"claim_ref":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","digest":{"algorithm":"sha256","encoding":"base64url","value":"TaKCbadZ3Agc-dpBFvBj_XyDPQjEsqlsUxKe8brU2rg"},"event_id":"evt_SnHtzCG1yOcD_O157OI8T7K8Nf","event_time":"2026-05-19T09:00:00Z","event_type":"claim.retracted","original_event_ref":"evt_Sf-q0Zn3I4rIemSO-AQ8qvKjTO","producer":{"agent_id":"urn:service:assistant-api","agent_type":"service","name":"Assistant API"},"retracted_at":"2026-05-19T09:00:00Z","retraction_reason":"The cited policy was superseded.","schema_url":"https://openclaims.org/schemas/openclaims/0.1/ClaimEvent.schema.json","spec_version":"0.1.0"}"""),
    json.loads(r"""{"agents":[],"claim_ref":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","digest":{"algorithm":"sha256","encoding":"base64url","value":"mhE3DhNLozplPysWuzwA_TgLglModCALL88mEQ9Acxs"},"event_id":"evt_bQiY0l1_4FDBgL8p0G5nDoNZEE","event_time":"2026-05-17T19:31:08Z","event_type":"claim.verified","evidence":[],"producer":{"agent_id":"urn:service:claim-verifier","agent_type":"service","name":"Claim Verifier"},"schema_url":"https://openclaims.org/schemas/openclaims/0.1/ClaimEvent.schema.json","spec_version":"0.1.0","verification":{"claim_status":"active","confidence":0.96,"validator":{"agent_id":"urn:service:claim-verifier","agent_type":"service","name":"Claim Verifier"},"verification_id":"ver_01","verification_method":"model_check","verification_result":"supported","verified_at":"2026-05-17T19:31:08Z"}}"""),
]
FIXTURES_INVALID = [
    ("claim-disputed-without-reason", json.loads(r"""{"claim_ref":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","digest":{"algorithm":"sha256","encoding":"base64url","value":"4mk0724z5kMPM2xCsPwomk7X0UVTtuKvkpSotoNBOAo"},"event_id":"evt_QXnVXNWetJtVmyqQbO9FeNJ3I3","event_time":"2026-05-18T12:00:00Z","event_type":"claim.disputed","producer":{"agent_id":"urn:service:claim-verifier","agent_type":"service","name":"Claim Verifier"},"schema_url":"https://openclaims.org/schemas/openclaims/0.1/ClaimEvent.schema.json","spec_version":"0.1.0","verification":{"claim_status":"disputed","validator":{"agent_id":"urn:service:claim-verifier","agent_type":"service","name":"Claim Verifier"},"verification_id":"ver_02","verification_method":"source_attestation","verification_result":"contradicted","verified_at":"2026-05-18T12:00:00Z"}}""")),
    ("claim-emitted-bad-support-type", json.loads(r"""{"agents":[],"claim":{"asserted_at":"2026-05-17T19:30:00Z","claim_id":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","claim_type":"factual","context":{"output_id":"answer-001","tenant":"example-org"},"derived_from_claims":[],"relations":[],"text":"The internal travel policy requires manager approval for overnight trips."},"digest":{"algorithm":"sha256","encoding":"base64url","value":"EBJDl5B6wJUsVcZYdymtw7uklJ6LOB9W1FBV8N9XQUw"},"event_id":"evt_Sf-q0Zn3I4rIemSO-AQ8qvKjTO","event_time":"2026-05-17T19:30:01Z","event_type":"claim.emitted","evidence":[{"claim_ref":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","content_digest":{"algorithm":"sha256","encoding":"base64url","value":"vFSAf-fx8jwS-EB9d3R4l9imnsfFhTCoNv1jqohc1Yw"},"evidence_id":"ev_qe421sPb_tdAdKqrDBkOu6PIJc","selector":{"end":1310,"page":7,"start":1220,"type":"page_span"},"source_ref":"src_kKpwK9CSqwxWQBeOYh3X7HNO15","support_type":"proves_absolutely"}],"inferences":[],"producer":{"agent_id":"urn:service:assistant-api","agent_type":"service","name":"Assistant API"},"schema_url":"https://openclaims.org/schemas/openclaims/0.1/ClaimEvent.schema.json","sources":[{"digest":{"algorithm":"sha256","encoding":"base64url","value":"UIk_mVKHCXT_02AXyQd_c7WSqk22iKmsj4Tm0psxQhw"},"observed_at":"2026-05-17T19:29:41Z","source_id":"src_kKpwK9CSqwxWQBeOYh3X7HNO15","uri":"https://example.org/policies/travel.pdf","version":"sha256:8a4d"}],"spec_version":"0.1.0","tool_runs":[{"parameters_digest":{"algorithm":"sha256","encoding":"base64url","value":"QHQvjH_dBbRK0fPsDFfYAMj1aUHtws05Zkkpx0kXf-c"},"parameters_summary":{"k":5,"query_digest":{"algorithm":"sha256","encoding":"base64url","value":"GkFYn85jjRu57zRIie8HvY5kmm5_eHeSWSuL3eKmp14"}},"tool":{"model":"text-embedding-3-large","model_version":"2026-01","name":"policy-index-search","provider":"example","version":"0.1.0"},"tool_run_id":"run_pdf_retriever_784","tool_type":"retriever","trace_ref":"4bf92f3577b34da6a3ce929d0e0e4736/00f067aa0ba902b7"}]}""")),
    ("claim-emitted-missing-claim", json.loads(r"""{"agents":[],"digest":{"algorithm":"sha256","encoding":"base64url","value":"EBJDl5B6wJUsVcZYdymtw7uklJ6LOB9W1FBV8N9XQUw"},"event_id":"evt_Sf-q0Zn3I4rIemSO-AQ8qvKjTO","event_time":"2026-05-17T19:30:01Z","event_type":"claim.emitted","evidence":[{"claim_ref":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","content_digest":{"algorithm":"sha256","encoding":"base64url","value":"vFSAf-fx8jwS-EB9d3R4l9imnsfFhTCoNv1jqohc1Yw"},"evidence_id":"ev_qe421sPb_tdAdKqrDBkOu6PIJc","selector":{"end":1310,"page":7,"start":1220,"type":"page_span"},"source_ref":"src_kKpwK9CSqwxWQBeOYh3X7HNO15","support_type":"supports_directly"}],"inferences":[],"producer":{"agent_id":"urn:service:assistant-api","agent_type":"service","name":"Assistant API"},"schema_url":"https://openclaims.org/schemas/openclaims/0.1/ClaimEvent.schema.json","sources":[{"digest":{"algorithm":"sha256","encoding":"base64url","value":"UIk_mVKHCXT_02AXyQd_c7WSqk22iKmsj4Tm0psxQhw"},"observed_at":"2026-05-17T19:29:41Z","source_id":"src_kKpwK9CSqwxWQBeOYh3X7HNO15","uri":"https://example.org/policies/travel.pdf","version":"sha256:8a4d"}],"spec_version":"0.1.0","tool_runs":[{"parameters_digest":{"algorithm":"sha256","encoding":"base64url","value":"QHQvjH_dBbRK0fPsDFfYAMj1aUHtws05Zkkpx0kXf-c"},"parameters_summary":{"k":5,"query_digest":{"algorithm":"sha256","encoding":"base64url","value":"GkFYn85jjRu57zRIie8HvY5kmm5_eHeSWSuL3eKmp14"}},"tool":{"model":"text-embedding-3-large","model_version":"2026-01","name":"policy-index-search","provider":"example","version":"0.1.0"},"tool_run_id":"run_pdf_retriever_784","tool_type":"retriever","trace_ref":"4bf92f3577b34da6a3ce929d0e0e4736/00f067aa0ba902b7"}]}""")),
    ("claim-retracted-without-retracted-at", json.loads(r"""{"claim_ref":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","digest":{"algorithm":"sha256","encoding":"base64url","value":"TaKCbadZ3Agc-dpBFvBj_XyDPQjEsqlsUxKe8brU2rg"},"event_id":"evt_SnHtzCG1yOcD_O157OI8T7K8Nf","event_time":"2026-05-19T09:00:00Z","event_type":"claim.retracted","original_event_ref":"evt_Sf-q0Zn3I4rIemSO-AQ8qvKjTO","producer":{"agent_id":"urn:service:assistant-api","agent_type":"service","name":"Assistant API"},"retraction_reason":"The cited policy was superseded.","schema_url":"https://openclaims.org/schemas/openclaims/0.1/ClaimEvent.schema.json","spec_version":"0.1.0"}""")),
    ("claim-verified-bad-digest", json.loads(r"""{"agents":[],"claim_ref":"clm_SCYcDu4K-Mw6o2Jg9IqNRa0rmn","digest":{"algorithm":"sha256","encoding":"base64url","value":"not-the-real-digest"},"event_id":"evt_bQiY0l1_4FDBgL8p0G5nDoNZEE","event_time":"2026-05-17T19:31:08Z","event_type":"claim.verified","evidence":[],"producer":{"agent_id":"urn:service:claim-verifier","agent_type":"service","name":"Claim Verifier"},"schema_url":"https://openclaims.org/schemas/openclaims/0.1/ClaimEvent.schema.json","spec_version":"0.1.0","verification":{"claim_status":"active","confidence":0.96,"validator":{"agent_id":"urn:service:claim-verifier","agent_type":"service","name":"Claim Verifier"},"verification_id":"ver_01","verification_method":"model_check","verification_result":"supported","verified_at":"2026-05-17T19:31:08Z"}}""")),
]


# v0.4.0 spine.py, compressed+embedded: the backward-compat
# selftest case re-inits a skeleton with the REAL old file, then
# `adopt`s it under v0.5 and proves byte-identity contracts.
V04_SPINE_B64 = (
    "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"
    "9s3a1Vb89jKcnj/9rfXul+Nk/vrifHYUJuH+y4PNEGdeLGDTsTbxjhwY07Nw4g+uKWZdOVbopIOO7sIIb5qBoHQnGAgYeZ/m"
    "mJOniTPUNVOwbHfv59+CX37b/9VLfkp+mV5/+rl/8HzH2//p0e4j3ZZLd1vkdWw9dtrPjttrnVYL/v8jbSOhlc2o3TDqcptJ"
    "pqSTIrrwB16H3nFk6qUI3jFzQVmyFTzm5E4WEbn4RTXH/TUqhFvjJJnFndVVlKrsSGuG0WiV28TG41XgEqvUWRdX0OQWzY/k"
    "As3VJLegbbOF+2jmD+t8zmXfsoyFG/m1/r6VF3KX4ZNeay03U51ZrCw8r1GewcxAfF6PmRqrHBdub4F3SV2lwNFoaQCjE6Ah"
    "dhMiXMw7mmmnT4/bzzuPFIKlt0OXYGHGbdDUg5he8fxssUnF3blBDJSECi+0SVCnxGl4V+50NvEcQBuiQVg4VtSjin6MOryK"
    "yJuwE4u/8gDW8RhNrsSLgFyxaPqFN0lJlagQ69kGLkYIaBLFEER0CNPNbYFRp3GT6f9LmE335U/bk8cvn1z+9C7+ZfDH78Pr"
    "aXL5dH4++enJ3sHL57+2d17+8mz/+W8/v7tkTpxhDEdnzqfWH8Gj3fVo15seHTibPz/7dPH64/FBJWPQ+9auYAzqGnDK9v9b"
    "Uupi52jzzDm7evbx8sjpvnw+fHS4PnnuT4P4bGd8vBXuX7Q/fgrHg/bvl6VS6pO3vtaO3/Z7yXBz+PpTtP3y/GD+5O3uT4My"
    "edV+1NYC66kWWO21tb9DYsmvcY9FweSa5JYfSCVGousSjFmbto478+/kTpuqtdh8u/u3sWVZoxSx5gvVlN3z3vSX16+2fjsG"
    "hrn52/XPw97g6a9Hn87X1vzX0/jj+vG0NYuvfh4TAmQKa+Ywfu15Z50w3iiXeveuUSVVDRfJdAgoxC58L15l9tGcDc+YAUth"
    "xEvsPHPXh7S1FbIKXVY99AYRtGZuBPuENbK/kHJ+fvXzxcdXveHL/uHr1tnbeHvn7PfNNx/b7rtXyWXcevzH+fnsqnX+25kz"
    "QMAZ48bz6dTF1CifrXOr87jBmVK+cDo/nu/8Hjx7/PHj4fzx0z8Pd33v2auL3x+fT6ePe94r7+jXo/neI+/1dNZeBwHFUMGx"
    "KFkovI9s22HLAAZxHjkTsKAQrTmbaApW3vN2ivDM1R3Ks+FwcA0rPMgrolSQZPaON+c23R3GFvwA29zDxIM+XpDuPX22rvZQ"
    "Upz+DZ/j9RfJH9b7Z8/Xzh49fvq0/2h96D5xHw2852vPhy2v5a0/ffRktdU6az156rqtvvu8tdZ/CkizSFLfixt/2eYdu6+3"
    "wKj949HmaOAMZy93Ll5+7P12vf3254/d+NMkfnf12nvWj96tsSjOS6jgVfLn1o/t64PBdg+I6unB7rPjp6+f7Z9VSqjnx63n"
    "C1XXNPMj0DzdK3InfAIoIXKnaPz7GWsmP2fl4orpOVk5GfjkRGOV5NKN03QlZB78x5TpeymL/xl0nI67j7bH+3vhn7PJ2+v4"
    "1/mfl5u949HeaPImHG5t7u09ezbt/vx8c3AVl6Bj/2f/99ak3Vvf2X452ns2a/34ONgO9//odu9QmNqd1rMKdNSZnjMa0+n/"
    "b3aVSmqcScXbaj5/8t+1s9qVdpaZirrKwDIi36usKxM/lHV1mjqRdvezbiSZbcdRZqgjQ0jSyJ7/JrO/p+/jm5/im5/i7/RT"
    "SNmjaEaapg6oI46kTBWK9M2X8c2X8c2X8V/xZdBZb9xz+3E4AYb1zZfxzZfxzZfxzZdR9GVUSPOpD5QMoFCByQtF+TcJ9U1C"
    "ffO2f5NQ3yTUNwn1t0so7cQ1nDTqCeXJ+uaX/3/UL/9/t8c9h4bKXUJ+D4k0jf9rHPJBmDjJ2EP/5UTN7pvj/Zvj/b/geCfP"
    "e5qeVoaXGonPzbS9CL+Yq0silHqY/RsL0lJ8Pj9SMaHyMd5+xghX+HpyepsrwJSNGjWS/kYRjiJ3QqXcN+vfYZpgaJQL4sXZ"
    "naRDnqr8qzxbHa7aoWoG8lJo8RZmpsCSzxehX6hqBjiqGcxcEkrMszAAdIoFjdp67Zw7NgcBeeTxtWBQ2A1jDmYcNsekpze1"
    "ZYog+foqw4mv5BchxQvJwuak0z5dCj4lu6RijFX+YLVHOI5MAH9OVRuTYidGqQBi8sP5dBbbn60QdER4rSH+9S9657ZBFaKC"
    "ZKOtKhhlwtFhBBWJ/uXB3nT94J98x4AoDOQDpaG28d6IpKn04g4+rEhwK5Pb5i5d6Fy32ds0TM0lucN5AKxsLevFdP5ybYta"
    "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"
    "uGv/B1s4Omw="
)


def cmd_conform(args, root=None):
    stats = {"valid_pass": 0, "invalid_rejected": 0, "failures": []}
    for ev in FIXTURES_VALID:
        errs = validate_event(ev)
        if errs:
            stats["failures"].append("valid rejected: %s: %s" % (
                ev.get("event_id"), "; ".join(errs)))
        else:
            stats["valid_pass"] += 1
    for name, ev in FIXTURES_INVALID:
        errs = validate_event(ev)
        if errs:
            stats["invalid_rejected"] += 1
            sys.stderr.write("rejected invalid/%s: %s\n" % (
                name, "; ".join(errs[:1])))
        else:
            stats["failures"].append("invalid accepted: %s" % name)
    ok = not stats["failures"]
    print(json.dumps({"ok": ok, **stats}, indent=1))
    sys.exit(0 if ok else 1)


# ------------------------------------------------------------- gate & files
def sha_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def attest_claim(root, path, by, reason):
    ev = base_event("claim.emitted")
    ev["claim"] = {
        "claim_id": new_id("clm"),
        "text": "attest %s sha256=%s by %s : %s" % (path, sha_file(
            os.path.join(root, path)), by, reason),
        "claim_type": "factual",
        "asserted_at": now(),
        "context": {"spine": {"kind": "attest", "path": path,
                              "sha256": sha_file(os.path.join(root, path)),
                              "by": by, "reason": reason}}}
    return append_event(root, ev)


def rule_claim(root, rid, text, src, asof):
    ev = base_event("claim.emitted")
    ev["claim"] = {"claim_id": new_id("clm"), "text": text,
                   "claim_type": "factual", "asserted_at": now(),
                   "context": {"spine": {"kind": "rule", "id": rid,
                                         "true_asof": asof}}}
    ev["sources"] = [{"source_id": new_id("src"), "uri": src,
                      "observed_at": now()}]
    ev["evidence"] = [{"evidence_id": new_id("ev"),
                       "source_ref": ev["sources"][0]["source_id"],
                       "claim_ref": ev["claim"]["claim_id"],
                       "selector": {"type": "uri_fragment",
                                    "fragment": rid},
                       "support_type": "context_only",
                       "observed_at": now()}]
    return append_event(root, ev)


TPL = {}
TPL["AGENTS.md"] = """# %NAME% - agent start-here

Purpose: see STATE.md first block. Skeleton by ai-project-spine %VER% %DATE%.

Boot ritual (every session, in order):
0. Step zero: read harness.md; preflight "your task" before funding work.
1. Read STATE.md - it is the state and ends with the literal next command.
2. Run: python3 tools/spine.py verify   (must exit 0 before any work)
3. TODO.md entries are stale hypotheses until re-justified against gates
   and DECISIONS.md. Deleting one is a valid first act.

Rules live where they already live - never restate them here:
- decisions/contracts: DECISIONS.md    - open risks: BUGS.md
- intentions + decay mechanics: TODO.md header
- lessons: LESSONS/
- claims (cited, dated, chained): python3 tools/spine.py claim query

Editing prose is legal; then sign:
  python3 tools/spine.py sign --by WHO --reason "why"
This file stays short. If a line duplicates another file, delete it here.
"""
TPL["STATE.md"] = """# State

Project: %NAME%. Created %DATE% by ai-project-spine %VER%.
Purpose: one paragraph, written by a human, here.

- Phase: 0 - skeleton only. No feature work started.
- Open risks: none recorded yet (see BUGS.md).

Next command:
    python3 tools/spine.py verify
    - then a human writes the Purpose paragraph above and signs STATE.md.

Resume rule: this file ends with the literal next command. Any session
(quota death, power cut, new agent) restarts from this file alone.
"""
TPL["TODO.md"] = """# TODO - disposable intentions

One line per item, max %TODO_MAX%.
`- [ ] what | why | kills-it-if | conf 0.0-1.0 | last-touch YYYY-MM-DD`

Rules (rule claims R1-R7 are in the ledger: claim query):
- Items are hypotheses, not orders. First act of a session: delete what
  no longer earns its place.
- Conf decays x0.9 per untouched loop; >=0.7 execute; 0.4-0.7 re-probe
  first (cheapest relevant gate); <0.4 needs a human ruling.
- The loop that wrote an item cannot raise its conf above 0.6 alone;
  crossing 0.6 needs human or pipeline evidence (claim verify).

(empty - a human or the first justified session fills this)
"""
TPL["DECISIONS.md"] = """# Decisions - append-only

ID | date | context -> decision | why | evidence
Supersede by appending; never edit a past entry.
Skeleton rule rationale (R1-R7, cited + dated) lives in the ledger:
  python3 tools/spine.py claim query
Project decisions start at D01.

---

D00 | %DATE% | Skeleton generated by ai-project-spine %VER%.
-> Rules R1-R7 bind this project until a numbered D-entry supersedes one
with counter-evidence. Evidence: their rule claims carry sources + dates.
"""
TPL["BUGS.md"] = """# Bugs & known risks - append-only

Scopes: [invariant] = agent/process flaw recurring across projects;
[domain] = project-specific. Closing a bug needs a verification record
naming the validator (python3 tools/spine.py claim verify REF --result
supported --method human_review|model_check|source_attestation|consensus|
formal_proof ...). Statuses: open|probing|resolved|disputed|retracted|
inconclusive. Gates are added only where a failure demanded one.

Discipline (v0.4): an entry that DISCARDS or DOWNGRADES a measured result
must carry a `retest:` field naming what gets re-measured and from which
artifacts - "the tool was broken" without a re-test obligation is a data
loss, not a verdict. verify enforces this mechanically.

---
(no entries yet)
"""
TPL["CLAIMS.md"] = """# Claims - human index

Machine truth: claims/claims.jsonl (OpenClaims v0.1 events, append-only,
digest-chained, spec-conformant: python3 tools/spine.py claim conform).
Read: python3 tools/spine.py claim query
This file only indexes; it never contradicts the JSONL.

| id | claim (short) | status | verified by |
|----|---------------|--------|-------------|
| (ledger-managed; rows added here when humans care) |
"""
TPL["LESSONS/README.md"] = """# Lessons

A lesson needs claim_ref + evidence or it does not get written
(add-nothing rule). Lessons are what future generations read; git already
stores what happened. One file per lesson: YYYY-MM-DD-slug.md.
"""
TPL["tests/run.sh"] = """#!/bin/bash
# Project gates. Add a gate only when a failure demands one (BUGS.md).
set -u
cd "$(dirname "$0")/.."
ok=1
python3 tools/spine.py verify || ok=0
python3 tools/spine.py claim conform || ok=0
python3 tools/spine.py selftest || ok=0
[ "$ok" = 1 ] && { echo "ALL GATES PASS"; exit 0; }
echo "GATES FAILED"; exit 1
"""
TPL[".gitignore"] = ".DS_Store\n__pycache__/\n.tmp/\n"
TPL["harness.md"] = """# Harness contract - %NAME% (spine %VER%)

Step zero, every session, before any task:
    python3 tools/spine.py verify        # must exit 0
    python3 tools/spine.py preflight "what you are about to do"

Deny-paths (direct edits here are FORBIDDEN - use the verb that owns them):
- claims/claims.jsonl  -> claim emit|verify|dispute|retract, sign, close,
  todo, loop, preflight (audits), db (receipts), hooks (accountability)
- data/db/records.jsonl -> db add|link|supersede (append-only snapshots)
- data/measurements.jsonl -> measure append (audit re-runs, never writes)
- data/kindex.jsonl + data/derived.json -> index build (derived, never hand)
- tools/REGISTRY.md -> register a tool in the same commit that adds it
After any legal hand edit of an attested file: sign --by WHO --reason WHY.

Machine surfaces: `mcp` (stdio) and `mcp --http PORT` expose
verify/preflight/db/measure/loop/search/dayreport as native tools; unattended
runs are accountable via `dayreport` and hooks-bypass.log (rule R6/R7).
"""
TPL["tools/REGISTRY.md"] = """# Tool registry - %NAME%

Every executable under tools/ gets a row the day it lands (verify warns
about unregistered executables; the ledger knows, so stay registered):

| path | status | purpose |
|------|--------|---------|
| tools/spine.py | canonical | the spine gate itself (%VER%) |
"""
TPL["docs/measurement-schema.md"] = """# Measurement schema (v0.5)

One JSON object per line in data/measurements.jsonl, append-only:

{"m_id","ts","command","value","unit","observed","source_claim","by"}

- value MUST equal the command's stdout (minus trailing newline) at
  append time - `measure append` runs the command and refuses a mismatch.
- source_claim must resolve to an issued claim id (exact or unique prefix).
- `measure audit` re-runs every command: OK / DRIFT lines, exit 1 on drift.
- The point (from silicon-ledger): a number without the command, unit and
  observed text that produced it is decoration, not measurement.
"""
TPL["vault/README.md"] = """# Vault - notes with receipts

One markdown note per fact-cluster. Front-matter fields the index uses:
    name: short handle            source: repo-relative path (optional)
    source_sha: sha256 of source  (optional; verify flags STALE on drift)
Cite measured numbers as fact:<m_id> (from data/measurements.jsonl); an
uncited number in a note is asserted, not measured (rule R6).
`index build` folds vault notes + measurements + db records into
data/kindex.jsonl; `search` ranks measured > linked > asserted.
"""

# v0.4 opt-in (init --with-golden): the capture-before-structural-change
# ritual, generalized from a live campaign's golden_capture.sh.
TPL["tools/golden.sh"] = """#!/bin/bash
# Golden capture ritual (opt-in): capture known-good command outputs BEFORE
# a structural change, diff them AFTER. Commands live in tools/golden.conf,
# one per line: `name|command`. This script never runs anything on its own.
set -u
cd "$(dirname "$0")/.."
CONF=tools/golden.conf
[ -f "$CONF" ] || { echo "golden: no $CONF - add lines 'name|command'"; exit 2; }
case "${1:-check}" in
  capture)
    mkdir -p golden
    while IFS='|' read -r n c; do
      case "$n" in ''|\\#*) continue;; esac
      eval "$c" > "golden/$n.out" 2> "golden/$n.err"
      echo "captured $n"
    done < "$CONF" ;;
  check)
    fail=0
    while IFS='|' read -r n c; do
      case "$n" in ''|\\#*) continue;; esac
      [ -f "golden/$n.out" ] || { echo "MISSING golden/$n.out - run capture"; fail=1; continue; }
      tmp=$(mktemp)
      eval "$c" > "$tmp" 2>&1 || true
      if diff -q "golden/$n.out" "$tmp" > /dev/null; then
        echo "OK $n"
      else
        echo "DRIFT $n"; fail=1
      fi
      rm -f "$tmp"
    done < "$CONF"
    exit $fail ;;
  *) echo "usage: golden.sh capture|check"; exit 2 ;;
esac
"""
TPL["tools/golden.conf"] = """# one line per golden: name|command (command's stdout is what gets diffed)
selfcheck|python3 -c "print('spine golden ritual alive')"
"""
DECISIONS_GOLDEN_SEED = """
D00g | %DATE% | Structural changes require a golden capture first (opt-in
ritual adopted at init --with-golden).
-> `tools/golden.sh capture` before, `check` after; drift blocks the commit.
Evidence: generalizes golden-capture practice proven in a live campaign
(ai-project-spine v0.4, 2026-10-24).
"""

FILES = ["AGENTS.md", "STATE.md", "TODO.md", "DECISIONS.md", "BUGS.md",
         "CLAIMS.md", "LESSONS/README.md", "tests/run.sh", ".gitignore"]


def today():
    pin = os.environ.get("SPINE_TEST_NOW")
    return pin[:10] if pin else time.strftime("%Y-%m-%d")


def render(t, name):
    return (t.replace("%NAME%", name).replace("%VER%", VERSION)
            .replace("%DATE%", today())
            .replace("%TODO_MAX%", str(PARAMS["todo_max_items"])))


def cmd_init(args):
    root = args.dir
    if os.path.exists(os.path.join(root, LEDGER)) and not args.force:
        sys.exit("spine: ledger exists in %s (use --force)" % root)
    for rel in FILES:
        dest = os.path.join(root, rel)
        if os.path.exists(dest) and not args.force:
            sys.exit("spine: refuses to overwrite %s (use --force)" % rel)
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(render(TPL[rel], args.name))
    os.chmod(os.path.join(root, "tests", "run.sh"), 0o755)
    os.makedirs(os.path.join(root, "tools"), exist_ok=True)
    with unlocked(os.path.join(root, "tools", "spine.py")):
        shutil.copy2(os.path.abspath(__file__),
                     os.path.join(root, "tools", "spine.py"))
    added = seed_new_files(root, args.name, force=args.force)
    extra = []
    if getattr(args, "with_golden", False):
        for rel in ("tools/golden.sh", "tools/golden.conf"):
            dest = os.path.join(root, rel)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(render(TPL[rel], args.name))
        os.chmod(os.path.join(root, "tools", "golden.sh"), 0o755)
        with open(os.path.join(root, "DECISIONS.md"), "a",
                  encoding="utf-8") as fh:
            fh.write(render(DECISIONS_GOLDEN_SEED, args.name))
        extra = ["tools/golden.sh", "tools/golden.conf"]
    os.environ.setdefault("SPINE_PRODUCER_NAME", "ai-project-spine " + VERSION)
    for rid, text, src, asof in RULES:
        rule_claim(root, rid, text, src, asof)
    for rel in FILES + ["tools/spine.py"] + extra + added:
        attest_claim(root, rel, "spine " + VERSION, "init")
    set_lock(os.path.join(root, "tools", "spine.py"), True)
    txlog(root, "init", 0, args.name)
    print("spine: skeleton ready in %s (%d rules + %d attestations)"
          % (root, len(RULES), len(FILES) + 1 + len(extra) + len(added)))
    print("spine: next -> python3 tools/spine.py verify ; then read AGENTS.md")


def run_verify(root):
    """Gate logic as a callable (the mcp/db path re-runs it after writes).
    Returns (fails, warns, lines, counts)."""
    lines, fails, warns = [], [], []
    events = read_events(root)
    if not events:
        sys.exit("verify: no ledger at %s - run init first" % root)
    ok, msg = chain_check(events)
    if not ok:
        fails.append("CHAIN: " + msg)
    att = {}
    for ev in events:
        sp = ((ev.get("claim") or {}).get("context") or {}).get("spine") or {}
        if sp.get("kind") == "attest":
            att[sp["path"]] = sp["sha256"]
    for rel, h in sorted(att.items()):
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            fails.append("MISSING attested file: %s" % rel)
        elif sha_file(p) != h:
            fails.append("UNATTESTED: %s modified outside the gate" % rel)
    for rel in FILES:
        if rel not in att:
            fails.append("UNTRACKED spine file: %s (never attested)" % rel)
    ag = os.path.join(root, "AGENTS.md")
    if os.path.exists(ag):
        n = len(open(ag, encoding="utf-8").read().splitlines())
        if n > PARAMS["agents_md_max_lines"]:
            fails.append("AGENTS.md %d lines > cap %d (rule R2/R3)"
                         % (n, PARAMS["agents_md_max_lines"]))
    st = os.path.join(root, "STATE.md")
    if os.path.exists(st):
        body = open(st, encoding="utf-8").read()
        n = len(body.splitlines())
        cap = PARAMS["state_md_max_lines"]
        strict = False
        dp = os.path.join(root, "DECISIONS.md")
        if os.path.exists(dp) and re.search(r"state-cap[: ]+strict",
                                            open(dp, encoding="utf-8")
                                            .read()):
            strict = True
        note = " (strict: opted in via DECISIONS.md state-cap: strict)" \
            if strict else " (opt in: add 'state-cap: strict' to " \
                           "DECISIONS.md to make this a FAIL)"
        lines.append("state: %d lines (cap %d)%s" % (n, cap, note))
        if n > cap:
            over = "STATE.md %d lines > cap %d - `spine.py archive` moves " \
                  "dated blocks to %s" % (n, cap, STATE_LOG)
            (fails if strict else warns).append(over)
        if "Next command:" not in body:
            fails.append("STATE.md lost its literal next-command "
                         "(resume rule)")
    issued = set(issued_claim_ids(root))
    verdicts = [ev for ev in events if ev["event_type"] != "claim.emitted"]
    phantoms = sorted({ev["claim_ref"] for ev in verdicts
                       if ev.get("claim_ref") not in issued})
    if phantoms:
        fails.append("PHANTOM refs: %d verdict(s) point at unissued claim "
                     "ids: %s" % (len(phantoms), ", ".join(
                         phantoms[:5])))
    # derived-view freshness (v0.5, criterion 12): WARNING, never fails.
    stale, derived = derived_stale(root)
    for rel in stale:
        warns.append("STALE derived view: %s sources moved - re-derive: %s"
                     % (derived.get("view", KINDEX),
                        derived.get("command", "index build")))
    # privilege boundary (v0.5, criterion 18): expected owner is planted
    # in .spine-owner; drift is a PERMISSION-DRIFT fail.
    owner = expect_owner(root)
    if owner:
        try:
            import pwd
            want_uid = pwd.getpwnam(owner).pw_uid
        except KeyError:
            want_uid = -2
        for rel in (DB_RECORDS, MEASURED):
            p = os.path.join(root, rel)
            if os.path.exists(p) and os.stat(p).st_uid != want_uid:
                fails.append("PERMISSION-DRIFT: %s owned by %s, expected "
                             "%s (privilege boundary broken)"
                             % (rel, pwd.getpwuid(os.stat(p).st_uid).pw_name,
                                owner))
    # tool registry (v0.5, criterion 8): unregistered executables WARN.
    rp = os.path.join(root, "tools", "REGISTRY.md")
    tdir = os.path.join(root, "tools")
    if os.path.isdir(tdir):
        reg = open(rp, encoding="utf-8").read() if os.path.exists(rp) else ""
        for f in sorted(os.listdir(tdir)):
            p = os.path.join(tdir, f)
            if os.path.isfile(p) and os.access(p, os.X_OK) \
                    and f != "spine.py" and ("tools/" + f) not in reg:
                warns.append("UNREGISTERED tool: tools/%s lacks a row in "
                             "tools/REGISTRY.md (rule R7 housekeeping)" % f)
    # orphan coverage (v0.4, generalizes AI_dev master_index): claims that
    # nothing references. Informational - flagged, never blocks (R6).
    todo_text = ""
    tp = os.path.join(root, "TODO.md")
    if os.path.exists(tp):
        todo_text = open(tp, encoding="utf-8").read()
    orphans = []
    for cid in sorted(issued):
        referenced = cid in todo_text
        for ev in events:
            if referenced:
                break
            rest = {k: v for k, v in ev.items() if k != "digest"}
            blob = json.dumps(rest)
            if cid in blob and (ev.get("claim") or {}).get("claim_id") != cid:
                referenced = True
        if not referenced:
            orphans.append(cid)
    if orphans:
        lines.append("ORPHAN-COVERAGE: %d/%d issued claims referenced by "
                     "nothing: %s" % (len(orphans), len(issued),
                                      ", ".join(orphans[:5]) +
                                      (" ..." if len(orphans) > 5 else "")))
    # BUGS.md discipline (v0.4): a discarded/downgraded result without a
    # retest: field is not allowed - discards must carry their re-measure.
    bp = os.path.join(root, "BUGS.md")
    if os.path.exists(bp):
        body = open(bp, encoding="utf-8").read().split("---", 1)[-1]
        for entry in re.split(r"\n(?=\[|B\d|BUG-)", body):
            low = entry.lower()
            if re.search(r"discard|downgrade|superseded-result", low) \
                    and "retest:" not in low:
                fails.append("BUGS.md entry discards a result without a "
                             "retest: field: \"%s\"" % entry.strip()[:60])
    return fails, warns, lines, {
        "events": len(events), "attested": len(att), "chain": msg,
        "issued": len(issued), "verdicts": len(verdicts),
        "phantoms": len(phantoms)}


def cmd_verify(args):
    root = args.dir
    fails, warns, lines, c = run_verify(root)
    for ln in lines:
        print(ln)
    for w in warns:
        print("WARN:", w)
    for f in fails:
        print("FAIL:", f)
    if fails:
        print("VERIFY: FAIL (%d)" % len(fails))
        txlog(root, "verify", 1, "fails=%d" % len(fails))
        sys.exit(1)
    print("VERIFY: PASS (%d events, %d files attested, %s)"
          % (c["events"], c["attested"], c["chain"]))
    print("claims: %d issued | %d verdicts | %d phantom refs"
          % (c["issued"], c["verdicts"], c["phantoms"]))
    txlog(root, "verify", 0, "pass")


def cmd_sign(args):
    root = args.dir
    files = args.files
    if not files:
        att = {}
        for ev in read_events(root):
            sp = ((ev.get("claim") or {}).get("context") or {}).get("spine") \
                or {}
            if sp.get("kind") == "attest":
                att[sp["path"]] = sp["sha256"]
        files = [rel for rel, h in sorted(att.items())
                 if os.path.exists(os.path.join(root, rel))
                 and sha_file(os.path.join(root, rel)) != h]
    if not files:
        print("sign: nothing drifted")
        return
    for rel in files:
        attest_claim(root, rel, args.by, args.reason)
        print("signed:", rel)


def main():
    ap = argparse.ArgumentParser(
        prog="spine.py", description=__doc__.splitlines()[0],
        epilog="exit codes: 0 ok | 1 gate failed (verify/conform/selftest) "
               "| 2 usage or validation refused (bad ref, cap, overwrite, "
               "model_check over 0.6)")
    sub = ap.add_subparsers(dest="cmd")

    pi = sub.add_parser("init")
    pi.add_argument("--name", required=True)
    pi.add_argument("--dir", default=".")
    pi.add_argument("--force", action="store_true")
    pi.add_argument("--with-golden", action="store_true",
                    help="opt-in: also drop tools/golden.sh + conf + "
                         "DECISIONS seed (capture-before-change ritual)")

    pv = sub.add_parser("verify")
    pv.add_argument("--dir", default=".")

    ps = sub.add_parser("sign")
    ps.add_argument("files", nargs="*")
    ps.add_argument("--by", required=True)
    ps.add_argument("--reason", required=True)
    ps.add_argument("--dir", default=".")

    pc = sub.add_parser("claim")
    csub = pc.add_subparsers(dest="verb")
    ce = csub.add_parser("emit")
    ce.add_argument("--text", required=True)
    ce.add_argument("--type", required=True, choices=sorted(CLAIM_TYPES))
    ce.add_argument("--claim-id")
    ce.add_argument("--source-uri")
    ce.add_argument("--selector")
    ce.add_argument("--support", default="supports_directly")
    ce.add_argument("--context")
    ce.add_argument("--kind", choices=sorted(TRUST_KINDS),
                    help="trust tier (default asserted): measured = a "
                         "command reproduced it, linked = cited source, "
                         "asserted = said so")
    ce.add_argument("--dir", default=".")
    for kind in ("verify", "dispute", "retract"):
        cv = csub.add_parser(kind)
        cv.add_argument("claim_ref")
        cv.add_argument("--dir", default=".")
        if kind == "verify":
            cv.add_argument("--result", required=True,
                            choices=sorted(VERIFICATION_RESULTS))
            cv.add_argument("--method", required=True,
                            choices=sorted(VERIFICATION_METHODS))
            cv.add_argument("--status", default="active")
            cv.add_argument("--confidence", type=float, default=0.95)
            cv.add_argument("--by")
            cv.add_argument("--by-type", default="human",
                            choices=sorted(AGENT_TYPES))
        else:
            cv.add_argument("--reason", required=True)
    cq = csub.add_parser("query")
    cq.add_argument("--kind", choices=sorted(TRUST_KINDS))
    cq.add_argument("--dir", default=".")
    cx = csub.add_parser("export")
    cx.add_argument("--kinds", default="measured,linked")
    cx.add_argument("--dir", default=".")
    cc = csub.add_parser("chain")
    cc.add_argument("--dir", default=".")
    cf = csub.add_parser("conform")

    pt = sub.add_parser("todo")
    tsub = pt.add_subparsers(dest="action")
    ta = tsub.add_parser("add")
    ta.add_argument("--what", required=True)
    ta.add_argument("--why", required=True)
    ta.add_argument("--kills", required=True)
    ta.add_argument("--conf", type=float, default=0.55)
    ta.add_argument("--dir", default=".")
    td = tsub.add_parser("done")
    td.add_argument("claim_ref")
    td.add_argument("--by", required=True)
    td.add_argument("--dir", default=".")
    tx = tsub.add_parser("drop")
    tx.add_argument("claim_ref")
    tx.add_argument("--reason", required=True)
    tx.add_argument("--dir", default=".")

    plo = sub.add_parser("loop")
    plo.add_argument("--close", action="store_true", required=True)
    plo.add_argument("--touch", nargs="*", default=[])
    plo.add_argument("--touch-conf", type=float, default=0.6)
    plo.add_argument("--method", default="model_check",
                     choices=sorted(VERIFICATION_METHODS))
    plo.add_argument("--dir", default=".")

    psl = sub.add_parser("selftest")
    psl.add_argument("--keep", action="store_true")
    psl.add_argument("--dir", default=".")

    pf = sub.add_parser("preflight")
    pf.add_argument("query")
    pf.add_argument("--reason")
    pf.add_argument("--artifacts", nargs="*", default=[])
    pf.add_argument("--server", help="query another spine mcp --http "
                                    "host instead of (or before) local")
    pf.add_argument("--dir", default=".")

    pcl = sub.add_parser("close")
    pcl.add_argument("--supersedes", default="")
    pcl.add_argument("--note")
    pcl.add_argument("--dir", default=".")

    pses = sub.add_parser("sessions")
    ssub = pses.add_subparsers(dest="action")
    si = ssub.add_parser("ingest")
    si.add_argument("files", nargs="+")
    si.add_argument("--into", default="sessions")
    si.add_argument("--dir", default=".")

    pdbc = sub.add_parser("db")
    dsub = pdbc.add_subparsers(dest="action")
    da = dsub.add_parser("add")
    da.add_argument("--key", required=True)
    da.add_argument("--value", required=True)
    da.add_argument("--trust", choices=sorted(TRUST_KINDS))
    da.add_argument("--source", default="")
    da.add_argument("--link", default="")
    da.add_argument("--server")
    da.add_argument("--dir", default=".")
    dg = dsub.add_parser("get")
    dg.add_argument("ref")
    dg.add_argument("--server")
    dg.add_argument("--dir", default=".")
    dl = dsub.add_parser("link")
    dl.add_argument("ref")
    dl.add_argument("--to", required=True)
    dl.add_argument("--server")
    dl.add_argument("--dir", default=".")
    dsu = dsub.add_parser("supersede")
    dsu.add_argument("ref")
    dsu.add_argument("--value", required=True)
    dsu.add_argument("--trust", choices=sorted(TRUST_KINDS))
    dsu.add_argument("--source", default="")
    dsu.add_argument("--server")
    dsu.add_argument("--dir", default=".")
    dli = dsub.add_parser("list")
    dli.add_argument("--key")
    dli.add_argument("--status", choices=sorted(DB_STATUSES))
    dli.add_argument("--server")
    dli.add_argument("--dir", default=".")

    pme = sub.add_parser("measure")
    msub = pme.add_subparsers(dest="action")
    ma = msub.add_parser("append")
    ma.add_argument("--command", required=True)
    ma.add_argument("--value")
    ma.add_argument("--unit", required=True)
    ma.add_argument("--source-claim", required=True, dest="source_claim")
    ma.add_argument("--dir", default=".")
    mau = msub.add_parser("audit")
    mau.add_argument("--dir", default=".")

    pidx = sub.add_parser("index")
    isub = pidx.add_subparsers(dest="action")
    ib = isub.add_parser("build")
    ib.add_argument("--dir", default=".")
    idg = isub.add_parser("digest")
    idg.add_argument("--dir", default=".")

    psea = sub.add_parser("search")
    psea.add_argument("query")
    psea.add_argument("--budget", type=int, default=0)
    psea.add_argument("--explain", action="store_true")
    psea.add_argument("--dir", default=".")

    par = sub.add_parser("archive")
    par.add_argument("--dir", default=".")

    phk = sub.add_parser("hooks")
    hksub = phk.add_subparsers(dest="action")
    hi = hksub.add_parser("install")
    hi.add_argument("--dir", default=".")
    hst = hksub.add_parser("status")
    hst.add_argument("--dir", default=".")
    hu = hksub.add_parser("unlock")
    hu.add_argument("--reason", required=True)
    hu.add_argument("--dir", default=".")

    pad = sub.add_parser("adopt")
    pad.add_argument("--name")
    pad.add_argument("--dry-run", action="store_true", dest="dry_run")
    pad.add_argument("--dir", default=".")

    ppm = sub.add_parser("promote")
    ppm.add_argument("claim_id")
    ppm.add_argument("--to", required=True)
    ppm.add_argument("--dir", default=".")

    pdr = sub.add_parser("dayreport")
    pdr.add_argument("--date")
    pdr.add_argument("--dir", default=".")

    pvt = sub.add_parser("vault")
    vsub = pvt.add_subparsers(dest="action")
    vi = vsub.add_parser("init")
    vi.add_argument("--volume")
    vi.add_argument("--dir", default=".")
    vm = vsub.add_parser("mirror")
    vm.add_argument("--volume", required=True)
    vm.add_argument("--dir", default=".")
    vr = vsub.add_parser("rehydrate")
    vr.add_argument("--volume", required=True)
    vr.add_argument("--dir", default=".")
    vs = vsub.add_parser("status")
    vs.add_argument("--volume", required=True)
    vs.add_argument("--dir", default=".")

    pmc = sub.add_parser("mcp")
    pmc.add_argument("--http", type=int)
    pmc.add_argument("--dir", default=".")

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        sys.exit(2)
    if args.cmd == "init":
        cmd_init(args)
    elif args.cmd == "verify":
        cmd_verify(args)
    elif args.cmd == "sign":
        cmd_sign(args)
    elif args.cmd == "todo":
        if not args.action:
            pt.print_help()
            sys.exit(2)
        cmd_todo(args, args.dir)
    elif args.cmd == "loop":
        cmd_loop_close(args, args.dir)
    elif args.cmd == "selftest":
        cmd_selftest(args)
    elif args.cmd == "preflight":
        cmd_preflight(args, args.dir)
    elif args.cmd == "close":
        cmd_close(args, args.dir)
    elif args.cmd == "sessions":
        if args.action != "ingest":
            pses.print_help()
            sys.exit(2)
        cmd_sessions_ingest(args, args.dir)
    elif args.cmd == "db":
        if not args.action:
            pdbc.print_help()
            sys.exit(2)
        cmd_db(args, args.dir)
    elif args.cmd == "measure":
        if not args.action:
            pme.print_help()
            sys.exit(2)
        cmd_measure(args, args.dir)
    elif args.cmd == "index":
        if args.action == "digest":
            cmd_index_digest(args, args.dir)
        elif args.action != "build":
            pidx.print_help()
            sys.exit(2)
        else:
            cmd_index_build(args, args.dir)
    elif args.cmd == "search":
        cmd_search(args, args.dir)
    elif args.cmd == "archive":
        cmd_archive(args, args.dir)
    elif args.cmd == "hooks":
        if not args.action:
            phk.print_help()
            sys.exit(2)
        cmd_hooks(args, args.dir)
    elif args.cmd == "adopt":
        cmd_adopt(args, args.dir)
    elif args.cmd == "promote":
        cmd_promote(args, args.dir)
    elif args.cmd == "dayreport":
        cmd_dayreport(args, args.dir)
    elif args.cmd == "vault":
        if not args.action:
            pvt.print_help()
            sys.exit(2)
        cmd_vault(args, args.dir)
    elif args.cmd == "mcp":
        cmd_mcp(args)
    elif args.cmd == "claim":
        if args.verb == "emit":
            cmd_claim_emit(args, args.dir)
        elif args.verb in ("verify", "dispute", "retract"):
            cmd_claim_verdict(args, args.dir,
                              "verified" if args.verb == "verify" else
                              ("disputed" if args.verb == "dispute" else
                               "retracted"))
        elif args.verb == "query":
            cmd_claim_query(args, args.dir)
        elif args.verb == "export":
            cmd_claim_export(args, args.dir)
        elif args.verb == "chain":
            ok, msg = chain_check(read_events(args.dir))
            print(json.dumps({"ok": ok, "detail": msg}))
            sys.exit(0 if ok else 1)
        elif args.verb == "conform":
            cmd_conform(args)
        else:
            pc.print_help()
            sys.exit(2)


if __name__ == "__main__":
    main()
