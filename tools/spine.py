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
`mcp` is v0.5.
"""
import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from decimal import Decimal

VERSION = "0.4.0"
LEDGER = os.path.join("claims", "claims.jsonl")
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

PARAMS = {"agents_md_max_lines": 25, "todo_max_items": 3}

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


def cmd_claim_query(args, root):
    state = {}
    for ev in read_events(root):
        t = ev["event_type"]
        if t == "claim.emitted":
            c = ev["claim"]
            state[c["claim_id"]] = {"type": c["claim_type"],
                                    "status": "active", "result": "-",
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
    for cid, s in sorted(state.items()):
        print("%s  %-9s %-10s %-28s %s" % (cid, s["type"], s["status"],
                                           s["result"], s["text"]))


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
    for rel in index:
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


# ------------------------------------------------------------- selftest
def _st(root, *rest, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run([sys.executable, os.path.abspath(__file__),
                           *rest, "--dir", root], capture_output=True,
                          text=True, env=e)


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


def render(t, name):
    return (t.replace("%NAME%", name).replace("%VER%", VERSION)
            .replace("%DATE%", time.strftime("%Y-%m-%d"))
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
    shutil.copy2(os.path.abspath(__file__),
                 os.path.join(root, "tools", "spine.py"))
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
    for rel in FILES + ["tools/spine.py"] + extra:
        attest_claim(root, rel, "spine " + VERSION, "init")
    print("spine: skeleton ready in %s (%d rules + %d attestations)"
          % (root, len(RULES), len(FILES) + 1))
    print("spine: next -> python3 tools/spine.py verify ; then read AGENTS.md")


def cmd_verify(args):
    root = args.dir
    events = read_events(root)
    if not events:
        sys.exit("verify: no ledger at %s - run init first" % root)
    fails = []
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
    if os.path.exists(st) and "Next command:" not in open(
            st, encoding="utf-8").read():
        fails.append("STATE.md lost its literal next-command (resume rule)")
    issued = set(issued_claim_ids(root))
    verdicts = [ev for ev in events if ev["event_type"] != "claim.emitted"]
    phantoms = sorted({ev["claim_ref"] for ev in verdicts
                       if ev.get("claim_ref") not in issued})
    if phantoms:
        fails.append("PHANTOM refs: %d verdict(s) point at unissued claim "
                     "ids: %s" % (len(phantoms), ", ".join(
                         phantoms[:5])))
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
        print("ORPHAN-COVERAGE: %d/%d issued claims referenced by nothing: "
              "%s" % (len(orphans), len(issued),
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
    for f in fails:
        print("FAIL:", f)
    if fails:
        print("VERIFY: FAIL (%d)" % len(fails))
        sys.exit(1)
    print("VERIFY: PASS (%d events, %d files attested, %s)"
          % (len(events), len(att), msg))
    print("claims: %d issued | %d verdicts | %d phantom refs"
          % (len(issued), len(verdicts), len(phantoms)))


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
    cq.add_argument("--dir", default=".")
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
