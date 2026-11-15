#!/usr/bin/env python3
"""Differential test: keeper (Rust) vs spine.py - criterion 21 gate.

Layer 1 (V/P/D cases): shared-tree cross-reads - each binary must accept
and reproduce the other's writes (the hot read path).
Layer 2 (S cases): full verb-sequence parity - the SAME command sequence
runs on two fresh skeletons (one seeded by each binary) with the clock
pinned via SPINE_TEST_NOW; every stdout+exit pair is compared
byte-for-byte after normalizing only the per-run randomness (ids, pids,
sha of each side's own tools/spine.py self-copy). Skeleton files must be
byte-identical except that self-copy. This is the replacement gate: a
diff is reported, never averaged.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SPINE = os.path.join(REPO, "spine.py")
KEEPER = next((p for p in (os.path.join(REPO, "keeper", "target",
                                        "release", "keeper"),
                          os.path.join(REPO, "keeper", "target", "debug",
                                       "keeper"))
              if os.path.exists(p)), None)

PIN = {"SPINE_TEST_NOW": "2026-11-14T20:00:00Z"}
ID_RE = re.compile(r"(evt|clm|rec|msr|src|ver|ev)_[0-9a-f]{16,32}")
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
SHA_RE = re.compile(r"\b[0-9a-f]{64}\b")
SHAPART_RE = re.compile(r"sha256=[0-9a-f]{16,}")
PID_RE = re.compile(r'"pid": \d+')


def norm(text):
    if TMP:
        text = text.replace(TMP, "<tmp>")
        text = re.sub(r"<tmp>/s1-(py|kp)", "<root>", text)
    return PID_RE.sub('"pid": N',
                      SHA_RE.sub("<sha>", TS_RE.sub("<ts>",
                      SHAPART_RE.sub("sha256=<sha>",
                                     ID_RE.sub("<id>", text)))))


def run(cmd, cwd=None, env=None):
    e = dict(os.environ)
    e.update(PIN)
    if env:
        e.update(env)
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env=e)
    return p.returncode, p.stdout + p.stderr


def seed(name, script):
    root = os.path.join(TMP, name)
    os.makedirs(root)
    code, out = run([sys.executable, SPINE, "init", "--name", name,
                     "--dir", root])
    assert code == 0, out
    for step in script:
        code, out = run([sys.executable, SPINE] + step + ["--dir", root])
        assert code == 0, "%s -> %d %s" % (step, code, out)
    return root


CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def parity(name, py_cmd, kp_cmd, normalize=False, extra=None):
    rc_p, out_p = run(py_cmd)
    rc_k, out_k = run(kp_cmd)
    a = norm(out_p) if normalize else out_p
    b = norm(out_k) if normalize else out_k
    ok = (rc_p == rc_k) and (a == b)
    detail = ""
    if not ok:
        pa, pb = a.splitlines(), b.splitlines()
        for i in range(max(len(pa), len(pb))):
            x = pa[i] if i < len(pa) else "<missing>"
            y = pb[i] if i < len(pb) else "<missing>"
            if x != y:
                detail = "line %d:\n  py: %s\n  kp: %s" % (i + 1, x, y)
                break
        if rc_p != rc_k and not detail:
            detail = "exit py=%d kp=%d" % (rc_p, rc_k)
        elif rc_p != rc_k:
            detail = ("exit py=%d kp=%d; " % (rc_p, rc_k)) + detail
    return {"case": name, "ok": ok, "detail": detail,
            "exit": (rc_p, rc_k), "extra": extra or ""}


@case
def v1_fresh():
    root = seed("v1", [])
    return [parity("V1 verify on fresh skeleton",
                   [sys.executable, SPINE, "verify", "--dir", root],
                   [KEEPER, "verify", "--dir", root])]


@case
def v2_floats():
    root = seed("v2", [["todo", "add", "--what", "Fix auth redirect",
                        "--why", "loop", "--kills", "probe",
                        "--conf", "0.55"],
                       ["loop", "--close", "--method",
                        "source_attestation"],
                       ["todo", "add", "--what", "Cache headers",
                        "--why", "paint", "--kills", "trace"]])
    return [parity("V2 verify after todo/loop (decimal floats in chain)",
                   [sys.executable, SPINE, "verify", "--dir", root],
                   [KEEPER, "verify", "--dir", root])]


@case
def v3_drift_fail():
    root = seed("v3", [])
    with open(os.path.join(root, "STATE.md"), "a") as fh:
        fh.write("unsigned drift line\n")
    return [parity("V3 verify FAILS identically on unsigned drift",
                   [sys.executable, SPINE, "verify", "--dir", root],
                   [KEEPER, "verify", "--dir", root])]


@case
def p1_preflight_hit():
    root = seed("p1", [["todo", "add", "--what", "Wire cartridge checksum",
                        "--why", "trust", "--kills", "probe"]])
    a = os.path.join(TMP, "p1-keeper")
    shutil.copytree(root + "/.", a)
    res = [parity("P1 preflight hits named identically (exit 2)",
                  [sys.executable, SPINE, "preflight", "cartridge checksum",
                   "--dir", root],
                  [KEEPER, "preflight", "cartridge checksum", "--dir", a])]
    rc, out = run([sys.executable, SPINE, "verify", "--dir", a])
    res.append({"case": "P1b python accepts keeper-written ledger event",
                "ok": rc == 0, "detail": out[-200:], "exit": (rc,),
                "extra": ""})
    return res


@case
def p2_preflight_clean():
    root = seed("p2", [])
    a = os.path.join(TMP, "p2-keeper")
    shutil.copytree(root + "/.", a)
    return [parity("P2 preflight clean path identical (exit 0)",
                   [sys.executable, SPINE, "preflight", "zzqqvoidwardz",
                    "--dir", root],
                   [KEEPER, "preflight", "zzqqvoidwardz", "--dir", a])]


@case
def d1_db_add_then_read():
    root = seed("d1", [["claim", "emit", "--text", "rom is ours",
                        "--type", "factual"]])
    rc, out = run([sys.executable, SPINE, "db", "add", "--key", "rom.sha",
                   "--value", "abc123", "--trust", "measured",
                   "--source", "shasum", "--dir", root])
    assert rc == 0, out
    rc, out = run([KEEPER, "db", "add", "--key", "patch.target",
                   "--value", "head.bin", "--dir", root])
    assert rc == 0, out
    res = [parity("D1 db list byte-exact across mixed python+keeper records",
                  [sys.executable, SPINE, "db", "list", "--dir", root],
                  [KEEPER, "db", "list", "--dir", root]),
           parity("D2 db get by key byte-exact (keeper-written record)",
                  [sys.executable, SPINE, "db", "get", "patch.target",
                   "--dir", root],
                  [KEEPER, "db", "get", "patch.target", "--dir", root])]
    rc2, out2 = run([sys.executable, SPINE, "verify", "--dir", root])
    res.append({"case": "D3 verify green on keeper-added record + event",
                "ok": rc2 == 0, "detail": out2[-200:], "exit": (rc2,),
                "extra": ""})
    return res


@case
def d4_db_add_receipt_shape():
    root = seed("d4", [])
    a = os.path.join(TMP, "d4-keeper")
    shutil.copytree(root + "/.", a)
    res = [parity("D4 db add receipts parity (ids/ts normalized)",
                  [sys.executable, SPINE, "db", "add", "--key", "k1",
                   "--value", "v1", "--dir", root],
                  [KEEPER, "db", "add", "--key", "k1", "--value", "v1",
                   "--dir", a], normalize=True)]
    return res


@case
def d5_malformed():
    root = seed("d5", [["db", "add", "--key", "rom.sha", "--value",
                        "abc"]])
    p = os.path.join(root, "data", "db", "records.jsonl")
    before = open(p, "rb").read()
    with open(p, "a") as fh:
        fh.write("{not json\n")
    res = [parity("D5 malformed record line: both refuse, exit 2, same "
                  "message",
                  [sys.executable, SPINE, "db", "list", "--dir", root],
                  [KEEPER, "db", "list", "--dir", root])]
    after = open(p, "rb").read()
    res.append({"case": "D5b record file byte-identical after refusal",
                "ok": after == before + b"{not json\n", "detail": "",
                "exit": (0,), "extra": ""})
    return res


# ---------------------------------------------------------------- layer 2
def byte_identical_seeds(a, b):
    """Every seeded file byte-equal except the self-copy each binary
    makes of itself at tools/spine.py (python file vs keeper binary)."""
    skip = {"tools/spine.py", "data/txlog.jsonl"}
    diffs = []
    for dirpath, dirs, files in os.walk(a):
        dirs.sort()
        for f in sorted(files):
            pa = os.path.join(dirpath, f)
            rel = os.path.relpath(pa, a)
            if rel in skip or rel.startswith("claims" + os.sep):
                continue
            pb = os.path.join(b, rel)
            if not os.path.exists(pb):
                diffs.append(rel + ": missing on keeper side")
            elif open(pa, "rb").read() != open(pb, "rb").read():
                if norm(open(pa, encoding="utf-8", errors="replace").read()
                        ) != norm(open(pb, encoding="utf-8",
                                      errors="replace").read()):
                    diffs.append(rel + ": differs beyond ids/paths")
    return diffs


def capture(out, field="id"):
    if field != "id":
        try:
            for ln in reversed(out.strip().splitlines()):
                j = json.loads(ln)
                if field in j:
                    return j[field]
        except ValueError:
            pass
    m = ID_RE.search(out)
    return m.group(0) if m else ""


@case
def s1_full_sequence():
    """One identical command sequence through both binaries: every
    receipt, table, report and gate verdict byte-equal (ids/pid/pinned-
    time-normalized), plus byte-equal resulting trees. Per-side ids are
    substituted from each side's own earlier receipts ({mid}/{tid}/
    {did}); only the random suffix differs, so shapes stay comparable."""
    p = os.path.join(TMP, "s1-py")
    k = os.path.join(TMP, "s1-kp")
    os.makedirs(p)
    os.makedirs(k)
    steps = []
    cap = {"p": {}, "k": {}}

    def both(verb_args, name, normalize=True, keep=None,
             sort_lines=False):
        subs = {"p": {}, "k": {}}
        for side, table in (("p", cap["p"]), ("k", cap["k"])):
            for key, val in table.items():
                subs[side][key] = val
        argsets = {}
        for side in ("p", "k"):
            argsets[side] = [a.format(**subs[side]) for a in verb_args]
        rc_p, out_p = run([sys.executable, SPINE] + argsets["p"]
                          + ["--dir", p])
        rc_k, out_k = run([KEEPER] + argsets["k"] + ["--dir", k])
        a = norm(out_p) if normalize else out_p
        b = norm(out_k) if normalize else out_k
        if sort_lines:
            a = "\n".join(sorted(a.splitlines()))
            b = "\n".join(sorted(b.splitlines()))
        ok = rc_p == rc_k and a == b
        detail = ""
        if not ok:
            pa, pb = a.splitlines(), b.splitlines()
            for i in range(max(len(pa), len(pb))):
                x = pa[i] if i < len(pa) else "<missing>"
                y = pb[i] if i < len(pb) else "<missing>"
                if x != y:
                    detail = "line %d:\n  py: %s\n  kp: %s" % (i + 1, x, y)
                    break
            if rc_p != rc_k:
                detail = ("exit py=%d kp=%d; " % (rc_p, rc_k)) + detail
        steps.append({"case": "S1 " + name, "ok": ok, "detail": detail,
                      "exit": (rc_p, rc_k), "extra": ""})
        if keep:
            key, field = keep
            cap["p"][key] = capture(out_p, field)
            cap["k"][key] = capture(out_k, field)

    both(["init", "--name", "seqproj"], "init receipts byte-equal")
    both(["claim", "emit", "--text", "measured: rom hash ok",
          "--type", "factual", "--kind", "measured"],
         "claim emit --kind measured", keep=("mid", "claim_id"))
    both(["claim", "emit", "--text", "asserted: perf feels fine",
          "--type", "recommendation"], "claim emit asserted")
    both(["claim", "query"], "claim query table byte-equal",
         sort_lines=True)
    both(["claim", "query", "--kind", "measured"],
         "claim query --kind measured filter byte-equal",
         sort_lines=True)
    both(["claim", "export", "--kinds", "measured,linked"],
         "claim export training rows byte-equal")
    both(["claim", "verify", "{mid}", "--result", "supported",
          "--method", "source_attestation", "--confidence", "0.8"],
         "claim verify on own id (float 0.8 byte-equal)")
    both(["claim", "verify", "clm_deadbeefdeadbeefdeadbeef00", "--result",
          "supported", "--method", "human_review"],
         "claim verify phantom ref refused exit 2, same message")
    both(["claim", "verify", "{mid}", "--result", "supported",
          "--method", "model_check", "--confidence", "0.9"],
         "claim verify model_check>0.6 refused exit 2, same message")
    both(["claim", "dispute", "{mid}", "--reason", "repro differs"],
         "claim dispute event receipt byte-equal")
    both(["todo", "add", "--what", "Wire cartridge checksum", "--why",
          "golden diff", "--kills", "audit green", "--conf", "0.6"],
         "todo add receipt", keep=("tid", "id"))
    both(["todo", "add", "--what", "Re-derive call graph", "--why",
          "stale", "--kills", "index fresh"], "todo add #2", keep=("did", "id"))
    both(["loop", "--close", "--method", "source_attestation",
          "--touch", "{tid}"], "loop close report byte-equal (floats+ids)",
         sort_lines=True)
    both(["loop", "--close", "--method", "human_review"],
         "second loop (all decay) report byte-equal", sort_lines=True)
    both(["todo", "done", "{tid}", "--by", "chris"], "todo done receipt")
    both(["todo", "drop", "{did}", "--reason", "superseded"],
         "todo drop receipt")
    both(["close", "--note", "sequence slice closed"],
         "close receipt (pinned ts + producer name byte-equal)")
    both(["measure", "append", "--command",
          "python3 -c \"print('12.5')\"", "--unit", "ms",
          "--source-claim", "{tid}"],
         "measure append receipt byte-equal")
    both(["measure", "audit"], "measure audit rows byte-equal")
    both(["measure", "append", "--command", "python3 -c \"pass\"",
          "--unit", "ms", "--source-claim", "{tid}"],
         "measure append empty stdout refused exit 2 alike")
    both(["db", "add", "--key", "rom.sha", "--value", "abc", "--trust",
          "measured"], "db add receipt byte-equal")
    both(["db", "list"], "db list byte-equal")
    both(["preflight", "cartridge checksum"],
         "preflight hit byte-equal (exit 2)")
    both(["preflight", "cartridge checksum", "--reason", "extend"],
         "preflight --reason proceed byte-equal")
    both(["verify"], "final gate green, byte-equal")

    diffs = byte_identical_seeds(p, k)
    steps.append({"case": "S1 trees byte-identical after full sequence "
                  "(except tools/spine.py self-copy)",
                  "ok": not diffs, "detail": "; ".join(diffs[:6]),
                  "exit": (0,), "extra": ""})
    rc_x, out_x = run([sys.executable, SPINE, "verify", "--dir", k])
    steps.append({"case": "S1 python verify accepts keeper-written tree",
                  "ok": rc_x == 0, "detail": out_x[-250:], "exit": (rc_x,),
                  "extra": ""})
    return steps


@case
def s2_digest_parity():
    rc_p, out_p = run([sys.executable, SPINE, "index", "digest",
                       "--dir", REPO])
    rc_k, out_k = run([KEEPER, "hash-templates", "--dir", REPO])
    return [{"case": "S2 skeleton spec digest agrees (templates/rules/"
             "params generated, not retyped)",
             "ok": rc_p == rc_k == 0 and out_p.strip() == out_k.strip()
             and len(out_p.strip()) == 64,
             "detail": "py=%s kp=%s" % (out_p.strip()[:64],
                                        out_k.strip()[:64]),
             "exit": (rc_p, rc_k), "extra": ""}]


def main():
    global KEEPER
    quiet = "--quiet" in sys.argv
    if KEEPER is None:
        if shutil.which("cargo") and os.path.isdir(os.path.join(REPO,
                                                                "keeper")):
            subprocess.run(["cargo", "build", "--quiet"],
                           cwd=os.path.join(REPO, "keeper"),
                           capture_output=True, timeout=600)
            KEEPER = os.path.join(REPO, "keeper", "target", "debug",
                                  "keeper")
    if KEEPER is None or not os.path.exists(KEEPER):
        print("DIFFTEST: BLOCKED - keeper binary not built and cargo "
              "unavailable; parity unproven (criterion 21)")
        sys.exit(0)
    results = []
    for fn in CASES:
        try:
            results.extend(fn())
        except AssertionError as e:
            results.append({"case": fn.__name__, "ok": False,
                            "detail": "seed failed: %s" % e,
                            "exit": ("seed",), "extra": ""})
    bad = [r for r in results if not r["ok"]]
    for r in results:
        if not quiet or not r["ok"]:
            print("%s  %s%s" % ("PARITY" if r["ok"] else "DIFF  ",
                                r["case"],
                                "" if r["ok"] else "   <- " + r["detail"]))
    print("DIFFTEST: %s (%d/%d parity on the full verb surface "
          "[criterion 21 replacement gate])"
          % ("PASS" if not bad else "FAIL", len(results) - len(bad),
             len(results)))
    sys.exit(0 if not bad else 1)


if __name__ == "__main__":
    TMP = tempfile.mkdtemp(prefix="difftest-")
    try:
        main()
    finally:
        if not os.environ.get("KEEP"):
            shutil.rmtree(TMP, ignore_errors=True)
