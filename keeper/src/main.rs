// keeper - the Rust subset of the spine gate (criterion 21).
//
// Implements `verify`, `preflight` and `db add|get|list` natively so the
// hot read path does not depend on Python. Parity with spine.py is proven
// by tools/difftest.py (same scratch, compare stdout+exit). When parity
// is full, keeper can replace the Python verify path (R6: proven, not
// promised). Only std: hand-rolled sha256, JSON, and RFC8785-style JCS
// byte-compatible with spine.py / OpenClaims v0.1.
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

mod generated;

// ------------------------------------------------------------------ sha256
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
        0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut data = msg.to_vec();
    let bitlen = (msg.len() as u64) * 8;
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in data.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1],
                                       chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18)
                ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19)
                ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut abcdefgh = h;
        for i in 0..64 {
            let [a, b, c, d, e, f, g, hh] = abcdefgh;
            let s1 = e.rotate_right(6) ^ e.rotate_right(11)
                ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13)
                ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            abcdefgh = [t1.wrapping_add(t2), a, b, c,
                        d.wrapping_add(t1), e, f, g];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(abcdefgh[i]);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

const B64U: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url(d: &[u8]) -> String {
    let mut s = String::new();
    for c in d.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        s.push(B64U[((n >> 18) & 63) as usize] as char);
        s.push(B64U[((n >> 12) & 63) as usize] as char);
        if c.len() > 1 {
            s.push(B64U[((n >> 6) & 63) as usize] as char);
        }
        if c.len() > 2 {
            s.push(B64U[(n & 63) as usize] as char);
        }
    }
    s
}

// -------------------------------------------------------------------- time
fn civil_from_days(z0: i64) -> (i64, u32, u32) {
    let z = z0 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn utc_parts(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86400);
    let r = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    (y, m, d, (r / 3600) as u32, ((r % 3600) / 60) as u32,
     (r % 60) as u32)
}

fn now() -> String {
    if let Ok(p) = env::var("SPINE_TEST_NOW") {
        if !p.is_empty() {
            return p;
        }
    }
    let secs = match std::time::SystemTime::now().duration_since(
        std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    };
    let (y, m, d, hh, mm, ss) = utc_parts(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}

fn today() -> String {
    if let Ok(p) = env::var("SPINE_TEST_NOW") {
        if p.len() >= 10 {
            return p[..10].to_string();
        }
    }
    now()[..10].to_string()
}

fn date_of(mtime: i64) -> String {
    let (y, m, d, _, _, _) = utc_parts(mtime);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn rand_id(prefix: &str) -> String {
    let mut b = [0u8; 16];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    let h: String = b.iter().map(|x| format!("{:02x}", x)).collect();
    format!("{}_{}", prefix, &h[..26])
}

// ------------------------------------------------------------------- spec
// The skeleton templates, rules and params are generated from spine.py
// (tools/gen_keeper_data.py) so both binaries land byte-identical files.
// `keeper hash-templates` and `spine.py index digest` share one sha256;
// difftest fails the pair on any drift.

const LEDGER_REL: &str = "claims/claims.jsonl";
const MEASURED_REL: &str = "data/measurements.jsonl";
const DERIVED_REL: &str = "data/derived.json";
const TXLOG_REL: &str = "data/txlog.jsonl";
const GOLDEN_SEED: &str = "\nD00g | %DATE% | Structural changes require a golden capture first (opt-in ritual: tools/golden.sh).\n";

fn spec_val() -> J {
    let s = generated::spec();
    let txt = dump(&s);
    match (P { b: txt.as_bytes(), i: 0 }).parse() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("keeper: generated spec invalid: {}", e);
            std::process::exit(2);
        }
    }
}

fn spec_int(p: &mut J, key: &str, dflt: i64) -> i64 {
    match p.get("params").and_then(|m| m.get(key)) {
        Some(J::Int(i)) => *i,
        Some(J::Num(f)) => *f as i64,
        _ => dflt,
    }
}

fn spec_files(p: &mut J) -> Vec<String> {
    match p.get("files") {
        Some(J::Arr(v)) => {
            v.iter().map(|x| x.as_str()).collect()
        }
        _ => Vec::new(),
    }
}

fn spec_tpl(p: &mut J, key: &str) -> String {
    p.get("tpl").and_then(|m| m.get(key)).map(|x| x.as_str())
        .unwrap_or_default()
}

fn render(t: &str, name: &str) -> String {
    let ver = spec_val().get("version").map(|v| v.as_str())
        .unwrap_or_default();
    let max = spec_int(&mut spec_val(), "todo_max_items", 3).to_string();
    t.replace("%NAME%", name).replace("%VER%", &ver)
        .replace("%DATE%", &today()).replace("%TODO_MAX%", &max)
}

fn txlog(root: &Path, tool: &str, exit_code: i32, note: &str) {
    let p = root.join(TXLOG_REL);
    if let Some(d) = p.parent() {
        let _ = fs::create_dir_all(d);
    }
    let line = dump(&J::Obj(vec![
        ("ts".into(), J::Str(now())),
        ("tool".into(), J::Str(tool.into())),
        ("exit".into(), J::Int(exit_code as i64)),
        ("note".into(), J::Str(note.into())),
        ("by".into(), J::Str(producer().s("name"))),
        ("pid".into(), J::Int(std::process::id() as i64)),
    ]));
    if let Ok(mut f) = fs::OpenOptions::new().append(true).create(true)
            .open(&p) {
        let _ = writeln!(f, "{}", line);
    }
}

fn write_text_unlocked(p: &Path, text: &str) -> std::io::Result<()> {
    let was = is_locked(p);
    if was {
        set_flags(p, false);
    }
    let r = fs::write(p, text);
    if was {
        set_flags(p, true);
    }
    r.map_err(|e| e.into())
}

fn pw_name(uid: u32) -> String {
    if let Ok(txt) = fs::read_to_string("/etc/passwd") {
        for ln in txt.lines() {
            let f: Vec<&str> = ln.split(':').collect();
            if f.len() >= 3 && f[2].parse::<u32>() == Ok(uid) {
                return f[0].to_string();
            }
        }
    }
    format!("uid:{}", uid)
}

fn expect_owner(root: &Path) -> Option<String> {
    let conf = root.join(".spine-owner");
    match fs::read_to_string(&conf) {
        Ok(s) => {
            let t = s.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }
        Err(_) => None,
    }
}

fn uid_of_named(name: &str) -> Option<u32> {
    if let Ok(txt) = fs::read_to_string("/etc/passwd") {
        for ln in txt.lines() {
            let f: Vec<&str> = ln.split(':').collect();
            if f.len() >= 3 && f[0] == name {
                return f[2].parse::<u32>().ok();
            }
        }
    }
    None
}

// -------------------------------------------------------------------- json
#[derive(Clone, Debug)]
enum J {
    Nul,
    Bool(bool),
    Num(f64),
    Int(i64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, k: &str) -> Option<&J> {
        if let J::Obj(v) = self {
            v.iter().find(|(kk, _)| kk == k).map(|(_, vv)| vv)
        } else {
            None
        }
    }
    fn s(&self, k: &str) -> String {
        match self.get(k) {
            Some(J::Str(s)) => s.clone(),
            _ => String::new(),
        }
    }
    fn as_str(&self) -> String {
        match self {
            J::Str(s) => s.clone(),
            _ => String::new(),
        }
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len()
                && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn parse(&mut self) -> Result<J, String> {
        self.ws();
        match self.b.get(self.i) {
            Some(b'{') => self.obj(),
            Some(b'[') => self.arr(),
            Some(b'"') => Ok(J::Str(self.string()?)),
            Some(b't') => self.lit("true", J::Bool(true)),
            Some(b'f') => self.lit("false", J::Bool(false)),
            Some(b'n') => self.lit("null", J::Nul),
            Some(c) if *c == b'-' || c.is_ascii_digit() => self.num(),
            _ => Err(format!("json: bad byte at {}", self.i)),
        }
    }
    fn lit(&mut self, w: &str, j: J) -> Result<J, String> {
        if self.b[self.i..].starts_with(w.as_bytes()) {
            self.i += w.len();
            Ok(j)
        } else {
            Err(format!("json: bad literal at {}", self.i))
        }
    }
    fn num(&mut self) -> Result<J, String> {
        let st = self.i;
        if self.b[self.i] == b'-' {
            self.i += 1;
        }
        while self.i < self.b.len() && (self.b[self.i].is_ascii_digit()
                || matches!(self.b[self.i], b'.' | b'e' | b'E' | b'+'
                           | b'-')) {
            self.i += 1;
        }
        let t = std::str::from_utf8(&self.b[st..self.i])
            .map_err(|e| e.to_string())?;
        if t.contains('.') || t.contains('e') || t.contains('E') {
            Ok(J::Num(t.parse::<f64>().map_err(|e| e.to_string())?))
        } else {
            Ok(J::Int(t.parse::<i64>().map_err(|e| e.to_string())?))
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = *self.b.get(self.i).ok_or("json: unterminated string")?;
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or("json: bad escape")?;
                    self.i += 1;
                    match e {
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'u' => {
                            let h = std::str::from_utf8(
                                &self.b[self.i..self.i + 4])
                                .map_err(|e| e.to_string())?;
                            self.i += 4;
                            let cp = u32::from_str_radix(h, 16)
                                .map_err(|e| e.to_string())?;
                            if (0xD800..0xDC00).contains(&cp)
                                    && self.b.get(self.i) == Some(&b'\\') {
                                let h2 = std::str::from_utf8(
                                    &self.b[self.i + 2..self.i + 6])
                                    .map_err(|e| e.to_string())?;
                                let lo = u32::from_str_radix(h2, 16)
                                    .map_err(|e| e.to_string())?;
                                let c = 0x10000 + ((cp - 0xD800) << 10)
                                    + (lo - 0xDC00);
                                out.push(char::from_u32(c).unwrap_or('\u{fffd}'));
                                self.i += 6;
                            } else {
                                out.push(char::from_u32(cp)
                                         .unwrap_or('\u{fffd}'));
                            }
                        }
                        _ => return Err("json: bad escape char".into()),
                    }
                }
                _ => {
                    let st = self.i - 1;
                    let len = if c < 0x80 {
                        1
                    } else if c >> 5 == 0b110 {
                        2
                    } else if c >> 4 == 0b1110 {
                        3
                    } else {
                        4
                    };
                    self.i = st + len;
                    out.push_str(std::str::from_utf8(&self.b[st..self.i])
                                 .map_err(|e| e.to_string())?);
                }
            }
        }
    }
    fn arr(&mut self) -> Result<J, String> {
        self.i += 1;
        let mut v = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(J::Arr(v));
        }
        loop {
            v.push(self.parse()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(J::Arr(v));
                }
                _ => return Err(format!("json: bad array at {}", self.i)),
            }
        }
    }
    fn obj(&mut self) -> Result<J, String> {
        self.i += 1;
        let mut v: Vec<(String, J)> = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(J::Obj(v));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return Err(format!("json: bad object at {}", self.i));
            }
            self.i += 1;
            let val = self.parse()?;
            v.push((k, val));
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(J::Obj(v));
                }
                _ => return Err(format!("json: bad object at {}", self.i)),
            }
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            '\r' => o.push_str("\\r"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}",
                                                          c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn js_num(n: f64) -> String {
    if n == 0.0 {
        return "0".into();
    }
    if n.fract() == 0.0 && n.abs() < 1e21 {
        return format!("{}", n as i64);
    }
    format!("{}", n)
}

fn dump(j: &J) -> String {
    match j {
        J::Nul => "null".into(),
        J::Bool(b) => if *b { "true" } else { "false" }.into(),
        J::Int(i) => format!("{}", i),
        J::Num(f) => js_num(*f),
        J::Str(s) => json_escape(s),
        J::Arr(v) => format!("[{}]", v.iter().map(dump).collect::<Vec<_>>()
                            .join(", ")),
        J::Obj(_) => {
            let mut m = BTreeMap::new();
            if let J::Obj(v) = j {
                for (k, x) in v {
                    m.insert(k, x);
                }
            }
            let parts: Vec<String> = m.iter()
                .map(|(k, x)| format!("{}: {}", json_escape(k), dump(x)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

// Insertion-order dump: receipts match Python json.dumps without sort_keys.
fn dump_ins(j: &J) -> String {
    match j {
        J::Obj(v) => {
            let parts: Vec<String> = v.iter()
                .map(|(k, x)| format!("{}: {}", json_escape(k), dump_ins(x)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        _ => dump(j),
    }
}

// JCS: keys sorted by UTF-16 code units, no whitespace, floats like JS,
// None values dropped from objects (byte-compatible with spine.py).
fn jcs(j: &J) -> String {
    match j {
        J::Nul => "null".into(),
        J::Bool(b) => if *b { "true" } else { "false" }.into(),
        J::Int(i) => format!("{}", i),
        J::Num(f) => js_num(*f),
        J::Str(s) => json_escape(s),
        J::Arr(v) => format!("[{}]", v.iter().map(jcs).collect::<Vec<_>>()
                            .join(",")),
        J::Obj(v) => {
            let mut e: Vec<(Vec<u16>, &String, &J)> = v.iter()
                .filter(|(_, x)| !matches!(x, J::Nul))
                .map(|(k, x)| (k.encode_utf16().collect(), k, x))
                .collect();
            e.sort_by(|a, b| a.0.cmp(&b.0));
            let parts: Vec<String> = e.iter()
                .map(|(_, k, x)| format!("{}:{}", json_escape(k), jcs(x)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

fn event_digest(ev: &J) -> String {
    let mut rest: Vec<(String, J)> = Vec::new();
    if let J::Obj(v) = ev {
        for (k, x) in v {
            if k != "digest" {
                rest.push((k.clone(), x.clone()));
            }
        }
    }
    b64url(&sha256(jcs(&J::Obj(rest)).as_bytes()))
}

// ----------------------------------------------------------------- helpers
fn ledger_path(root: &Path) -> PathBuf {
    root.join("claims").join("claims.jsonl")
}

fn read_events(root: &Path) -> Vec<J> {
    let mut out = Vec::new();
    if let Ok(txt) = fs::read_to_string(ledger_path(root)) {
        for ln in txt.lines() {
            let ln = ln.trim();
            if ln.is_empty() {
                continue;
            }
            if let Ok(ev) = (P { b: ln.as_bytes(), i: 0 }).parse() {
                out.push(ev);
            }
        }
    }
    out
}

fn sha_file(path: &Path) -> String {
    let mut v = Vec::new();
    if let Ok(mut f) = fs::File::open(path) {
        let _ = f.read_to_end(&mut v);
    }
    hex(&sha256(&v))
}

fn finalize_event(root: &Path, mut ev: J) -> J {
    let events = read_events(root);
    let trace: Vec<(String, J)> =
        if let Some(last) = events.last() {
            vec![
                ("event_ids".into(), J::Arr(vec![J::Str(last.s("event_id"))])),
                ("hash_chain".into(), J::Arr(vec![J::Str(
                    last.get("digest").map(|d| d.s("value"))
                        .unwrap_or_default())])),
            ]
        } else {
            Vec::new()
        };
    if let J::Obj(v) = &mut ev {
        if !trace.is_empty() {
            v.push(("auditable_trace".into(), J::Obj(trace)));
        }
        v.retain(|(k, _)| k != "digest");
    }
    let dig = event_digest(&ev);
    if let J::Obj(v) = &mut ev {
        v.push(("digest".into(), J::Obj(vec![
            ("algorithm".into(), J::Str("sha256".into())),
            ("encoding".into(), J::Str("base64url".into())),
            ("value".into(), J::Str(dig)),
        ])));
    }
    ev
}

fn write_event_line(root: &Path, ev: &J) -> Result<(), String> {
    let p = ledger_path(root);
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let mut f = fs::OpenOptions::new().append(true).create(true).open(&p)
        .map_err(|e| format!("ledger write refused: {}", e))?;
    writeln!(f, "{}", dump(ev)).map_err(|e| e.to_string())
}

fn append_event(root: &Path, ev: J) -> Result<(), String> {
    let ev = finalize_event(root, ev);
    write_event_line(root, &ev)
}

fn producer() -> J {
    let aid = match env::var("SPINE_PRODUCER_ID") {
        Ok(a) if !a.is_empty() => a,
        _ => match env::var("OPENFOX_SESSION_ID") {
            Ok(s) => format!("urn:session:{}", s),
            Err(_) => "urn:tool:ai-project-spine".into(),
        },
    };
    J::Obj(vec![
        ("agent_id".into(), J::Str(aid)),
        ("agent_type".into(),
         J::Str(env::var("SPINE_PRODUCER_TYPE")
                .unwrap_or_else(|_| "service".into()))),
        ("name".into(), J::Str(env::var("SPINE_PRODUCER_NAME")
                               .unwrap_or_else(|_| {
            format!("ai-project-spine {}",
                    spec_val().get("version").map(|v| v.as_str())
                        .unwrap_or_default())
        }))),
    ])
}

fn base_event(etype: &str) -> J {
    J::Obj(vec![
        ("event_id".into(), J::Str(rand_id("evt"))),
        ("event_type".into(), J::Str(etype.into())),
        ("event_time".into(), J::Str(now())),
        ("spec_version".into(), J::Str("0.1.0".into())),
        ("schema_url".into(), J::Str("https://openclaims.org/schemas/\
             openclaims/0.1/ClaimEvent.schema.json".into())),
        ("producer".into(), producer()),
    ])
}

fn attest(root: &Path, rel: &str, by: &str, reason: &str)
        -> Result<(), String> {
    let h = sha_file(&root.join(rel));
    let mut ev = base_event("claim.emitted");
    if let J::Obj(v) = &mut ev {
        v.push(("claim".into(), J::Obj(vec![
            ("claim_id".into(), J::Str(rand_id("clm"))),
            ("text".into(), J::Str(format!("attest {} sha256={} by {} : {}",
                                           rel, h, by, reason))),
            ("claim_type".into(), J::Str("factual".into())),
            ("asserted_at".into(), J::Str(now())),
            ("context".into(), J::Obj(vec![("spine".into(), J::Obj(vec![
                ("kind".into(), J::Str("attest".into())),
                ("path".into(), J::Str(rel.into())),
                ("sha256".into(), J::Str(h)),
                ("by".into(), J::Str(by.into())),
                ("reason".into(), J::Str(reason.into())),
            ]))])),
        ])));
    }
    append_checked(root, ev).map(|_| ())
}

fn is_locked(p: &Path) -> bool {
    let out = Command::new("ls").args(["-lO", &p.to_string_lossy()])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains("uchg"),
        Err(_) => false,
    }
}

fn set_flags(p: &Path, on: bool) {
    let _ = Command::new("chflags")
        .arg(if on { "uchg" } else { "nouchg" })
        .arg(p).output();
}

fn write_append_unlocked(p: &Path, line: &str) -> std::io::Result<()> {
    let was = is_locked(p);
    if was {
        set_flags(p, false);
    }
    let r = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new().append(true).create(true).open(p)?;
        writeln!(f, "{}", line)
    })();
    if was {
        set_flags(p, true);
    }
    r
}

// ------------------------------------------------------------------ verify
// (criterion 21): the tracked-file list now lives in the
// generated spec (spec_files) so it cannot drift from spine.py.

fn issued_ids(events: &[J]) -> Vec<String> {
    let mut ids = Vec::new();
    for ev in events {
        if ev.s("event_type") == "claim.emitted" {
            if let Some(c) = ev.get("claim") {
                let id = c.s("claim_id");
                if !id.is_empty() {
                    ids.push(id);
                }
            }
        }
    }
    ids
}

fn cmd_verify(root: &Path, full: bool) -> i32 {
    let mut sp = spec_val();
    let events = read_events(root);
    if events.is_empty() {
        eprintln!("verify: no ledger at {} - run init first",
                  root.display());
        return 1;
    }
    let mut lines: Vec<String> = Vec::new();
    let mut warns: Vec<String> = Vec::new();
    let mut fails: Vec<String> = Vec::new();
    let (ok, msg) = chain_check(&events);
    if !ok {
        fails.push(format!("CHAIN: {}", msg));
    }
    let mut att: BTreeMap<String, String> = BTreeMap::new();
    for ev in &events {
        if let Some(sp) = ev.get("claim").and_then(|c| c.get("context"))
                .and_then(|c| c.get("spine")) {
            if sp.s("kind") == "attest" {
                att.insert(sp.s("path"), sp.s("sha256"));
            }
        }
    }
    for (rel, h) in &att {
        let p = root.join(rel);
        if !p.exists() {
            fails.push(format!("MISSING attested file: {}", rel));
        } else if sha_file(&p) != *h {
            fails.push(format!("UNATTESTED: {} modified outside the gate",
                              rel));
        }
    }
    for rel in spec_files(&mut sp) {
        if !att.contains_key(&rel) {
            fails.push(format!("UNTRACKED spine file: {} (never attested)",
                              rel));
        }
    }
    let ag = root.join("AGENTS.md");
    if ag.exists() {
        let n = fs::read_to_string(&ag).unwrap_or_default()
            .lines().count();
        let amax = spec_int(&mut sp, "agents_md_max_lines", 25);
        if n > amax as usize {
            fails.push(format!("AGENTS.md {} lines > cap {} (rule R2/R3)",
                              n, amax));
        }
    }
    let st = root.join("STATE.md");
    if st.exists() {
        let body = fs::read_to_string(&st).unwrap_or_default();
        let n = body.lines().count();
        let cap = spec_int(&mut sp, "state_md_max_lines", 120);
        let strict = root.join("DECISIONS.md").exists()
            && fs::read_to_string(root.join("DECISIONS.md"))
                .unwrap_or_default().contains("state-cap: strict");
        let note = if strict {
            " (strict: opted in via DECISIONS.md state-cap: strict)".to_string()
        } else {
            " (opt in: add 'state-cap: strict' to DECISIONS.md to make \
             this a FAIL)".to_string()
        };
        lines.push(format!("state: {} lines (cap {}){}", n, cap, note));
        if n > cap as usize {
            let m = format!("STATE.md {} lines > cap {} - `spine.py \
                            archive` moves dated blocks to docs/STATE-LOG.md",
                           n, cap);
            if strict {
                fails.push(m);
            } else {
                warns.push(m);
            }
        }
        if !body.contains("Next command:") {
            fails.push("STATE.md lost its literal next-command (resume \
                        rule)"
                       .into());
        }
    }
    let issued: Vec<String> = issued_ids(&events);
    let mut phantoms: Vec<String> = Vec::new();
    for ev in &events {
        let t = ev.s("event_type");
        if t != "claim.emitted" {
            let r = ev.s("claim_ref");
            if !r.is_empty() && !issued.contains(&r)
                    && !phantoms.contains(&r) {
                phantoms.push(r);
            }
        }
    }
    phantoms.sort();
    if !phantoms.is_empty() {
        fails.push(format!("PHANTOM refs: {} verdict(s) point at unissued \
                           claim ids: {}",
                           phantoms.len(),
                           phantoms.iter().take(5).cloned()
                                   .collect::<Vec<_>>().join(", ")));
    }
    let dpath = root.join(DERIVED_REL);
    if dpath.exists() {
        if let Ok(j) = (P { b: fs::read_to_string(&dpath)
                .unwrap_or_default().as_bytes(), i: 0 }).parse() {
            if let Some(J::Obj(srcs)) = j.get("sources") {
                for (rel, want) in srcs {
                    let p = root.join(rel);
                    let have = if p.exists() { sha_file(&p) }
                        else { "missing".into() };
                    if want.as_str() != have {
                        warns.push(format!("STALE derived view: {} sources \
                                            moved - re-derive: {}",
                                           j.get("view").map(|v| v.as_str())
                                             .unwrap_or_else(||
                                               "data/kindex.jsonl".into()),
                                           j.get("command")
                                             .map(|v| v.as_str())
                                             .unwrap_or_else(||
                                               "index build".into())));
                    }
                }
            }
        }
    }
    if let Some(owner) = expect_owner(root) {
        let want_uid = uid_of_named(&owner).unwrap_or(4294967294);
        for rel in [DB_REL, MEASURED_REL] {
            let p = root.join(rel);
            if p.exists() && p.metadata().map(|m| m.uid())
                    .unwrap_or(want_uid) != want_uid {
                fails.push(format!("PERMISSION-DRIFT: {} owned by {}, \
                                    expected {} (privilege boundary broken)",
                                   rel, pw_name(p.metadata().unwrap().uid()),
                                   owner));
            }
        }
    }
    {
        let tdir = root.join("tools");
        if tdir.is_dir() {
            let rp = root.join("tools/REGISTRY.md");
            let reg = fs::read_to_string(&rp).unwrap_or_default();
            let mut entries: Vec<PathBuf> = fs::read_dir(&tdir)
                .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path())
                     .collect()).unwrap_or_default();
            entries.sort();
            for p in entries {
                let name = p.file_name().map(|s| s.to_string_lossy()
                    .to_string()).unwrap_or_default();
                let exec = {
                    p.is_file() && p.metadata().map(|m| m.permissions()
                        .mode() & 0o111 != 0).unwrap_or(false)
                };
                if exec && name != "spine.py"
                        && !reg.contains(&format!("tools/{}", name)) {
                    warns.push(format!("UNREGISTERED tool: tools/{} lacks \
                                        a row in tools/REGISTRY.md (rule \
                                        R7 housekeeping)", name));
                }
            }
        }
    }
    let todo = fs::read_to_string(root.join("TODO.md")).unwrap_or_default();
    let mut orphans: Vec<String> = Vec::new();
    let mut issued_sorted = issued.clone();
    issued_sorted.sort();
    for cid in &issued_sorted {
        let mut referenced = todo.contains(cid.as_str());
        for ev in &events {
            if referenced {
                break;
            }
            if ev.get("claim").map(|c| c.s("claim_id"))
                    == Some(cid.clone()) {
                continue;
            }
            let without: J = {
                let mut v: Vec<(String, J)> = Vec::new();
                if let J::Obj(ov) = ev {
                    for (k, x) in ov {
                        if k != "digest" {
                            v.push((k.clone(), x.clone()));
                        }
                    }
                }
                J::Obj(v)
            };
            if dump(&without).contains(cid.as_str())
                    && ev.get("claim").map(|c| c.s("claim_id"))
                        != Some(cid.clone()) {
                referenced = true;
            }
        }
        if !referenced {
            orphans.push(cid.clone());
        }
    }
    if !orphans.is_empty() {
        let mut s = orphans.iter().take(5).cloned()
            .collect::<Vec<_>>().join(", ");
        if orphans.len() > 5 {
            s.push_str(" ...");
        }
        lines.push(format!("ORPHAN-COVERAGE: {}/{} issued claims referenced \
                           by nothing: {}",
                          orphans.len(), issued.len(), s));
    }
    let bp = root.join("BUGS.md");
    if bp.exists() {
        let full = fs::read_to_string(&bp).unwrap_or_default();
        let body = full.split("---").nth(1).unwrap_or("").to_lowercase();
        for entry in body.split('\n') {
            let e = entry.trim();
            if e.is_empty() {
                continue;
            }
            let named = e.starts_with('[')
                || (e.starts_with('b')
                    && e.get(1..2).map_or(false, |c| c.chars().next()
                                          .map_or(false, |c| c.is_ascii_digit())))
                || e.starts_with("bug-");
            if named && (e.contains("discard") || e.contains("downgrade")
                         || e.contains("superseded-result"))
                    && !e.contains("retest:") {
                let cut: String = e.chars().take(60).collect();
                fails.push(format!("BUGS.md entry discards a result \
                                   without a retest: field: \"{}\"", cut));
            }
        }
    }
    for l in &lines {
        println!("{}", l);
    }
    if !full {
        return 0;
    }
    for w in &warns {
        println!("WARN: {}", w);
    }
    for f in &fails {
        println!("FAIL: {}", f);
    }
    if !fails.is_empty() {
        println!("VERIFY: FAIL ({})", fails.len());
        return 1;
    }
    println!("VERIFY: PASS ({} events, {} files attested, {})",
             events.len(), att.len(), msg);
    println!("claims: {} issued | {} verdicts | {} phantom refs",
             issued.len(),
             events.iter().filter(|e| e.s("event_type") != "claim.emitted")
                 .count(),
             phantoms.len());
    0
}

fn chain_check(events: &[J]) -> (bool, String) {
    let mut prev_id = String::new();
    let mut prev_dig = String::new();
    let mut first = true;
    for (i, ev) in events.iter().enumerate() {
        let want = event_digest(ev);
        let have = ev.get("digest").map(|d| d.s("value")).unwrap_or_default();
        if have.is_empty() || have != want {
            return (false, format!("digest mismatch at event {} ({})", i,
                                  ev.s("event_id")));
        }
        let ids: Vec<String> = ev.get("auditable_trace")
            .and_then(|t| t.get("event_ids")).and_then(|a| {
                if let J::Arr(v) = a {
                    Some(v.iter().map(|x| x.as_str()).collect())
                } else {
                    None
                }
            }).unwrap_or_default();
        let chain: Vec<String> = ev.get("auditable_trace")
            .and_then(|t| t.get("hash_chain")).and_then(|a| {
                if let J::Arr(v) = a {
                    Some(v.iter().map(|x| x.as_str()).collect())
                } else {
                    None
                }
            }).unwrap_or_default();
        if first {
            if !ids.is_empty() || !chain.is_empty() {
                return (false,
                        format!("first event must be unlinked ({})", i));
            }
        } else if ids.len() != 1 || ids[0] != prev_id
                || chain.len() != 1 || chain[0] != prev_dig {
            return (false, format!("broken link at event {} ({})", i,
                                  ev.s("event_id")));
        }
        prev_id = ev.s("event_id");
        prev_dig = have;
        first = false;
    }
    (true, format!("chain ok ({} events)", events.len()))
}

// --------------------------------------------------------------- preflight
fn terms_of(query: &str) -> Vec<String> {
    query.to_lowercase()
        .split(|c: char| !c.is_ascii_lowercase() && !c.is_ascii_digit()
              && c != '_')
        .filter(|t| t.len() >= 4)
        .map(|t| t.to_string())
        .collect()
}

fn index_files(root: &Path, extra: &[String]) -> Vec<String> {
    let mut idx: Vec<String> = ["README.md", "STATE.md", "TODO.md",
        "DECISIONS.md", "BUGS.md", "CLAIMS.md"].iter()
        .map(|s| s.to_string()).collect();
    for e in extra {
        idx.push(e.clone());
    }
    for e in env::var("SPINE_ARTIFACTS").unwrap_or_default()
            .split(':').filter(|s| !s.is_empty()) {
        idx.push(e.to_string());
    }
    if !idx.contains(&"tools/REGISTRY.md".to_string()) {
        idx.push("tools/REGISTRY.md".to_string());
    }
    let data_dirs = env::var("SPINE_DATA_DIRS")
        .unwrap_or_else(|_| "data".to_string());
    let mut dirs: Vec<String> = data_dirs.split(':')
        .filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
    dirs.push("vault".into());
    for d in dirs {
        let droot = root.join(&d);
        if droot.is_dir() {
            walk(&droot, root, &mut idx);
        }
    }
    idx.sort();
    idx
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
    if let Ok(rd) = fs::read_dir(dir) {
        let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok())
            .map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, root, out);
            } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if ["jsonl", "json", "md", "txt", "csv"].contains(&ext) {
                    if let Ok(rel) = p.strip_prefix(root) {
                        out.push(rel.to_string_lossy().to_string());
                    }
                }
            }
        }
    }
}

fn cmd_preflight(root: &Path, query: &str, reason: Option<&str>) -> i32 {
    let terms = terms_of(query);
    if terms.is_empty() {
        eprintln!("preflight: query needs >=1 word of 4+ chars");
        return 2;
    }
    let mut hits: Vec<(String, String, String)> = Vec::new();
    for ev in read_events(root) {
        let text = ev.get("claim").map(|c| c.s("text")).unwrap_or_default();
        let low = text.to_lowercase();
        if terms.iter().any(|t| low.contains(t.as_str())) {
            hits.push(("ledger".into(), ev.s("event_time"),
                       text.chars().take(100).collect::<String>()
                           .replace('\n', " ")));
        }
    }
    for rel in index_files(root, &[]) {
        let p = root.join(&rel);
        if !p.exists() {
            continue;
        }
        let mt = p.metadata().map(|m| m.modified().ok()).ok().flatten()
            .map(|t| t.duration_since(std::time::UNIX_EPOCH)
                 .map(|d| d.as_secs() as i64).unwrap_or(0))
            .unwrap_or(0);
        let d = date_of(mt);
        for ln in fs::read_to_string(&p).unwrap_or_default().lines() {
            let low = ln.to_lowercase();
            if terms.iter().any(|t| low.contains(t.as_str())) {
                let cut: String = ln.trim().chars().take(100).collect();
                hits.push((rel.clone(), d.clone(), cut));
            }
        }
    }
    for (src, d, txt) in hits.iter().take(12) {
        println!("  [{} {}] {}", src, d, txt);
    }
    let mut ev = base_event("claim.emitted");
    if let J::Obj(v) = &mut ev {
        v.push(("claim".into(), J::Obj(vec![
            ("claim_id".into(), J::Str(rand_id("clm"))),
            ("text".into(), J::Str(format!("preflight \"{}\": {} hit(s)",
                                           query, hits.len()))),
            ("claim_type".into(), J::Str("factual".into())),
            ("asserted_at".into(), J::Str(now())),
            ("context".into(), J::Obj(vec![("spine".into(), J::Obj(vec![
                ("kind".into(), J::Str("preflight".into())),
                ("query".into(), J::Str(query.into())),
                ("hits".into(), J::Int(hits.len() as i64)),
            ]))])),
        ])));
    }
    if let Err(e) = append_event(root, ev) {
        eprintln!("{}", e);
        return 2;
    }
    if !hits.is_empty() && reason.is_none() {
        println!("PREFLIGHT: {} prior-art hit(s) - read them, then re-run \
                 with --reason '<why proceed>'", hits.len());
        return 2;
    }
    if hits.is_empty() {
        println!("PREFLIGHT: clean");
    } else {
        println!("PREFLIGHT: PROCEED (reason logged): {}",
                 reason.unwrap_or(""));
    }
    0
}

// ---------------------------------------------------------------- ------ db
const DB_REL: &str = "data/db/records.jsonl";

fn validate_record(r: &J) -> Vec<String> {
    let mut errs = Vec::new();
    if r.s("record_id").is_empty() {
        errs.push("missing record_id".to_string());
    }
    if r.s("key").is_empty() {
        errs.push("missing key".to_string());
    }
    let st = r.s("status");
    if !["active", "superseded", "void"].contains(&st.as_str()) {
        errs.push(format!("status {:?} not in [active, superseded, void]",
                         st));
    }
    let tr = r.s("trust");
    if !["measured", "linked", "asserted"].contains(&tr.as_str()) {
        errs.push(format!("trust {:?} not in [asserted, linked, measured]",
                         tr));
    }
    match r.get("links") {
        Some(J::Arr(_)) | None => {}
        _ => errs.push("links must be a list".to_string()),
    }
    errs
}

fn read_records(root: &Path) -> Result<Vec<J>, String> {
    let p = root.join(DB_REL);
    let mut out = Vec::new();
    if p.exists() {
        for (n, ln) in fs::read_to_string(&p).unwrap_or_default()
                .lines().enumerate() {
            let ln = ln.trim();
            if ln.is_empty() {
                continue;
            }
            let r = P { b: ln.as_bytes(), i: 0 }.parse()
                .map_err(|_| format!("db: {} line {} is not valid JSON - \
                                      repair first (file untouched)",
                                     DB_REL, n + 1))?;
            let errs = validate_record(&r);
            if !errs.is_empty() {
                return Err(format!("db: {} line {} malformed: {} (file \
                                   untouched)", DB_REL, n + 1,
                                   errs.join("; ")));
            }
            out.push(r);
        }
    }
    Ok(out)
}

fn db_effective(root: &Path) -> Result<(BTreeMap<String, J>, Vec<String>),
                                       String> {
    let mut eff = BTreeMap::new();
    let mut order = Vec::new();
    for r in read_records(root)? {
        let id = r.s("record_id");
        if !eff.contains_key(&id) {
            order.push(id.clone());
        }
        eff.insert(id, r);
    }
    Ok((eff, order))
}

fn db_add(root: &Path, opts: &BTreeMap<String, String>) -> i32 {
    let (eff, _) = match db_effective(root) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{}", e);
            return 2;
        }
    };
    if let Some(l) = opts.get("link") {
        for ref_ in l.split(',') {
            let r = ref_.trim();
            if !r.is_empty() && !eff.contains_key(r) {
                eprintln!("db add: link target {} not a known record_id \
                          (exit 2, nothing written)", r);
                return 2;
            }
        }
    }
    let rid = rand_id("rec");
    let links: Vec<J> = opts.get("link").map(|l| {
        l.split(',').map(|s| s.trim()).filter(|s| !s.is_empty())
            .map(|s| J::Str(s.to_string())).collect()
    }).unwrap_or_default();
    let rec = J::Obj(vec![
        ("record_id".into(), J::Str(rid.clone())),
        ("key".into(), J::Str(opts.get("key").cloned().unwrap_or_default())),
        ("value".into(), J::Str(opts.get("value").cloned()
                               .unwrap_or_default())),
        ("trust".into(), J::Str(opts.get("trust").cloned()
                               .unwrap_or_else(|| "asserted".into()))),
        ("source".into(), J::Str(opts.get("source").cloned()
                                .unwrap_or_default())),
        ("links".into(), J::Arr(links)),
        ("status".into(), J::Str("active".into())),
        ("supersedes".into(), J::Nul),
        ("created".into(), J::Str(now())),
    ]);
    let p = root.join(DB_REL);
    if let Some(d) = p.parent() {
        let _ = fs::create_dir_all(d);
    }
    if let Err(e) = write_append_unlocked(&p, &dump(&rec)) {
        eprintln!("db: write refused: {}", e);
        return 1;
    }
    let note = format!("add {}", opts.get("key").cloned()
                      .unwrap_or_default());
    let key = opts.get("key").cloned().unwrap_or_default();
    let val = opts.get("value").cloned().unwrap_or_default();
    let mut cev = base_event("claim.emitted");
    if let J::Obj(v) = &mut cev {
        v.push(("claim".into(), J::Obj(vec![
            ("claim_id".into(), J::Str(rid.clone())),
            ("text".into(), J::Str(format!("db record {}: {} = {}",
                                           rid, key, val))),
            ("claim_type".into(), J::Str("factual".into())),
            ("asserted_at".into(), J::Str(now())),
            ("context".into(), J::Obj(vec![("spine".into(), J::Obj(vec![
                ("kind".into(), J::Str("db-record".into())),
                ("key".into(), J::Str(key.clone())),
            ]))])),
        ])));
    }
    if let Err(e) = append_event(root, cev) {
        eprintln!("db: record claim refused: {}", e);
        return 1;
    }
    if let Err(e) = attest(root, DB_REL, "spine db", &note) {
        eprintln!("db: attestation refused: {}", e);
        return 1;
    }
    cmd_verify(root, false);
    let sha = sha_file(&p);
    println!("{}", dump_ins(&J::Obj(vec![
        ("ok".into(), J::Bool(true)),
        ("record_id".into(), J::Str(rid)),
        ("sha256".into(), J::Str(sha)),
    ])));
    0
}

fn cmd_db(root: &Path, action: &str, rest: &[String]) -> i32 {
    let mut opts: BTreeMap<String, String> = BTreeMap::new();
    let mut positional: Vec<String> = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == "--key" || a == "--value" || a == "--trust" || a == "--source"
                || a == "--link" || a == "--status" {
            opts.insert(a.trim_start_matches("--").to_string(),
                        it.next().cloned().unwrap_or_default());
        } else {
            positional.push(a.clone());
        }
    }
    match action {
        "add" => db_add(root, &opts),
        "get" => {
            let r = match db_effective(root) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };
            let (eff, _) = r;
            let ref_ = positional.first().cloned().unwrap_or_default();
            if let Some(rec) = eff.get(&ref_) {
                println!("{}", dump(rec));
                return 0;
            }
            let hits: Vec<&J> = eff.values()
                .filter(|v| v.s("key") == ref_).collect();
            if hits.len() == 1 {
                println!("{}", dump(hits[0]));
                return 0;
            }
            eprintln!("db get: no record {} (exact record_id or unique key)",
                      ref_);
            2
        }
        "list" => {
            let (eff, order) = match db_effective(root) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };
            let mut n = 0;
            for rid in &order {
                let r = &eff[rid];
                if opts.get("key").map_or(false, |k| *k != r.s("key")) {
                    continue;
                }
                if opts.get("status").map_or(false, |s| *s != r.s("status")) {
                    continue;
                }
                println!("{}  {:<9} {:<11} {:<24} {}", rid,
                         r.s("trust"), r.s("status"), r.s("key"),
                         r.s("value").chars().take(60).collect::<String>());
                n += 1;
            }
            eprintln!("db: {} record(s) visible", n);
            0
        }
        _ => {
            eprintln!("db: unknown action {} (keeper: add|get|list)",
                      action);
            2
        }
    }
}

// ---------------------------------------------------- refs / validators
fn issued_all_ids(root: &Path) -> Vec<String> {
    let mut ids = Vec::new();
    for ev in read_events(root) {
        let cid = ev.get("claim").map(|c| c.s("claim_id"))
            .unwrap_or_default();
        if !cid.is_empty() {
            ids.push(cid);
        }
    }
    ids
}

fn resolve_ref(root: &Path, ref_: &str) -> Result<String, String> {
    let ids = issued_all_ids(root);
    if ids.iter().any(|i| i == ref_) {
        return Ok(ref_.to_string());
    }
    let hits: Vec<String> = ids.iter()
        .filter(|i| i.starts_with(ref_)).cloned().collect();
    if hits.len() == hits.iter().collect::<std::collections::HashSet<_>>()
            .len() && hits.len() == 1 {
        return Ok(hits[0].clone());
    }
    if hits.is_empty() {
        return Err(format!("reject: unknown claim ref {} - no issued claim \
                           carries it; full ids are in TODO.md and `claim \
                           query` (rule R6: refuse loud, never silently \
                           no-op)", ref_));
    }
    let mut seen: Vec<String> = Vec::new();
    for i in hits.iter().rev() {
        if !seen.contains(i) {
            seen.push(i.clone());
        }
    }
    let mut msg = format!("reject: ambiguous claim ref {} - {} claims \
                          match, give more characters (most recent first):",
                          ref_, seen.len());
    for h in seen.iter().take(8) {
        msg.push_str(&format!("\n  {}", h));
    }
    if seen.len() > 8 {
        msg.push_str(&format!("\n  ... and {} more", seen.len() - 8));
    }
    Err(msg)
}

fn dt_ok(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20 && &b[4..5] == b"-" && &b[7..8] == b"-"
        && &b[10..11] == b"T" && &b[19..20] == b"Z"
        && b[..4].iter().all(|c| c.is_ascii_digit())
        && b[5..7].iter().all(|c| c.is_ascii_digit())
        && b[8..10].iter().all(|c| c.is_ascii_digit())
        && b[11..13].iter().all(|c| c.is_ascii_digit())
        && b[14..16].iter().all(|c| c.is_ascii_digit())
        && b[17..19].iter().all(|c| c.is_ascii_digit())
}

fn bad_val(v: &J) -> bool {
    match v {
        J::Nul => true,
        J::Str(s) => s.is_empty(),
        J::Arr(v) => v.is_empty(),
        J::Obj(v) => v.is_empty(),
        _ => false,
    }
}

fn idx(v: &J, i: usize) -> String {
    match v {
        J::Arr(items) => items.get(i).map(|x| x.as_str())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn validate(ev: &J) -> Vec<String> {
    let mut errs: Vec<String> = Vec::new();
    fn req(obj: &J, keys: &[&str], path: &str, errs: &mut Vec<String>) {
        for k in keys {
            match obj.get(k) {
                Some(v) if !bad_val(v) => {}
                _ => errs.push(format!("{} missing {}",
                                       if path.is_empty() {
                                           "/".to_string()
                                       } else {
                                           path.to_string()
                                       }, k)),
            }
        }
    }
    {
        req(ev, &["event_id", "event_type", "event_time", "spec_version",
                  "schema_url", "producer", "digest"], "", &mut errs);
        req(&ev.get("producer").cloned().unwrap_or(J::Nul),
            &["agent_id", "agent_type", "name"], "/producer", &mut errs);
        let et = ev.s("event_type");
        let has_claim = ev.get("claim").map(|c| !bad_val(c))
            .unwrap_or(false);
        let has_ref = ev.get("claim_ref").map(|c| !bad_val(c))
            .unwrap_or(false);
        if !has_claim && !has_ref {
            errs.push("event requires claim or claim_ref".into());
        }
        if et == "claim.emitted" {
            match ev.get("claim") {
                None => errs.push("/claim: claim.emitted requires claim"
                                  .into()),
                Some(c) => {
                    req(c, &["claim_id", "text", "claim_type",
                             "asserted_at"], "/claim", &mut errs);
                    let at = c.s("asserted_at");
                    if !at.is_empty() && !dt_ok(&at) {
                        errs.push("/claim/asserted_at: not date-time"
                                  .into());
                    }
                }
            }
        }
        if et == "claim.verified" {
            req(ev, &["claim_ref", "verification"], "", &mut errs);
            req(&ev.get("verification").cloned().unwrap_or(J::Nul),
                &["verification_result", "verification_method",
                  "claim_status", "verified_at"], "/verification",
                &mut errs);
            req(&ev.get("verification").cloned().unwrap_or(J::Nul)
                .get("validator").cloned().unwrap_or(J::Nul),
                &["agent_id", "agent_type", "name"],
                "/verification/validator", &mut errs);
            let v = ev.get("verification").cloned().unwrap_or(J::Nul);
            if let Some(r) = v.get("verification_result") {
                if !["supported", "contradicted", "inconclusive"]
                        .contains(&r.as_str().as_str()) {
                    errs.push("/verification/verification_result: \
                               unknown".into());
                }
            }
            if let Some(m) = v.get("verification_method") {
                if !["human_review", "model_check", "source_attestation",
                     "consensus", "formal_proof"]
                        .contains(&m.as_str().as_str()) {
                    errs.push("/verification/verification_method: \
                               unknown".into());
                }
            }
            if let Some(st) = v.get("claim_status") {
                if !["active", "disputed", "retracted"]
                        .contains(&st.as_str().as_str()) {
                    errs.push("/verification/claim_status: unknown".into());
                }
            }
        }
        if et == "claim.disputed" {
            req(ev, &["claim_ref"], "", &mut errs);
            let has_e = ev.get("dispute_rationale").map(|x| !bad_val(x))
                .unwrap_or(false);
            let has_ev = ev.get("contradicting_evidence")
                .map(|x| !bad_val(x)).unwrap_or(false);
            if !has_e && !has_ev {
                errs.push("claim.disputed requires dispute_rationale or \
                           contradicting_evidence".into());
            }
        }
        if et == "claim.retracted" {
            req(ev, &["claim_ref", "retracted_at", "retraction_reason"],
                "", &mut errs);
        }
    }
    errs
}

fn append_checked(root: &Path, ev: J) -> Result<J, String> {
    let ev = finalize_event(root, ev);
    let errs = validate(&ev);
    if !errs.is_empty() {
        return Err(format!("reject: {}", errs.join("; ")));
    }
    write_event_line(root, &ev)?;
    Ok(ev)
}

// -------------------------------------------------------------- options
fn parse_opts(rest: &[String])
        -> (BTreeMap<String, String>, Vec<String>) {
    let mut o: BTreeMap<String, String> = BTreeMap::new();
    let mut pos: Vec<String> = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a.starts_with("--") {
            let k = a.trim_start_matches('-').replace('-', "_");
            let take = !matches!(k.as_str(), "force" | "close");
            if take {
                o.insert(k, it.next().cloned().unwrap_or_default());
            } else {
                o.insert(k, "1".into());
            }
        } else {
            pos.push(a.clone());
        }
    }
    (o, pos)
}

fn chars_take(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

// ---------------------------------------------------------------- claim
fn sel_from_spec(spec: &str) -> J {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts[0] {
        "text_span" | "byte_range" => J::Obj(vec![
            ("type".into(), J::Str(parts[0].into())),
            ("start".into(), J::Int(parts.get(1).and_then(|s|
                s.parse().ok()).unwrap_or(0))),
            ("end".into(), J::Int(parts.get(2).and_then(|s|
                s.parse().ok()).unwrap_or(0)))]),
        "page_span" => J::Obj(vec![
            ("type".into(), J::Str("page_span".into())),
            ("page".into(), J::Int(parts.get(1).and_then(|s|
                s.parse().ok()).unwrap_or(0))),
            ("start".into(), J::Int(parts.get(2).and_then(|s|
                s.parse().ok()).unwrap_or(0))),
            ("end".into(), J::Int(parts.get(3).and_then(|s|
                s.parse().ok()).unwrap_or(0)))]),
        "json_pointer" => J::Obj(vec![
            ("type".into(), J::Str("json_pointer".into())),
            ("path".into(), J::Str(spec.splitn(2, ':').nth(1)
                .unwrap_or("").into()))]),
        _ => J::Obj(vec![
            ("type".into(), J::Str("uri_fragment".into())),
            ("fragment".into(), J::Str(parts.get(1).map(|s| s.to_string())
                .unwrap_or_else(|| "full".into())))]),
    }
}

fn json_from_opt(o: &BTreeMap<String, String>, k: &str) -> Option<J> {
    o.get(k).filter(|s| !s.is_empty())
        .and_then(|s| (P { b: s.as_bytes(), i: 0 }).parse().ok())
}

fn cmd_claim(root: &Path, action: &str, rest: &[String]) -> i32 {
    let (o, pos) = parse_opts(rest);
    if action == "emit" {
        let text = match o.get("text") {
            Some(t) => t.clone(),
            None => {
                eprintln!("claim emit: missing --text");
                return 2;
            }
        };
        let ctype = match o.get("type") {
            Some(t) => t.clone(),
            None => {
                eprintln!("claim emit: missing --type");
                return 2;
            }
        };
        let mut claim: Vec<(String, J)> = vec![
            ("claim_id".into(),
             J::Str(o.get("claim_id").cloned().unwrap_or_else(
                 || rand_id("clm")))),
            ("text".into(), J::Str(text)),
            ("claim_type".into(), J::Str(ctype)),
            ("asserted_at".into(), J::Str(now())),
        ];
        if let Some(k) = o.get("kind") {
            claim.push(("trust".into(), J::Str(k.clone())));
        }
        if let Some(c) = json_from_opt(&o, "context") {
            claim.push(("context".into(), c));
        }
        let cid = claim[0].1.as_str();
        let mut ev = base_event("claim.emitted");
        if let J::Obj(v) = &mut ev {
            v.push(("claim".into(), J::Obj(claim)));
            v.push(("sources".into(), J::Arr(vec![])));
            v.push(("evidence".into(), J::Arr(vec![])));
        }
        if let Some(uri) = o.get("source_uri") {
            let sid = rand_id("src");
            let evid = rand_id("ev");
            if let J::Obj(v) = &mut ev {
                if let Some(J::Arr(s)) = v.iter_mut().find(|(k, _)|
                        k == "sources").map(|x| &mut x.1) {
                    s.push(J::Obj(vec![
                        ("source_id".into(), J::Str(sid.clone())),
                        ("uri".into(), J::Str(uri.clone())),
                        ("observed_at".into(), J::Str(now()))]));
                }
                if let Some(J::Arr(s)) = v.iter_mut().find(|(k, _)|
                        k == "evidence").map(|x| &mut x.1) {
                    s.push(J::Obj(vec![
                        ("evidence_id".into(), J::Str(evid)),
                        ("source_ref".into(), J::Str(sid)),
                        ("claim_ref".into(), J::Str(cid.clone())),
                        ("selector".into(), sel_from_spec(
                            o.get("selector").map(|s| s.as_str())
                             .unwrap_or("uri_fragment:full"))),
                        ("support_type".into(), J::Str(
                            o.get("support").cloned()
                             .unwrap_or_else(|| "supports_directly"
                                              .into()))),
                        ("observed_at".into(), J::Str(now()))]));
                }
            }
        }
        match append_checked(root, ev) {
            Ok(ev) => {
                println!("{}", dump_ins(&J::Obj(vec![
                    ("ok".into(), J::Bool(true)),
                    ("event_id".into(), J::Str(ev.s("event_id"))),
                    ("claim_id".into(), J::Str(cid))])));
                0
            }
            Err(e) => {
                eprintln!("{}", e);
                2
            }
        }
    } else if action == "query" {
        let mut state: BTreeMap<String, (String, String, String, String,
                                         String)> = BTreeMap::new();
        for ev in read_events(root) {
            let t = ev.s("event_type");
            if t == "claim.emitted" {
                if let Some(c) = ev.get("claim") {
                    state.insert(c.s("claim_id"), (
                        c.s("claim_type"), "active".into(), "-".into(),
                        c.get("trust").map(|x| x.as_str())
                            .unwrap_or("asserted".into()),
                        chars_take(&c.s("text"), 64)));
                }
            } else if t == "claim.verified" {
                let r = ev.s("claim_ref");
                if let Some(s) = state.get_mut(&r) {
                    if let Some(v) = ev.get("verification") {
                        s.1 = v.s("claim_status");
                        s.2 = format!("{}/{}",
                                      v.s("verification_result"),
                                      v.s("verification_method"));
                    }
                }
            } else if t == "claim.disputed" {
                let r = ev.s("claim_ref");
                if let Some(s) = state.get_mut(&r) {
                    s.1 = "disputed".into();
                }
            } else if t == "claim.retracted" {
                let r = ev.s("claim_ref");
                if let Some(s) = state.get_mut(&r) {
                    s.1 = "retracted".into();
                }
            }
        }
        for (cid, s) in &state {
            if let Some(k) = o.get("kind") {
                if *k != s.3 {
                    continue;
                }
            }
            println!("{:<26}  {:<9} {:<10} {:<8} {:<28} {}", cid, s.0,
                     s.1, s.3, s.2, s.4);
        }
        0
    } else if action == "export" {
        let kinds_raw = o.get("kinds").cloned()
            .unwrap_or_else(|| "measured,linked".into());
        let mut kinds: Vec<String> = kinds_raw.split(',')
            .map(|s| s.to_string()).collect();
        kinds.sort();
        let known = ["asserted", "linked", "measured"];
        let bad: Vec<String> = kinds.iter()
            .filter(|k| !known.contains(&k.as_str())).cloned().collect();
        if !bad.is_empty() {
            eprintln!("claim export: unknown kind(s): {} (have: \
                       asserted, linked, measured)",
                       bad.join(", "));
            return 2;
        }
        let mut n = 0;
        for ev in read_events(root) {
            if ev.s("event_type") != "claim.emitted" {
                continue;
            }
            let c = match ev.get("claim") {
                Some(c) => c,
                None => continue,
            };
            let trust = c.get("trust").map(|x| x.as_str())
                .unwrap_or_else(|| "asserted".into());
            if !kinds.iter().any(|k| k == &trust) {
                continue;
            }
            println!("{}", dump(&J::Obj(vec![
                ("asserted_at".into(), J::Str(c.s("asserted_at"))),
                ("claim_id".into(), J::Str(c.s("claim_id"))),
                ("text".into(), J::Str(c.s("text"))),
                ("claim_type".into(), J::Str(c.s("claim_type"))),
                ("trust".into(), J::Str(trust))])));
            n += 1;
        }
        eprintln!("claim export: {} claim(s) of kind(s) {}", n,
                  kinds.join(","));
        0
    } else if ["verify", "dispute", "retract"].contains(&action) {
        let ref_ = match pos.first() {
            Some(r) => r.clone(),
            None => {
                eprintln!("claim {}: missing claim_ref", action);
                return 2;
            }
        };
        let cid = match resolve_ref(root, &ref_) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{}", e);
                return 2;
            }
        };
        if action == "verify" {
            let method = match o.get("method") {
                Some(m) => m.clone(),
                None => {
                    eprintln!("claim verify: missing --method");
                    return 2;
                }
            };
            let conf: f64 = o.get("confidence").and_then(|c| c.parse().ok())
                .unwrap_or(0.95);
            if method == "model_check" && conf > 0.6 {
                eprintln!("reject: model_check cannot grade above 0.6 - \
                          the loop that wrote an item cannot be its own \
                          judge (rule R4); use human_review/pipeline/\
                          formal_proof with evidence (exit 2: validation \
                          refused)");
                return 2;
            }
            let by = o.get("by").cloned().unwrap_or_default();
            let (vid, vat) = (rand_id("ver"), now());
            let mut v: Vec<(String, J)> = vec![
                ("verification_id".into(), J::Str(vid)),
                ("verification_result".into(),
                 J::Str(o.get("result").cloned().unwrap_or_default()))];
            if method != "model_check" {
                v.push(("confidence".into(), J::Num(conf)));
            }
            v.push(("verification_method".into(), J::Str(method)));
            v.push(("claim_status".into(),
                    J::Str(o.get("status").cloned()
                        .unwrap_or_else(|| "active".into()))));
            let p = producer();
            v.push(("validator".into(), J::Obj(vec![
                ("agent_id".into(), if by.is_empty() {
                    J::Str(p.s("agent_id"))
                } else {
                    J::Str(by.clone())
                }),
                ("agent_type".into(), J::Str(o.get("by_type").cloned()
                    .unwrap_or_else(|| "human".into()))),
                ("name".into(), if by.is_empty() {
                    J::Str(p.s("name"))
                } else {
                    J::Str(by.clone())
                })])));
            v.push(("verified_at".into(), J::Str(vat)));
            let mut ev = base_event("claim.verified");
            if let J::Obj(x) = &mut ev {
                x.push(("claim_ref".into(), J::Str(cid.clone())));
                x.push(("verification".into(), J::Obj(v)));
            }
            match append_checked(root, ev) {
                Ok(ev) => {
                    let (items, _) = todo_state(root);
                    if items.contains_key(&cid) {
                        write_todo_md(root);
                        if let Err(e) = attest(root, "TODO.md",
                                "spine claim", "verdict refresh") {
                            eprintln!("{}", e);
                            return 2;
                        }
                    }
                    println!("{}", dump_ins(&J::Obj(vec![
                        ("ok".into(), J::Bool(true)),
                        ("event_id".into(), J::Str(ev.s("event_id"))),
                        ("claim_ref".into(), J::Str(cid))])));
                    0
                }
                Err(e) => {
                    eprintln!("{}", e);
                    2
                }
            }
        } else {
            let reason = match o.get("reason") {
                Some(r) => r.clone(),
                None => {
                    eprintln!("claim {}: missing --reason", action);
                    return 2;
                }
            };
            let (etype, mut extra): (String, Vec<(String, J)>) =
                if action == "dispute" {
                    ("claim.disputed".into(),
                     vec![("dispute_rationale".into(), J::Str(reason))])
                } else {
                    ("claim.retracted".into(),
                     vec![("retracted_at".into(), J::Str(now())),
                          ("retraction_reason".into(), J::Str(reason))])
                };
            extra.push(("claim_ref".into(), J::Str(cid.clone())));
            let mut ev = base_event(&etype);
            if let J::Obj(x) = &mut ev {
                x.extend(extra);
            }
            match append_checked(root, ev) {
                Ok(ev) => {
                    println!("{}", dump_ins(&J::Obj(vec![
                        ("ok".into(), J::Bool(true)),
                        ("event_id".into(), J::Str(ev.s("event_id"))),
                        ("claim_ref".into(), J::Str(cid))])));
                    0
                }
                Err(e) => {
                    eprintln!("{}", e);
                    2
                }
            }
        }
    } else {
        eprintln!("claim: unknown action {} (keeper: emit|verify|dispute|\
                   retract|query|export)", action);
        2
    }
}

// ------------------------------------------------------------ todo/loop
fn todo_state(root: &Path) -> (BTreeMap<String, (String, String, String,
                                                 f64, bool, String)>, i64) {
    let mut items: BTreeMap<String, (String, String, String, f64, bool,
                                    String)> = BTreeMap::new();
    let mut loop_index: i64 = 0;
    for ev in read_events(root) {
        let c = ev.get("claim").cloned().unwrap_or(J::Nul);
        let sp = c.get("context").and_then(|x| x.get("spine"))
            .cloned().unwrap_or(J::Nul);
        let t = ev.s("event_type");
        if t == "claim.emitted" && sp.s("kind") == "todo" {
            items.insert(c.s("claim_id"), (
                sp.s("what"), sp.s("why"), sp.s("kills"),
                match sp.get("conf") {
                    Some(J::Num(f)) => *f,
                    Some(J::Int(i)) => *i as f64,
                    _ => 0.55,
                },
                true, ev.s("event_time")[..10].to_string()));
        }
        if t == "claim.emitted" && sp.s("kind") == "loop" {
            if let Some(J::Int(i)) = sp.get("index") {
                loop_index = loop_index.max(*i);
            }
        }
        let cid = ev.s("claim_ref");
        if cid.is_empty() {
            continue;
        }
        if let Some(it) = items.get_mut(&cid) {
            if t == "claim.verified" {
                if let Some(v) = ev.get("verification") {
                    let mut conf = match v.get("confidence") {
                        Some(J::Num(f)) => *f,
                        Some(J::Int(i)) => *i as f64,
                        _ => it.3,
                    };
                    if v.s("verification_method") == "model_check" {
                        conf = conf.min(0.6);
                    }
                    it.3 = conf;
                    it.5 = ev.s("event_time")[..10].to_string();
                }
            } else if t == "claim.disputed" {
                it.3 = it.3.min(0.2);
            } else if t == "claim.retracted" {
                it.4 = false;
            }
        }
    }
    (items, loop_index)
}

fn action_for(conf: f64) -> &'static str {
    if conf >= 0.7 {
        "execute"
    } else if conf >= 0.4 {
        "re-probe"
    } else if conf >= 0.2 {
        "defer"
    } else {
        "expired"
    }
}

fn round3(x: f64) -> f64 {
    format!("{:.3}", x).parse::<f64>().unwrap_or(x)
}

fn write_todo_md(root: &Path) {
    let (items, loop_index) = todo_state(root);
    let mut sp = spec_val();
    let tpl = spec_tpl(&mut sp, "TODO.md");
    let rendered = render(&tpl, "TODO");
    let head = match rendered.find("(empty") {
        Some(i) => rendered[..i].to_string(),
        None => rendered.clone(),
    };
    let mut out = head.trim_end().to_string();
    out.push_str("\n\n\n");
    let mut active: Vec<(String, (String, String, String, f64, bool,
                                 String))> = items.iter()
        .filter(|(_, v)| v.4).map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    active.sort_by(|a, b| b.1 .3.partial_cmp(&a.1 .3)
                   .unwrap_or(std::cmp::Ordering::Equal));
    if active.is_empty() {
        out.push_str("(empty - a human or the first justified session \
                      fills this)");
    }
    for (cid, it) in &active {
        out.push_str(&format!("- [ ] {} ({}) | why: {} | kills-it-if: {} \
                              | conf {:.2} | last-touch {}",
                             it.0, cid, it.1, it.2, it.3, it.5));
        out.push('\n');
    }
    out.push_str(&format!("\n# loop {} | actions: >=0.70 execute | \
                          0.40-0.69 re-probe | 0.20-0.39 defer | \
                          <0.20 expired", loop_index));
    let p = root.join("TODO.md");
    let _ = write_text_unlocked(&p, &format!("{}\n", out));
}

fn cmd_todo(root: &Path, action: &str, rest: &[String]) -> i32 {
    let (o, pos) = parse_opts(rest);
    if action == "add" {
        let (items, _) = todo_state(root);
        let n_active = items.values().filter(|v| v.4).count();
        let cap = spec_int(&mut spec_val(), "todo_max_items", 3);
        if n_active as i64 >= cap {
            eprintln!("todo: cap {} reached - retire something first \
                      (disposable by rule R4)", cap);
            return 1;
        }
        let (what, why, kills) = (o.get("what").cloned().unwrap_or_default(
            ), o.get("why").cloned().unwrap_or_default(),
            o.get("kills").cloned().unwrap_or_default());
        let conf: f64 = o.get("conf").and_then(|c| c.parse().ok())
            .unwrap_or(0.55);
        let cid = rand_id("clm");
        let ev = base_event("claim.emitted");
        let mut ev = ev;
        if let J::Obj(v) = &mut ev {
            v.push(("claim".into(), J::Obj(vec![
                ("claim_id".into(), J::Str(cid.clone())),
                ("text".into(), J::Str(format!("TODO: {} | why: {} | \
                                                kills-it-if: {}",
                                               what, why, kills))),
                ("claim_type".into(), J::Str("recommendation".into())),
                ("asserted_at".into(), J::Str(now())),
                ("context".into(), J::Obj(vec![("spine".into(),
                    J::Obj(vec![
                        ("kind".into(), J::Str("todo".into())),
                        ("what".into(), J::Str(what)),
                        ("why".into(), J::Str(why)),
                        ("kills".into(), J::Str(kills)),
                        ("conf".into(), J::Num(conf))]))]))])));
        }
        match append_checked(root, ev) {
            Ok(_) => println!("added: {}", cid),
            Err(e) => {
                eprintln!("{}", e);
                return 2;
            }
        }
    } else if action == "done" || action == "drop" {
        let ref_ = match pos.first() {
            Some(r) => r.clone(),
            None => {
                eprintln!("todo {}: missing claim_ref", action);
                return 2;
            }
        };
        let cid = match resolve_ref(root, &ref_) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{}", e);
                return 2;
            }
        };
        if action == "done" {
            let by = o.get("by").cloned().unwrap_or_default();
            let mut ev = base_event("claim.verified");
            if let J::Obj(v) = &mut ev {
                v.push(("claim_ref".into(), J::Str(cid.clone())));
                v.push(("verification".into(), J::Obj(vec![
                    ("verification_id".into(), J::Str(rand_id("ver"))),
                    ("verification_result".into(),
                     J::Str("supported".into())),
                    ("verification_method".into(),
                     J::Str("human_review".into())),
                    ("claim_status".into(), J::Str("active".into())),
                    ("validator".into(), J::Obj(vec![
                        ("agent_id".into(),
                         J::Str(format!("urn:human:{}", by))),
                        ("agent_type".into(), J::Str("human".into())),
                        ("name".into(), J::Str(by))])),
                    ("verified_at".into(), J::Str(now())),
                    ("confidence".into(), J::Num(0.95))])));
            }
            match append_checked(root, ev) {
                Ok(_) => println!("done (human attested): {}", cid),
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            }
        } else {
            let reason = o.get("reason").cloned().unwrap_or_default();
            let mut ev = base_event("claim.retracted");
            if let J::Obj(v) = &mut ev {
                v.push(("claim_ref".into(), J::Str(cid.clone())));
                v.push(("retracted_at".into(), J::Str(now())));
                v.push(("retraction_reason".into(), J::Str(reason)));
            }
            match append_checked(root, ev) {
                Ok(_) => println!("dropped: {}", cid),
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            }
        }
    } else {
        eprintln!("todo: unknown action {} (keeper: add|done|drop)",
                  action);
        return 2;
    }
    write_todo_md(root);
    if let Err(e) = attest(root, "TODO.md", "spine todo", action) {
        eprintln!("{}", e);
        return 2;
    }
    0
}

fn cmd_loop(root: &Path, rest: &[String]) -> i32 {
    let (o, _) = parse_opts(rest);
    let method = o.get("method").cloned()
        .unwrap_or_else(|| "model_check".into());
    let touch_conf: f64 = o.get("touch_conf").and_then(|c| c.parse().ok())
        .unwrap_or(0.6);
    let touch: Vec<String> = o.get("touch").map(|t| t.split_whitespace()
        .map(|s| s.to_string()).collect()).unwrap_or_default();
    let (items, loop_index) = todo_state(root);
    let idx = loop_index + 1;
    let mut report: Vec<(String, String, f64, String)> = Vec::new();
    let mut cids: Vec<String> = items.iter().filter(|(_, v)| v.4)
        .map(|(k, _)| k.clone()).collect();
    cids.sort();
    for cid in cids {
        let it = items.get(&cid).unwrap().clone();
        let (conf, result) = if touch.contains(&cid) {
            (touch_conf, "supported")
        } else {
            (round3(it.3 * 0.9), "inconclusive")
        };
        let conf = if method == "model_check" { conf.min(0.6) }
            else { conf };
        let mut ev = base_event("claim.verified");
        if let J::Obj(v) = &mut ev {
            v.push(("claim_ref".into(), J::Str(cid.clone())));
            v.push(("verification".into(), J::Obj(vec![
                ("verification_id".into(), J::Str(rand_id("ver"))),
                ("verification_result".into(), J::Str(result.into())),
                ("verification_method".into(), J::Str(method.clone())),
                ("claim_status".into(), J::Str("active".into())),
                ("validator".into(), J::Obj(vec![
                    ("agent_id".into(),
                     J::Str("urn:tool:ai-project-spine".into())),
                    ("agent_type".into(), J::Str("pipeline".into())),
                    ("name".into(), J::Str(format!("spine loop {}",
                        spec_val().get("version").map(|v| v.as_str())
                            .unwrap_or_default())))])),
                ("verified_at".into(), J::Str(now())),
                ("confidence".into(), J::Num(conf))])));
        }
        if let Err(e) = append_checked(root, ev) {
            eprintln!("{}", e);
            return 2;
        }
        let mut act = action_for(conf).to_string();
        if conf < 0.2 {
            let mut ev = base_event("claim.retracted");
            if let J::Obj(v) = &mut ev {
                v.push(("claim_ref".into(), J::Str(cid.clone())));
                v.push(("retracted_at".into(), J::Str(now())));
                v.push(("retraction_reason".into(), J::Str(format!(
                    "expired: conf {:.2} < 0.2 after loop {}", conf,
                    idx))));
            }
            if let Err(e) = append_checked(root, ev) {
                eprintln!("{}", e);
                return 2;
            }
            act = "EXPIRED+retracted".into();
        }
        report.push((cid, it.0, conf, act));
    }
    let mut ev = base_event("claim.emitted");
    if let J::Obj(v) = &mut ev {
        v.push(("claim".into(), J::Obj(vec![
            ("claim_id".into(), J::Str(rand_id("clm"))),
            ("text".into(), J::Str(format!("loop {} closed: {} items \
                                            updated", idx, report.len()))),
            ("claim_type".into(), J::Str("factual".into())),
            ("asserted_at".into(), J::Str(now())),
            ("context".into(), J::Obj(vec![("spine".into(),
                J::Obj(vec![("kind".into(), J::Str("loop".into())),
                            ("index".into(), J::Int(idx))]))]))])));
    }
    if let Err(e) = append_checked(root, ev) {
        eprintln!("{}", e);
        return 2;
    }
    write_todo_md(root);
    if let Err(e) = attest(root, "TODO.md", "spine loop",
                           &format!("loop {}", idx)) {
        eprintln!("{}", e);
        return 2;
    }
    println!("loop {} closed:", idx);
    for (cid, what, conf, act) in &report {
        let w = chars_take(what, 40);
        println!("  {:<30} {:<42} conf {:.2}  -> {}", cid, w, conf, act);
    }
    if report.is_empty() {
        println!("  (no active items)");
    }
    0
}

// --------------------------------------------------------- close/sign
fn cmd_close(root: &Path, rest: &[String]) -> i32 {
    let (o, _) = parse_opts(rest);
    let mut resolved: Vec<String> = Vec::new();
    for ref_ in o.get("supersedes").cloned().unwrap_or_default()
            .split(',') {
        let ref_ = ref_.trim();
        if ref_.is_empty() {
            continue;
        }
        match resolve_ref(root, ref_) {
            Ok(c) => resolved.push(c),
            Err(e) => {
                eprintln!("{}", e);
                return 2;
            }
        }
    }
    let who = producer().s("name");
    let note = o.get("note").cloned().unwrap_or_default();
    let line = format!("Closed {} by {}: supersedes {}{}", now(), who,
                       if resolved.is_empty() {
                           "(nothing)".to_string()
                       } else {
                           resolved.join(", ")
                       },
                       if note.is_empty() {
                           "".to_string()
                       } else {
                           format!(" - {}", note)
                       });
    let p = root.join("STATE.md");
    let mut body = fs::read_to_string(&p).unwrap_or_default();
    if !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str(&format!("\n{}\n", line));
    if let Err(e) = write_text_unlocked(&p, &body) {
        eprintln!("close: {}", e);
        return 1;
    }
    let mut ev = base_event("claim.emitted");
    if let J::Obj(v) = &mut ev {
        v.push(("claim".into(), J::Obj(vec![
            ("claim_id".into(), J::Str(rand_id("clm"))),
            ("text".into(), J::Str(line.clone())),
            ("claim_type".into(), J::Str("factual".into())),
            ("asserted_at".into(), J::Str(now())),
            ("context".into(), J::Obj(vec![("spine".into(),
                J::Obj(vec![("kind".into(), J::Str("close".into())),
                            ("supersedes".into(),
                             J::Arr(resolved.iter().map(|s| J::Str(
                                 s.clone())).collect()))]))]))])));
    }
    if let Err(e) = append_checked(root, ev) {
        eprintln!("{}", e);
        return 2;
    }
    if let Err(e) = attest(root, "STATE.md", "spine close", "close-out") {
        eprintln!("{}", e);
        return 2;
    }
    println!("closed: {}", line);
    0
}

fn cmd_sign(root: &Path, rest: &[String]) -> i32 {
    let (o, pos) = parse_opts(rest);
    let (by, reason) = (o.get("by").cloned().unwrap_or_default(),
                        o.get("reason").cloned().unwrap_or_default());
    let mut files: Vec<String> = pos;
    if files.is_empty() {
        let mut att: Vec<(String, String)> = Vec::new();
        for ev in read_events(root) {
            if let Some(sp) = ev.get("claim").and_then(|c| c.get("context"))
                    .and_then(|c| c.get("spine")) {
                if sp.s("kind") == "attest" {
                    let (p_, h) = (sp.s("path"), sp.s("sha256"));
                    match att.iter_mut().find(|(k, _)| *k == p_) {
                        Some(e) => e.1 = h,
                        None => att.push((p_, h)),
                    }
                }
            }
        }
        files = att.iter().filter(|(rel, h)| {
            let p = root.join(rel);
            p.exists() && sha_file(&p) != *h
        }).map(|(rel, _)| rel.clone()).collect();
    }
    if files.is_empty() {
        println!("sign: nothing drifted");
        return 0;
    }
    for rel in files {
        if let Err(e) = attest(root, &rel, &by, &reason) {
            eprintln!("{}", e);
            return 1;
        }
        println!("signed: {}", rel);
    }
    0
}

// ------------------------------------------------------------ measure
fn run_shell(cmd: &str) -> (i32, String, String) {
    let out = Command::new("sh").arg("-c").arg(cmd).output();
    match out {
        Ok(o) => (o.status.code().unwrap_or(-1),
                  String::from_utf8_lossy(&o.stdout).to_string(),
                  String::from_utf8_lossy(&o.stderr).to_string()),
        Err(e) => (127, String::new(), e.to_string()),
    }
}

fn cmd_measure(root: &Path, action: &str, rest: &[String]) -> i32 {
    let (o, _) = parse_opts(rest);
    if action == "append" {
        let (cmd, unit) = (o.get("command").cloned().unwrap_or_default(),
                           o.get("unit").cloned().unwrap_or_default());
        if cmd.is_empty() || unit.is_empty() || o.get("source_claim")
                .is_none() {
            eprintln!("measure append: --command, --unit and \
                       --source-claim are required");
            return 2;
        }
        let cid = match resolve_ref(root,
                &o.get("source_claim").cloned().unwrap_or_default()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{}", e);
                return 2;
            }
        };
        let (code, stdout, stderr) = run_shell(&cmd);
        if code != 0 {
            eprintln!("measure: command exited {} - refusing to record a \
                       failed measurement (stderr: {})", code,
                      chars_take(&stderr, 200));
            return 2;
        }
        let observed = stdout.trim_end_matches('\n').to_string();
        if observed.is_empty() {
            eprintln!("measure: command exited 0 with empty stdout - a \
                       measurement must observe something; refusing \
                       (exit 2)");
            return 2;
        }
        let value = o.get("value").cloned().unwrap_or_else(
            || observed.clone());
        if value != observed {
            eprintln!("measure: claimed value '{}' != observed '{}' - \
                       measured means reproduced, refusal is the point \
                       (exit 2)", chars_take(&value, 60),
                      chars_take(&observed, 60));
            return 2;
        }
        let mid = rand_id("msr");
        let rec = J::Obj(vec![
            ("m_id".into(), J::Str(mid.clone())),
            ("ts".into(), J::Str(now())),
            ("command".into(), J::Str(cmd.clone())),
            ("value".into(), J::Str(value.clone())),
            ("unit".into(), J::Str(unit.clone())),
            ("observed".into(), J::Str(observed.clone())),
            ("source_claim".into(), J::Str(cid.clone())),
            ("by".into(), J::Str(producer().s("name"))),
        ]);
        let mut em = base_event("claim.emitted");
        if let J::Obj(v) = &mut em {
            v.push(("claim".into(), J::Obj(vec![
                ("claim_id".into(), J::Str(mid.clone())),
                ("text".into(), J::Str(format!("measured {} {} via: {}",
                                               value, unit, cmd))),
                ("claim_type".into(), J::Str("calculation".into())),
                ("asserted_at".into(), J::Str(now())),
                ("trust".into(), J::Str("measured".into())),
                ("context".into(), J::Obj(vec![("spine".into(),
                    J::Obj(vec![("kind".into(),
                                J::Str("measurement".into())),
                                ("m_id".into(), J::Str(mid.clone())),
                                ("source_claim".into(),
                                 J::Str(cid.clone()))]))]))])));
        }
        if let Err(e) = append_checked(root, em) {
            eprintln!("{}", e);
            return 2;
        }
        let path = root.join(MEASURED_REL);
        if let Some(d) = path.parent() {
            let _ = fs::create_dir_all(d);
        }
        let line = {
            let mut v: Vec<(String, J)> = match rec {
                J::Obj(v) => v,
                _ => Vec::new(),
            };
            v.sort_by(|a, b| a.0.cmp(&b.0));
            dump(&J::Obj(v))
        };
        if let Err(e) = write_append_unlocked(&path, &line) {
            eprintln!("measure: write refused: {}", e);
            return 1;
        }
        if let Err(e) = attest(root, MEASURED_REL, "spine measure", &mid) {
            eprintln!("{}", e);
            return 2;
        }
        txlog(root, "measure", 0, &format!("append {}", mid));
        println!("{}", dump(&J::Obj(vec![
            ("ok".into(), J::Bool(true)),
            ("m_id".into(), J::Str(mid)),
            ("sha256".into(), J::Str(sha_file(&path)))])));
        0
    } else if action == "audit" {
        let path = root.join(MEASURED_REL);
        if !path.exists() {
            eprintln!("measure audit: no {} - nothing has been measured \
                       yet", MEASURED_REL);
            return 2;
        }
        let mut bad = 0;
        let mut n = 0;
        for ln in fs::read_to_string(&path).unwrap_or_default()
                .lines() {
            if ln.trim().is_empty() {
                continue;
            }
            let rec = match (P { b: ln.as_bytes(), i: 0 }).parse() {
                Ok(r) => r,
                Err(_) => {
                    eprintln!("measure audit: unparseable row");
                    return 2;
                }
            };
            n += 1;
            let (code, stdout, _) = run_shell(&rec.s("command"));
            let observed = stdout.trim_end_matches('\n').to_string();
            if code != 0 || observed != rec.s("observed") {
                bad += 1;
                println!("DRIFT {}: was '{}' now '{}' (exit {})",
                         rec.s("m_id"), chars_take(&rec.s("observed"), 50),
                         chars_take(&observed, 50), code);
            } else {
                println!("OK   {}  {} {}", rec.s("m_id"),
                         chars_take(&rec.s("value"), 40), rec.s("unit"));
            }
        }
        println!("measure audit: {}/{} reproduced", n - bad, n);
        if bad > 0 {
            1
        } else {
            0
        }
    } else {
        eprintln!("measure: unknown action {} (keeper: append|audit)",
                  action);
        2
    }
}

// --------------------------------------------------------------- init
fn copy_mode(from: &Path, to: &Path) {
    if let Ok(md) = fs::metadata(from) {
        let _ = fs::set_permissions(to,
            fs::Permissions::from_mode(md.permissions().mode() & 0o7777));
    }
}

fn cmd_init(root: &Path, rest: &[String]) -> i32 {
    let (o, _) = parse_opts(rest);
    let name = match o.get("name") {
        Some(n) => n.clone(),
        None => {
            eprintln!("init: --name required");
            return 2;
        }
    };
    let force = o.contains_key("force");
    let golden = o.contains_key("with_golden");
    if root.join(LEDGER_REL).exists() && !force {
        eprintln!("spine: ledger exists in {} (use --force)",
                  root.display());
        return 1;
    }
    let mut sp = spec_val();
    let files = spec_files(&mut sp);
    for rel in &files {
        let dest = root.join(rel);
        if dest.exists() && !force {
            eprintln!("spine: refuses to overwrite {} (use --force)", rel);
            return 1;
        }
    }
    let tpl: Vec<(String, String)> = match sp.get("tpl") {
        Some(J::Obj(v)) => v.iter().map(|(k, x)| (k.clone(), x.as_str()))
            .collect(),
        _ => Vec::new(),
    };
    for rel in &files {
        let t = match tpl.iter().find(|(k, _)| k == rel) {
            Some((_, t)) => t.clone(),
            None => {
                eprintln!("spine: no template for {}", rel);
                return 2;
            }
        };
        let dest = root.join(rel);
        if let Some(d) = dest.parent() {
            let _ = fs::create_dir_all(d);
        }
        if let Err(e) = fs::write(&dest, render(&t, &name)) {
            eprintln!("spine: {}: {}", rel, e);
            return 1;
        }
    }
    let _ = fs::set_permissions(root.join("tests/run.sh"),
        fs::Permissions::from_mode(0o755));
    let tdir = root.join("tools");
    let _ = fs::create_dir_all(&tdir);
    let me = env::current_exe().unwrap_or_default();
    let dest = tdir.join("spine.py");
    if dest.exists() {
        let _ = set_flags_ok(&dest, false);
    }
    if let Err(e) = fs::copy(&me, &dest) {
        eprintln!("spine: copy of keeper failed: {}", e);
        return 1;
    }
    copy_mode(&me, &dest);
    let mut added: Vec<String> = Vec::new();
    for rel in ["harness.md", "tools/REGISTRY.md",
                "docs/measurement-schema.md", "vault/README.md"] {
        let dest = root.join(rel);
        if dest.exists() && !force {
            continue;
        }
        let t = match tpl.iter().find(|(k, _)| k == rel) {
            Some((_, t)) => t.clone(),
            None => continue,
        };
        if let Some(d) = dest.parent() {
            let _ = fs::create_dir_all(d);
        }
        if let Err(e) = fs::write(&dest, render(&t, &name)) {
            eprintln!("spine: {}: {}", rel, e);
            return 1;
        }
        added.push(rel.to_string());
    }
    let _ = fs::create_dir_all(root.join("data/db"));
    let _ = fs::create_dir_all(root.join("docs"));
    let mut extras: Vec<String> = Vec::new();
    if golden {
        for rel in ["tools/golden.sh", "tools/golden.conf"] {
            let t = match tpl.iter().find(|(k, _)| k == rel) {
                Some((_, t)) => t.clone(),
                None => continue,
            };
            let dest = root.join(rel);
            if let Some(d) = dest.parent() {
                let _ = fs::create_dir_all(d);
            }
            if let Err(e) = fs::write(&dest, render(&t, &name)) {
                eprintln!("spine: {}: {}", rel, e);
                return 1;
            }
            extras.push(rel.to_string());
        }
        let _ = fs::set_permissions(root.join("tools/golden.sh"),
            fs::Permissions::from_mode(0o755));
        let p = root.join("DECISIONS.md");
        let mut body = fs::read_to_string(&p).unwrap_or_default();
        body.push_str(&render(GOLDEN_SEED, &name));
        let _ = fs::write(&p, body);
    }
    let mut n_attest: i64 = 0;
    if let J::Arr(rules) = sp.get("rules").cloned().unwrap_or(J::Arr(vec![]))
    {
        for r in &rules {
            let rid = idx(r, 0);
            let text = idx(r, 1);
            let src = idx(r, 2);
            let asof = idx(r, 3);
            let sid = rand_id("src");
            let evid = rand_id("ev");
            let cid = rand_id("clm");
            let mut ev = base_event("claim.emitted");
            if let J::Obj(v) = &mut ev {
                let spine = J::Obj(vec![
                    ("kind".into(), J::Str("rule".into())),
                    ("id".into(), J::Str(rid.clone())),
                    ("true_asof".into(), J::Str(asof)),
                ]);
                let context = J::Obj(vec![("spine".into(), spine)]);
                let claim = J::Obj(vec![
                    ("claim_id".into(), J::Str(cid.clone())),
                    ("text".into(), J::Str(text)),
                    ("claim_type".into(), J::Str("factual".into())),
                    ("asserted_at".into(), J::Str(now())),
                    ("context".into(), context),
                ]);
                let source = J::Obj(vec![
                    ("source_id".into(), J::Str(sid.clone())),
                    ("uri".into(), J::Str(src)),
                    ("observed_at".into(), J::Str(now())),
                ]);
                let selector = J::Obj(vec![
                    ("type".into(), J::Str("uri_fragment".into())),
                    ("fragment".into(), J::Str(rid.clone())),
                ]);
                let evidence = J::Obj(vec![
                    ("evidence_id".into(), J::Str(evid)),
                    ("source_ref".into(), J::Str(sid)),
                    ("claim_ref".into(), J::Str(cid)),
                    ("selector".into(), selector),
                    ("support_type".into(), J::Str("context_only".into())),
                    ("observed_at".into(), J::Str(now())),
                ]);
                v.push(("claim".into(), claim));
                v.push(("sources".into(), J::Arr(vec![source])));
                v.push(("evidence".into(), J::Arr(vec![evidence])));
            }
            match append_checked(root, ev) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            }
        }
    }
    let mut order: Vec<String> = files.clone();
    order.push("tools/spine.py".into());
    order.extend(extras);
    order.extend(added);
    for rel in &order {
        let ver = spec_val().get("version").map(|v| v.as_str())
            .unwrap_or_default();
        let by = format!("spine {}", ver);
        match attest(root, rel, &by, "init") {
            Ok(_) => n_attest += 1,
            Err(e) => {
                eprintln!("{}", e);
                return 2;
            }
        }
    }
    let _ = set_flags_ok(&tdir.join("spine.py"), true);
    txlog(root, "init", 0, &name);
    println!("spine: skeleton ready in {} ({} rules + {} attestations)",
             root.display(), rules_len(&sp), n_attest);
    println!("spine: next -> python3 tools/spine.py verify ; then read \
              AGENTS.md");
    0
}

fn rules_len(sp: &J) -> usize {
    match sp.get("rules") {
        Some(J::Arr(v)) => v.len(),
        _ => 0,
    }
}

fn set_flags_ok(p: &Path, on: bool) -> bool {
    if !p.exists() {
        return false;
    }
    set_flags(p, on);
    true
}


// vault mirror (daemon --mirror): copy vault/** to DEST, content-compare
// first, re-hash after write. Returns (files_copied, bytes_changed).
fn vault_mirror(root: &Path, dest: &Path) -> std::io::Result<(u64, u64)> {
    let src = root.join("vault");
    let mut copied = 0u64;
    let mut changed = 0u64;
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for ent in fs::read_dir(&dir)? {
            let fp = ent?.path();
            if fp.is_dir() {
                stack.push(fp);
                continue;
            }
            let rel = fp.strip_prefix(root).unwrap_or(&fp);
            let tp = dest.join(rel);
            if let Some(d) = tp.parent() {
                fs::create_dir_all(d)?;
            }
            let want = fs::read(&fp)?;
            let have = fs::read(&tp).unwrap_or_default();
            if want != have {
                fs::write(&tp, &want)?;
                fs::set_permissions(&tp,
                    fs::Permissions::from_mode(0o664))?;
                let back = fs::read(&tp)?;
                if back != want {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("mirror rehash mismatch: {}",
                                rel.display())));
                }
                changed += 1;
            }
            copied += 1;
        }
    }
    Ok((copied, changed))
}

// daemon: the supervised heartbeat (criterion 21). Loops verify against
// the tree, appends one JSON line per cycle, exits 3 the moment drift
// appears. LaunchDaemon plists call this; `--iterations` bounds tests.
fn cmd_daemon(root: &Path, rest: &[String]) -> i32 {
    let (o, _) = parse_opts(rest);
    let interval: u64 = o.get("interval").and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let max_runtime: u64 = o
        .get("max_runtime").and_then(|v| v.parse().ok()).unwrap_or(0);
    let iterations: u64 = o.get("iterations")
        .and_then(|v| v.parse().ok()).unwrap_or(0);
    let logp = o.get("log").cloned().unwrap_or_default();
    let mirror = o.get("mirror").cloned().unwrap_or_default();
    let start = std::time::Instant::now();
    let (mut runs, mut drifts) = (0u64, 0u64);
    loop {
        let code = cmd_verify(root, true);
        runs += 1;
        if code != 0 {
            drifts += 1;
        }
        let mut extra = String::new();
        if !mirror.is_empty() && code == 0 {
            match vault_mirror(root, &PathBuf::from(&mirror)) {
                Ok((n, c)) => extra = format!(", \"mirror\": {{\
                           \"changed\": {}, \"files\": {}}}", c, n),
                Err(e) => {
                    drifts += 1;
                    extra = format!(", \"mirror_error\": \"{}\"", e);
                }
            }
        }
        let line = format!("{{\"by\": \"{}\", \"drifts\": {}, \"exit\": {}, \"run\": {}{}, \"ts\": \"{}\"}}",
                          producer().s("name"), drifts, code, runs, extra,
                          now());
        if !logp.is_empty() {
            let lp = PathBuf::from(&logp);
            if let Some(d) = lp.parent() {
                let _ = fs::create_dir_all(d);
            }
            let _ = write_append_unlocked(&lp, &line);
        }
        println!("{}", line);
        if iterations > 0 && runs >= iterations {
            break;
        }
        if max_runtime > 0 && start.elapsed().as_secs() >= max_runtime {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
    if drifts > 0 {
        3
    } else {
        0
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut dir = ".".to_string();
    let mut argv: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--dir" {
            dir = args.get(i + 1).cloned().unwrap_or_else(|| ".".into());
            i += 2;
        } else {
            argv.push(args[i].clone());
            i += 1;
        }
    }
    let root = PathBuf::from(&dir);
    let code = match argv.first().map(|s| s.as_str()) {
        Some("verify") => cmd_verify(&root, true),
        Some("preflight") => {
            let q = argv.get(1).cloned().unwrap_or_default();
            let reason = argv.windows(2).find(|w| w[0] == "--reason")
                .map(|w| w[1].clone());
            cmd_preflight(&root, &q, reason.as_deref())
        }
        Some("db") => {
            let action = argv.get(1).cloned().unwrap_or_default();
            cmd_db(&root, &action, &argv[2.min(argv.len())..])
        }
        Some("claim") => {
            let action = argv.get(1).cloned().unwrap_or_default();
            cmd_claim(&root, &action, &argv[2.min(argv.len())..])
        }
        Some("todo") => {
            let action = argv.get(1).cloned().unwrap_or_default();
            cmd_todo(&root, &action, &argv[2.min(argv.len())..])
        }
        Some("loop") => cmd_loop(&root, &argv[1.min(argv.len())..]),
        Some("close") => cmd_close(&root, &argv[1.min(argv.len())..]),
        Some("sign") => cmd_sign(&root, &argv[1.min(argv.len())..]),
        Some("measure") => {
            let action = argv.get(1).cloned().unwrap_or_default();
            cmd_measure(&root, &action, &argv[2.min(argv.len())..])
        }
        Some("init") => cmd_init(&root, &argv[1.min(argv.len())..]),
        Some("daemon") => cmd_daemon(&root, &argv[1.min(argv.len())..]),
        Some("hash-templates") => {
            println!("{}", hex(&sha256(dump(&generated::spec()).as_bytes())));
            0
        }
        _ => {
            eprintln!("keeper 0.5.0: usage: keeper daemon|verify|\
                      preflight|db|claim|todo|loop|close|sign|\
                      measure|init|hash-templates --dir PATH");
            2
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        assert_eq!(hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn b64url_matches_python_rstrip() {
        assert_eq!(b64url(&[0xfb, 0xff, 0xff]), "-___");
        assert_eq!(b64url(&[0x00]), "AA");
    }

    #[test]
    fn jcs_sorts_by_utf16_units() {
        let j = P { b: br#"{"b":1,"a":2,"A":3}"#, i: 0 }.parse().unwrap();
        assert_eq!(jcs(&j), "{\"A\":3,\"a\":2,\"b\":1}");
    }

    #[test]
    fn jcs_drops_nulls_and_formats_floats() {
        let j = P { b: br#"{"x":null,"y":0.495,"i":5}"#, i: 0 }
            .parse().unwrap();
        assert_eq!(jcs(&j), "{\"i\":5,\"y\":0.495}");
    }
}
