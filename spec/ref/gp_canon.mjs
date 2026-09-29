// Gatepost canonical form: independent JavaScript implementation (Node >= 18, no dependencies).
// Written from CANON.md / SCHEMA.md, not ported from gp_canon.py. It has its own strict
// JSON parser, its own key ordering (UTF-8 byte order), Node's SHA-256 and Node's Ed25519.
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

export const CANON_VERSION = "gp-canon/1";
const MAX = 9007199254740991n;
export class CanonError extends Error {
  constructor(code, detail = "") { super(detail ? `${code}: ${detail}` : code); this.code = code; }
}

// ------------------------------------------------------------------ strict parser
export function strictParse(text) {
  let i = 0;
  const fail = (code, d) => { throw new CanonError(code, d ?? `at ${i}`); };
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  function value() {
    ws();
    const c = text[i];
    if (c === "{") return object();
    if (c === "[") return array();
    if (c === '"') return string();
    if (c === "-" || (c >= "0" && c <= "9")) return number();
    for (const [lit, v] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(lit, i)) { i += lit.length; return v; }
    }
    fail("bad_json");
  }
  function object() {
    i++; const o = new Map(); ws();
    if (text[i] === "}") { i++; return o; }
    for (;;) {
      ws(); if (text[i] !== '"') fail("bad_json");
      const k = string(); ws();
      if (text[i] !== ":") fail("bad_json"); i++;
      const v = value();
      if (o.has(k)) fail("dup_key", k);
      o.set(k, v); ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "}") { i++; return o; }
      fail("bad_json");
    }
  }
  function array() {
    i++; const a = []; ws();
    if (text[i] === "]") { i++; return a; }
    for (;;) {
      a.push(value()); ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "]") { i++; return a; }
      fail("bad_json");
    }
  }
  function string() {
    i++; let s = "";
    for (;;) {
      if (i >= text.length) fail("bad_json");
      const c = text[i];
      const cu = c.charCodeAt(0);
      if (c === '"') { i++; break; }
      if (cu < 0x20) fail("bad_json", "raw control character");
      if (c === "\\") {
        const e = text[i + 1];
        const map = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (e in map) { s += map[e]; i += 2; continue; }
        if (e === "u") {
          const h = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("bad_json");
          s += String.fromCharCode(parseInt(h, 16)); i += 6; continue;
        }
        fail("bad_json");
      }
      s += c; i++;
    }
    return s; // surrogate and NFC checks happen in checkStr, after pairs are joined
  }
  function number() {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!m) fail("bad_json");
    i += m[0].length;
    if (m[2] || m[3]) fail("float", m[0]);
    if (m[0] === "-0") fail("neg_zero");
    const b = BigInt(m[0]);
    if (b > MAX || b < -MAX) fail("int_range", m[0]);
    return Number(b);
  }
  const v = value(); ws();
  if (i !== text.length) fail("bad_json", "trailing data");
  walkStrings(v);
  return v;
}

function checkStr(s) {
  for (let k = 0; k < s.length; k++) {
    const u = s.charCodeAt(k);
    if (u >= 0xd800 && u <= 0xdbff) {
      const n = s.charCodeAt(k + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) throw new CanonError("lone_surrogate");
      k++;
    } else if (u >= 0xdc00 && u <= 0xdfff) throw new CanonError("lone_surrogate");
  }
  if (s.normalize("NFC") !== s) throw new CanonError("non_nfc", JSON.stringify(s));
}
function walkStrings(v) {
  if (typeof v === "string") checkStr(v);
  else if (Array.isArray(v)) v.forEach(walkStrings);
  else if (v instanceof Map) for (const [k, x] of v) { checkStr(k); walkStrings(x); }
}

// ------------------------------------------------------------------ canonical bytes
function esc(s) {
  let o = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') o += '\\"';
    else if (ch === "\\") o += "\\\\";
    else if (c === 8) o += "\\b";
    else if (c === 12) o += "\\f";
    else if (c === 10) o += "\\n";
    else if (c === 13) o += "\\r";
    else if (c === 9) o += "\\t";
    else if (c < 0x20) o += "\\u" + c.toString(16).padStart(4, "0");
    else o += ch;
  }
  return o + '"';
}
const byUtf8 = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));

function canonStr(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || Object.is(v, -0)) throw new CanonError("float", String(v));
    return String(v);
  }
  if (typeof v === "string") { checkStr(v); return esc(v); }
  if (Array.isArray(v)) return "[" + v.map(canonStr).join(",") + "]";
  const m = v instanceof Map ? v : new Map(Object.entries(v));
  const keys = [...m.keys()];
  keys.forEach(checkStr);
  keys.sort(byUtf8); // UTF-8 byte order == code point order
  return "{" + keys.map((k) => esc(k) + ":" + canonStr(m.get(k))).join(",") + "}";
}
export const canon = (v) => Buffer.from(canonStr(v), "utf8");
export const sha256hex = (b) => createHash("sha256").update(b).digest("hex");

// ------------------------------------------------------------------ float boundary
export function decimalFromFloat(x, places) {
  if (!Number.isFinite(x)) throw new CanonError("non_finite");
  if (!(Number.isInteger(places) && places >= 0 && places <= 18)) throw new CanonError("bad_places");
  const s = String(x); // shortest round-trip digits
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:e([+-]\d+))?$/.exec(s);
  const neg = m[1] === "-";
  const frac = m[3] ?? "";
  let digits = (m[2] + frac).replace(/^0+/, "") || "0";
  const exp = Number(m[4] ?? 0) - frac.length; // value = digits * 10^exp
  const shift = exp + places;
  let n;
  if (shift >= 0) n = BigInt(digits) * 10n ** BigInt(shift);
  else {
    const cut = -shift;
    const padded = digits.padStart(cut + 1, "0");
    const kept = BigInt(padded.slice(0, padded.length - cut));
    const rest = padded.slice(padded.length - cut);
    const half = "5" + "0".repeat(cut - 1);
    const cmp = rest === half ? 0 : rest > half ? 1 : -1; // equal-length digit strings compare lexically
    n = kept + (cmp > 0 || (cmp === 0 && kept % 2n === 1n) ? 1n : 0n);
  }
  let t = n.toString().padStart(places + 1, "0");
  if (places) t = t.slice(0, -places) + "." + t.slice(-places);
  return neg && n !== 0n ? "-" + t : t;
}

// ------------------------------------------------------------------ schema
const COMMON = ["canon_version", "chain_id", "seq", "prev_hash", "kind", "recorded_at", "occurred_at"];
const SHAPE = {
  intent: [...COMMON, "gate_id", "policy_id", "policy_version", "policy_digest", "subject", "action",
    "inputs_digest", "decision", "reason", "detail", "actor"],
  outcome: [...COMMON, "gate_id", "result", "detail", "actor"],
  failure: [...COMMON, "gate_id", "failure_code", "detail", "actor"],
  seal: [...COMMON, "key_id"],
};
const MAYBE_NULL = new Set(["policy_version", "policy_digest", "inputs_digest", "detail"]);
const DOTTED = /^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$/;
const str = (v) => typeof v === "string";
function timestampOk(v) {
  if (!str(v)) return false;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z$/.exec(v);
  if (!m) return false;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  if (y < 1 || mo < 1 || mo > 12 || h > 23 || mi > 59 || se > 59) return false;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  return d >= 1 && d <= dim;
}
const CHECK = {
  chain_id: (v) => str(v) && DOTTED.test(v),
  policy_id: (v) => str(v) && DOTTED.test(v),
  seq: (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0,
  prev_hash: (v) => str(v) && /^[0-9a-f]{64}$/.test(v),
  kind: (v) => typeof v === "string" && Object.hasOwn(SHAPE, v),
  recorded_at: timestampOk,
  occurred_at: timestampOk,
  gate_id: (v) => str(v) && /^[0-9a-f]{32}$/.test(v),
  policy_version: (v) => str(v) && /^[A-Za-z0-9._+-]{1,64}$/.test(v),
  policy_digest: (v) => str(v) && /^sha256:[0-9a-f]{64}$/.test(v),
  inputs_digest: (v) => str(v) && /^sha256:[0-9a-f]{64}$/.test(v),
  subject: (v) => str(v) && v.length > 0,
  action: (v) => str(v) && v.length > 0,
  actor: (v) => str(v) && v.length > 0,
  decision: (v) => v === "allow" || v === "deny",
  reason: (v) => ["policy_allowed", "policy_denied", "policy_unknown", "policy_raised",
    "policy_prefix_mismatch", "inputs_invalid"].includes(v),
  detail: str,
  result: (v) => ["ok", "raised", "skipped"].includes(v),
  failure_code: (v) => v === "outcome_unwritten",
  key_id: (v) => str(v) && /^[0-9a-f]{16}$/.test(v),
};

export function validateSealed(s) {
  if (!(s instanceof Map)) return ["bad_field"];
  if (!s.has("kind")) return ["missing_field"];
  const kind = s.get("kind");
  if (typeof kind !== "string" || !Object.hasOwn(SHAPE, kind)) return ["bad_field"];
  const want = SHAPE[kind];
  const e = new Set();
  if (s.has("canon_version") && s.get("canon_version") !== CANON_VERSION) e.add("canon_version_unsupported");
  for (const f of want) if (!s.has(f)) e.add("missing_field");
  for (const f of s.keys()) if (!want.includes(f)) e.add("unknown_field");
  for (const f of want) {
    if (f === "canon_version" || !s.has(f)) continue;
    const v = s.get(f);
    if (v === null) { if (!MAYBE_NULL.has(f)) e.add("null_not_allowed"); continue; }
    if (!CHECK[f](v)) e.add("bad_field");
  }
  if (kind === "intent" && e.size === 0) {
    const g = (f) => s.get(f);
    if ((g("decision") === "allow") !== (g("reason") === "policy_allowed")) e.add("decision_reason_mismatch");
    const noPolicy = ["policy_unknown", "policy_prefix_mismatch"].includes(g("reason"));
    for (const f of ["policy_version", "policy_digest"]) {
      if (noPolicy && g(f) !== null) e.add("null_required");
      if (!noPolicy && g(f) === null) e.add("null_not_allowed");
    }
    const invalid = g("reason") === "inputs_invalid";
    if (invalid && g("inputs_digest") !== null) e.add("null_required");
    if (!invalid && g("inputs_digest") === null) e.add("null_not_allowed");
    const samePrefix = g("policy_id").split(".")[0] === g("chain_id").split(".")[0];
    if ((g("reason") === "policy_prefix_mismatch") === samePrefix) e.add("policy_prefix_mismatch");
  }
  return [...e].sort();
}

// ------------------------------------------------------------------ seal
export function sealVerify(pubHex, sealed, sigHex) {
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(pubHex, "hex").toString("base64url") }, format: "jwk" });
  const msg = Buffer.concat([Buffer.from("gatepost/seal/v1\n", "utf8"), canon(sealed)]);
  return edVerify(null, msg, key, Buffer.from(sigHex, "hex"));
}
