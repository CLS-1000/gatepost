// Runs every G1 vector through the JavaScript implementation.  node ref/check_vectors.mjs
import { readFileSync } from "node:fs";
import { strictParse, canon, sha256hex, decimalFromFloat, validateSealed, sealVerify, CanonError } from "./gp_canon.mjs";

const V = JSON.parse(readFileSync(new URL("../vectors/gatepost-vectors-v1.json", import.meta.url), "utf8"));
const jsonl = readFileSync(new URL("../vectors/chain-spec1.publish.jsonl", import.meta.url), "utf8");
let pass = 0, fail = 0;
const ok = (cond, id, msg) => { if (cond) pass++; else { fail++; console.log(`FAIL ${id}: ${msg}`); } };

for (const v of V.canon_vectors) {
  const c = canon(strictParse(v.input));
  ok(c.toString("hex") === v.canon_hex, v.id, `canon ${c.toString()} != ${v.canon}`);
  ok(sha256hex(c) === v.sha256, v.id, "sha256");
}
for (const v of V.reject_vectors) {
  let code = "accepted";
  try { strictParse(v.input); } catch (e) { code = e instanceof CanonError ? e.code : "exception:" + e.message; }
  ok(code === v.reason, v.id, `${code} != ${v.reason}`);
}
for (const v of V.decimal_vectors) {
  const got = decimalFromFloat(Number(v.float), v.places);
  ok(got === v.expect, v.id, `${v.float}@${v.places}: ${got} != ${v.expect}`);
}
for (const v of V.schema_vectors) {
  const got = validateSealed(strictParse(v.sealed));
  ok(JSON.stringify(got) === JSON.stringify(v.errors), v.id, `${JSON.stringify(got)} != ${JSON.stringify(v.errors)}`);
}

// chain: parse the JSONL file itself, not the generator's copy of it
const pub = V.test_key.public_key_hex;
ok(sha256hex(Buffer.from(pub, "hex")).slice(0, 16) === V.test_key.key_id, "key_id", "key_id");
const lines = jsonl.split("\n");
ok(lines.pop() === "", "jsonl", "file must end with a newline");
let prev = "0".repeat(64);
lines.forEach((text, n) => {
  const id = `chain#${n}`;
  const exp = V.chain.records[n];
  const line = strictParse(text);
  ok(canon(line).toString("utf8") === text, id, "stored line is not canonical");
  const keys = [...line.keys()];
  ok(keys.every((k) => ["h", "n", "s", "sig"].includes(k)), id, "unexpected line key");
  const s = line.get("s");
  const h = sha256hex(canon(s));
  ok(h === line.get("h") && h === exp.hash, id, "record hash");
  ok(s.get("prev_hash") === prev, id, "prev_hash link");
  ok(s.get("seq") === n, id, "seq");
  ok(s.get("chain_id") === V.chain.chain_id, id, "chain_id");
  ok(validateSealed(s).length === 0, id, `schema ${validateSealed(s)}`);
  if (exp.inputs !== undefined) {
    ok("sha256:" + sha256hex(canon(strictParse(JSON.stringify(exp.inputs)))) === s.get("inputs_digest"), id, "inputs_digest");
  }
  const isSeal = s.get("kind") === "seal";
  ok(isSeal === line.has("sig"), id, "sig present iff seal");
  if (isSeal) {
    ok(sealVerify(pub, s, line.get("sig")), id, "seal signature");
    const tampered = new Map(s); tampered.set("seq", n + 1);
    ok(!sealVerify(pub, tampered, line.get("sig")), id, "tampered seal must not verify");
  }
  prev = h;
});
console.log(`JS: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
