# CANON.md: Gatepost canonical form

`canon_version: "gp-canon/1"` · status: **frozen for G1** · 2026-09-27

This file defines the bytes that get hashed and signed. Once a real chain has been written under `gp-canon/1`, nothing in this file may change. Any change needs a new `canon_version` value, and verifiers must keep accepting old chains under the old rules.

Normative test: `vectors/gatepost-vectors-v1.json`. An implementation conforms when it reproduces every vector. Where this prose and the vectors disagree, the vectors win, and the prose gets fixed.

---

## 1. Value model

A canonical value is exactly one of:

| type | allowed | notes |
|---|---|---|
| null | `null` | distinct from `""` and from an absent key |
| boolean | `true`, `false` | never interchangeable with 0/1 |
| integer | −(2^53 − 1) … +(2^53 − 1) | i.e. ±9007199254740991. No `-0`. |
| string | NFC-normalised Unicode, no lone surrogates | |
| array | ordered list of values | order is significant |
| object | string keys → values | keys unique; order not significant (canonicalisation sorts) |

**There are no floats.** Fractional quantities (scores, amounts, confidence) are carried as decimal strings (section 6). `"0.40"` and `"0.4"` are different strings and hash differently. That is intended: the string records the precision that was claimed.

Null, empty string and absent key are three different states. No implementation may coerce one into another. Vectors `c03a`, `c03b` and `c03c` produce three different hashes.

## 2. Parsing (verifier input)

A verifier reads JSON text and must reject, with the named reason, anything outside the value model:

| input | reason |
|---|---|
| number with a fraction or exponent (`1.0`, `1e2`, `-1.5`) | `float` |
| `-0` | `neg_zero` |
| integer outside ±(2^53 − 1) | `int_range` |
| duplicate key in one object | `dup_key` |
| string or key not in NFC | `non_nfc` |
| unpaired surrogate (raw, or via `\uD800`-style escape) | `lone_surrogate` |
| anything that is not RFC 8259 JSON (NaN, BOM, trailing comma, leading zero, raw control char, trailing data) | `bad_json` |

Checking for surrogates happens after `\uXXXX` escape pairs are joined, so `"\ud83d\ude00"` is one valid code point.

**Do not normalise.** A non-NFC string is rejected, not silently fixed. Normalisation belongs at the producer boundary, before the first hash. A verifier that "fixes" input would be hashing bytes the producer never committed to.

Integers: JavaScript implementations must range-check the literal before converting it to a Number (vector `r05`: `9007199254740992` rounds to a valid-looking double).

## 3. Canonical bytes

`canon(v)` is the UTF-8 encoding (no BOM) of the following serialisation:

- **No whitespace** anywhere outside strings.
- `null`, `true`, `false` as literals.
- **Integers** in shortest decimal form: no leading zeros, no `+`, `-` only for negatives.
- **Arrays**: `[` elements joined by `,` `]`, in their original order.
- **Objects**: `{` members `"key":value` joined by `,` `}`, **sorted by key in Unicode code point order**. Equivalently: compare the keys' UTF-8 bytes. This is *not* UTF-16 code-unit order (the RFC 8785 / JavaScript default). The two differ for keys above U+FFFF. Vector `c10` puts `"｡"` (U+FF61) before `"😀"` (U+1F600); a UTF-16 sort gets it backwards.
- **Strings** in double quotes. Escape exactly these characters and nothing else:

| character | written as |
|---|---|
| `"` | `\"` |
| `\` | `\\` |
| U+0008, U+000C, U+000A, U+000D, U+0009 | `\b` `\f` `\n` `\r` `\t` |
| other U+0000–U+001F | `\u00XX`, **lowercase** hex |

Everything else is emitted as raw UTF-8. That includes `/`, U+007F, U+00AD, U+2028 and all non-ASCII (vectors `c06`–`c09`). Input escapes such as `\u00e9` or `\/` decode on parse, so they never reach the canonical form.

## 4. Record hash and chain

Each record's hashed portion is its **sealed zone** `s`, an object whose fields SCHEMA.md defines. The hash is:

```
h_n = lowercase_hex( SHA-256( canon(s_n) ) )
```

The link is the `prev_hash` field **inside** `s_n`, which must equal `h_(n−1)`. The genesis record (`seq` 0) has `prev_hash` = 64 × `"0"`.

> This replaces the blueprint formula `sha256(hash_(n−1) ‖ canon(sealed_n))`. `prev_hash` already sits in the sealed zone, so concatenating it a second time added nothing and created a second place to get byte-joining wrong.

`inputs_digest` = `"sha256:" + lowercase_hex(SHA-256(canon(inputs)))`. The inputs must themselves be canonical values; a float anywhere in the inputs makes the gate deny with `inputs_invalid` (SCHEMA.md §4).

## 5. Seal signature

A seal is a normal chain record (`kind: "seal"`). Its signature covers its own sealed zone, domain-separated:

```
msg = UTF-8("gatepost/seal/v1\n") ‖ canon(s_seal)
sig = Ed25519(secret_key, msg)            RFC 8032, pure Ed25519 (not ph, not ctx)
```

Because `s_seal` contains `chain_id`, `seq` and `prev_hash`, the signature commits to the whole chain up to that point and to the chain's identity. A seal can't be moved to another chain or another position. `sig` is stored on the line as 128 lowercase hex characters, outside the sealed zone (a signature can't be part of the bytes it signs). `key_id` = the first 16 hex characters of `SHA-256(raw 32-byte public key)`.

- **Producer (signing):** uses the `cryptography` package. That is the only dependency, and it lives only on the side that holds the key. Never hand-rolled.
- **Verifier:** stdlib-only. `ref/ed25519_verify.py` is the RFC 8032 reference verifier. It handles no secrets, so it doesn't need constant-time code. It is cross-checked against both `cryptography` (the signer) and Node/OpenSSL.

The vector chain is signed with a **published test key** (`test_key` in the vector file). It exists so anyone can reproduce the signatures. Never seal a real chain with it.

## 6. The float boundary

Floats come in from callers (SPEC-1's confidence is a Python `float`). There is exactly one sanctioned conversion, and it runs at the producer boundary, never inside the verifier:

```
decimal_from_float(x, places):
    reject NaN / ±Infinity                               → non_finite
    0 ≤ places ≤ 18, else                                → bad_places
    d = the shortest round-trip decimal repr of x        (Python repr(x), JS String(x))
    q = round d to `places` fractional digits, ROUND_HALF_EVEN
    if q is zero, drop the sign
    return fixed-point string: no exponent, exactly `places` fractional digits
```

Why shortest-repr rather than the exact binary value: `2.675` is stored as 2.67499999…, and exact-binary rounding would record `"2.67"` for a value every log and every human reads as 2.675. The shortest repr is what Python and JavaScript both print, and it's reproducible in any language (the JS implementation does it with BigInt digit arithmetic). Half-even means `0.125 → "0.12"` but `2.675 → "2.68"`. The 20 `decimal_vectors` pin this, including `-0.005 → "0.00"` (no negative zero) and `99.995 → "100.00"`.

`places` is fixed per field by the policy that reads it (e.g. confidence at 2). It is not inferred from the input.

## 7. Reason codes for canonicalisation

`float` · `neg_zero` · `int_range` · `dup_key` · `non_nfc` · `lone_surrogate` · `bad_json` · `bad_type` (producer passed a non-JSON type) · `non_finite` · `bad_places`

## 8. Known limits

- **Unicode version drift.** NFC is stable for assigned code points. A string containing a code point unassigned in one implementation's Unicode tables but assigned in another's could, in theory, normalise differently. The two reference implementations use Unicode 14 (Python 3.11) and 15.1 (Node 22 ICU). Producers should reject unassigned code points at the boundary if this ever matters to a customer.
- **Large integers** beyond 2^53 − 1 (e.g. a 64-bit external ID) must be carried as strings.

## 9. Conformance

```
python3 ref/check_vectors.py     # Python: strict parser, canon, schema, pure-Python Ed25519
node    ref/check_vectors.mjs    # JavaScript: independent parser, UTF-8-byte key sort, Node crypto
```

Both report **282 passed, 0 failed** against `gatepost-vectors-v1.json` (276 at G1; six `finding` schema vectors added 2026-09-28). A third implementation, `gpcanon/` in the repo root, passes the same vectors (`test/test_conformance.py`). The two share no code. Each parses `vectors/chain-spec1.publish.jsonl` itself, rather than trusting the generator's copy of the chain.
