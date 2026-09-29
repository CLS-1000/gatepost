"""Gatepost canonical form, reference implementation (Python, stdlib only).

Implements CANON.md and SCHEMA.md for canon_version "gp-canon/1".
This module is the Python half of the G1 cross-check; ref/gp_canon.mjs is
the independent JavaScript half. Neither imports the other.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from decimal import Decimal, ROUND_HALF_EVEN, InvalidOperation

CANON_VERSION = "gp-canon/1"
INT_MAX = 2**53 - 1
SEAL_DOMAIN = b"gatepost/seal/v1\n"
GENESIS_PREV = "0" * 64


class CanonError(Exception):
    """Raised with a named reason code (see CANON.md section 7)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# ---------------------------------------------------------------- parsing

def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise CanonError("dup_key", k)
        out[k] = v
    return out


def _reject_float(s):
    raise CanonError("float", s)


def _reject_const(s):
    raise CanonError("bad_json", s)  # NaN / Infinity are not JSON


def _parse_int(s):
    if s == "-0":
        raise CanonError("neg_zero")
    v = int(s)
    if not -INT_MAX <= v <= INT_MAX:
        raise CanonError("int_range", s)
    return v


def strict_loads(text: str):
    """Parse JSON text under CANON.md section 2. Raises CanonError."""
    try:
        v = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_const,
        )
    except CanonError:
        raise
    except (ValueError, RecursionError) as e:
        raise CanonError("bad_json", str(e)) from None
    _check_strings(v)
    return v


def _check_str(s: str):
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonError("lone_surrogate") from None
    if unicodedata.normalize("NFC", s) != s:
        raise CanonError("non_nfc", repr(s))


def _check_strings(v):
    if isinstance(v, str):
        _check_str(v)
    elif isinstance(v, list):
        for x in v:
            _check_strings(x)
    elif isinstance(v, dict):
        for k, x in v.items():
            _check_str(k)
            _check_strings(x)


# ---------------------------------------------------------------- canonical bytes

_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
          "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _esc(s: str) -> str:
    out = []
    for ch in s:
        if ch in _SHORT:
            out.append(_SHORT[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _canon(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if not -INT_MAX <= v <= INT_MAX:
            raise CanonError("int_range", str(v))
        return str(v)
    if isinstance(v, float):
        raise CanonError("float", repr(v))
    if isinstance(v, str):
        _check_str(v)
        return _esc(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_canon(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise CanonError("bad_type", "non-string key")
            _check_str(k)
        # Python str ordering is by code point, which is what CANON.md requires.
        return "{" + ",".join(_esc(k) + ":" + _canon(v[k]) for k in sorted(v)) + "}"
    raise CanonError("bad_type", type(v).__name__)


def canon(v) -> bytes:
    return _canon(v).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def record_hash(sealed: dict) -> str:
    return sha256_hex(canon(sealed))


def inputs_digest(inputs) -> str:
    return "sha256:" + sha256_hex(canon(inputs))


def seal_message(sealed: dict) -> bytes:
    return SEAL_DOMAIN + canon(sealed)


# ---------------------------------------------------------------- float boundary

def decimal_from_float(x: float, places: int) -> str:
    """CANON.md section 6: the only sanctioned float -> decimal-string path."""
    if isinstance(x, bool) or not isinstance(x, (float, int)):
        raise CanonError("bad_type")
    if not 0 <= places <= 18:
        raise CanonError("bad_places")
    if x != x or x in (float("inf"), float("-inf")):
        raise CanonError("non_finite")
    d = Decimal(repr(float(x)))  # shortest round-trip digits, not the exact binary value
    q = d.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_EVEN)
    if q == 0:
        q = abs(q)
    s = format(q, "f")
    return s


# ---------------------------------------------------------------- schema (SCHEMA.md)

KINDS = ("intent", "outcome", "failure", "seal")
COMMON = ("canon_version", "chain_id", "seq", "prev_hash", "kind", "recorded_at", "occurred_at")
FIELDS = {
    "intent": COMMON + ("gate_id", "policy_id", "policy_version", "policy_digest", "subject",
                        "action", "inputs_digest", "decision", "reason", "detail", "actor"),
    "outcome": COMMON + ("gate_id", "result", "detail", "actor"),
    "failure": COMMON + ("gate_id", "failure_code", "detail", "actor"),
    "seal": COMMON + ("key_id",),
}
REASONS = ("policy_allowed", "policy_denied", "policy_unknown", "policy_raised",
           "policy_prefix_mismatch", "inputs_invalid")
NULLABLE = {"policy_version", "policy_digest", "inputs_digest", "detail"}

RE_DOTTED = re.compile(r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$")
RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")
RE_HEX32 = re.compile(r"^[0-9a-f]{32}$")
RE_HEX16 = re.compile(r"^[0-9a-f]{16}$")
RE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RE_VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
RE_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z$")
_DIM = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _ts_ok(s) -> bool:
    if not isinstance(s, str):
        return False
    m = RE_TS.match(s)
    if not m:
        return False
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    if not 1 <= mo <= 12 or h > 23 or mi > 59 or se > 59 or y < 1:
        return False
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    dim = 29 if (mo == 2 and leap) else _DIM[mo - 1]
    return 1 <= d <= dim


def _nonempty(v) -> bool:
    return isinstance(v, str) and len(v) > 0


def _fmt_ok(field: str, v) -> bool:
    if field == "canon_version":
        return isinstance(v, str)
    if field in ("chain_id", "policy_id"):
        return isinstance(v, str) and bool(RE_DOTTED.match(v))
    if field == "seq":
        return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= INT_MAX
    if field == "prev_hash":
        return isinstance(v, str) and bool(RE_HEX64.match(v))
    if field == "kind":
        return v in KINDS
    if field in ("recorded_at", "occurred_at"):
        return _ts_ok(v)
    if field == "gate_id":
        return isinstance(v, str) and bool(RE_HEX32.match(v))
    if field == "policy_version":
        return isinstance(v, str) and bool(RE_VERSION.match(v))
    if field in ("policy_digest", "inputs_digest"):
        return isinstance(v, str) and bool(RE_DIGEST.match(v))
    if field in ("subject", "action", "actor"):
        return _nonempty(v)
    if field == "decision":
        return v in ("allow", "deny")
    if field == "reason":
        return v in REASONS
    if field == "detail":
        return isinstance(v, str)
    if field == "result":
        return v in ("ok", "raised", "skipped")
    if field == "failure_code":
        return v in ("outcome_unwritten",)
    if field == "key_id":
        return isinstance(v, str) and bool(RE_HEX16.match(v))
    return False


def validate_sealed(s) -> list[str]:
    """Return every SCHEMA.md reason code that applies; [] means valid."""
    if not isinstance(s, dict):
        return ["bad_field"]
    errs: list[str] = []
    kind = s.get("kind")
    if kind not in KINDS:
        return ["bad_field"] if "kind" in s else ["missing_field"]
    if s.get("canon_version") != CANON_VERSION and "canon_version" in s:
        errs.append("canon_version_unsupported")
    allowed = FIELDS[kind]
    for f in allowed:
        if f not in s:
            errs.append("missing_field")
    for f in s:
        if f not in allowed:
            errs.append("unknown_field")
    for f in allowed:
        if f not in s or f == "canon_version":
            continue
        v = s[f]
        if v is None:
            if f not in NULLABLE:
                errs.append("null_not_allowed")
            continue
        if not _fmt_ok(f, v):
            errs.append("bad_field")
    if kind == "intent" and not errs:
        errs += _intent_rules(s)
    return sorted(set(errs))


def _intent_rules(s) -> list[str]:
    errs = []
    reason, decision = s["reason"], s["decision"]
    if (decision == "allow") != (reason == "policy_allowed"):
        errs.append("decision_reason_mismatch")
    no_policy = reason in ("policy_unknown", "policy_prefix_mismatch")
    for f in ("policy_version", "policy_digest"):
        if no_policy and s[f] is not None:
            errs.append("null_required")
        if not no_policy and s[f] is None:
            errs.append("null_not_allowed")
    if reason == "inputs_invalid" and s["inputs_digest"] is not None:
        errs.append("null_required")
    if reason != "inputs_invalid" and s["inputs_digest"] is None:
        errs.append("null_not_allowed")
    same = s["policy_id"].split(".")[0] == s["chain_id"].split(".")[0]
    if reason == "policy_prefix_mismatch":
        if same:
            errs.append("policy_prefix_mismatch")
    elif not same:
        errs.append("policy_prefix_mismatch")
    return errs


def key_id(public_key: bytes) -> str:
    return sha256_hex(public_key)[:16]
