"""gatepost/v1 writer (Python). Stdlib + the openssl CLI for RSA key generation and signing.

Contract with verify.py:
  * every value is hashed as the exact string written (or None); nothing is re-read
  * prev_hash chains from GENESIS; row_hash excludes itself
  * a head is signed at every session close AND before every export (no unsigned tail)
  * keys carry effective_from / retired_at; a head must be signed inside its key's window
"""
import base64, json, os, subprocess, tempfile
from gp_encoding import GENESIS, row_hash, head_stmt, key_id, schema_id

def _ossl(*args, inp=None):
    return subprocess.run(["openssl", *args], input=inp, capture_output=True, check=True).stdout

def generate_key(pem_path, bits=3072):
    """Offline key generation (PKCS#8 PEM, the form Apps Script also accepts)."""
    _ossl("genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}", "-out", pem_path)
    os.chmod(pem_path, 0o600)
    return public_key(pem_path)

def public_key(pem_path):
    n_hex = _ossl("rsa", "-in", pem_path, "-noout", "-modulus").decode().strip().split("=", 1)[1].lower()
    txt = _ossl("rsa", "-in", pem_path, "-noout", "-text").decode()
    e = int(txt.split("publicExponent:")[1].split()[0])
    return {"key_id": key_id(n_hex, e), "n_hex": n_hex, "e": str(e)}

class Chain:
    def __init__(self, columns, schema_name=None):
        if columns[0] != "seq" or columns[-1] != "prev_hash":
            raise ValueError("columns must start with seq and end with prev_hash")
        self.columns = columns + ["row_hash"]
        self.schema_name = schema_name
        self.schema = schema_id(schema_name, columns) if "schema" in columns else None
        self.rows, self.heads, self.keys = [], [], []

    def add_key(self, pub, effective_from, retired_at=None):
        for k in self.keys:
            if k["retired_at"] is None: k["retired_at"] = effective_from
        self.keys.append({**pub, "effective_from": effective_from, "retired_at": retired_at})

    def append(self, values: dict):
        row = {"seq": str(len(self.rows) + 1)}
        if self.schema: row["schema"] = self.schema
        for c in self.columns:
            if c in ("seq", "schema", "prev_hash", "row_hash"): continue
            v = values.get(c)
            if v is not None and not isinstance(v, str):
                raise TypeError(f"{c}: values must be str or None (got {type(v).__name__}); format before writing")
            row[c] = v
        row["prev_hash"] = self.rows[-1]["row_hash"] if self.rows else GENESIS
        row["row_hash"] = row_hash(row, self.columns)
        self.rows.append(row)
        return row

    def sign_head(self, pem_path, session_id, signed_at):
        if not self.rows: raise ValueError("nothing to sign")
        last = self.rows[-1]
        pub = public_key(pem_path)
        stmt = head_stmt(last["row_hash"], last["seq"], signed_at, session_id, pub["key_id"])
        with tempfile.NamedTemporaryFile(delete=False) as f: f.write(stmt); p = f.name
        try: sig = _ossl("dgst", "-sha256", "-sign", pem_path, p)
        finally: os.unlink(p)
        h = {"head_hash": last["row_hash"], "seq": last["seq"], "signed_at": signed_at,
             "session_id": session_id, "key_id": pub["key_id"], "signature": base64.b64encode(sig).decode()}
        self.heads.append(h)
        return h

    def export(self, out_dir, from_seq=1, extra_manifest=None):
        rows = [r for r in self.rows if int(r["seq"]) >= from_seq]
        last = int(rows[-1]["seq"])
        if not any(int(h["seq"]) == last for h in self.heads):
            raise RuntimeError("export would end on an unsigned tail; sign_head() first")
        man = {"format": "gatepost/v1", "columns": self.columns, "row_count": len(rows),
               "chain_head": rows[-1]["row_hash"], "from_seq": str(from_seq), **(extra_manifest or {})}
        if self.schema_name: man["schema_name"] = self.schema_name
        if from_seq > 1:
            anchor = [h for h in self.heads if int(h["seq"]) == from_seq - 1]
            if not anchor: raise RuntimeError(f"no signed head at seq {from_seq-1} to anchor a partial export")
            man["anchor"] = anchor[-1]
        os.makedirs(out_dir, exist_ok=True)
        w = lambda n, s: open(os.path.join(out_dir, n), "w", encoding="utf-8", newline="\n").write(s)
        w("records.jsonl", "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
        w("heads.jsonl", "".join(json.dumps(h) + "\n" for h in self.heads if int(h["seq"]) >= from_seq))
        w("keys.json", json.dumps(self.keys, indent=1))
        w("manifest.json", json.dumps(man, indent=1, ensure_ascii=False))
        return out_dir
