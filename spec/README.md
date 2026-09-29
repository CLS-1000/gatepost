# Gatepost G1: record spec + golden vectors

- `CANON.md`: the bytes that are hashed and signed (`gp-canon/1`)
- `SCHEMA.md`: record kinds, field presence, the gate contract, concurrency, truncation, verify reason codes
- `vectors/gatepost-vectors-v1.json`: the normative vectors. `vectors/chain-spec1.publish.jsonl` is the signed sample chain.
- `ref/`: two independent implementations that must agree on every vector (the G1 done-condition)
- `tools/gen_vectors.py`: regenerates the vectors (needs `cryptography` for signing; nothing else does)

```
python3 ref/check_vectors.py    # Python: 282 passed, 0 failed
node    ref/check_vectors.mjs   # Node 18+: 282 passed, 0 failed
```

The vector chain is signed with a **public test key** whose seed is in the vector file. Never seal a real chain with it.

`ref/` is conformance code, not the product. Per the build order, verify.py (G2) and the writer/`gate()` (G3) wait until day 30. `ref/gp_canon.py` and `ref/ed25519_verify.py` are written so verify.py can start from them.
