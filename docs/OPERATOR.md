# Operator runbook

Everything here runs on **your machine (Kali)**. The private key is created there and never leaves it.

## Once: set up

```bash
git clone https://github.com/CLS-1000/gatepost && cd gatepost
# signing needs the `cryptography` package; the verifier needs nothing.
# Kali / Debian / Ubuntu (pip is blocked there with "externally-managed-environment"):
python3 -c "import cryptography" 2>/dev/null || sudo apt install -y python3-cryptography
# macOS or other systems: python3 -m venv ~/.gatepost-venv && ~/.gatepost-venv/bin/pip install cryptography
#   then run the tools with ~/.gatepost-venv/bin/python3 instead of python3
bash tools/ci.sh                                  # optional: proves your checkout is intact (needs node + pytest)
```

## Once: create your signing key

```bash
python3 tools/gp_operator.py keygen
```

- Creates `~/.gatepost/op_key.pem` (private, mode 600) and `~/.gatepost/keyring.json`.
- Prints a `key_id` and a public key. **Publish those two lines** somewhere public you control: a GitHub gist, your Substack, your site. That published copy is what makes your seals trustworthy to anyone else.
- **Back up `~/.gatepost/op_key.pem`** to an offline USB stick or your password manager. If it's lost, make a new key and rotate (SCHEMA §10); old seals stay valid under the old key.
- It refuses to overwrite an existing key.

## The Oregon veto pack

```bash
python3 tools/gp_operator.py veto-pack --out or_veto_pack_$(date +%F) --baseline-v1 out/or_veto_pack_DEMO_KEY/records.jsonl
```

- Pulls every measure with a "Governor vetoed." action live from `api.oregonlegislature.gov`, records one `finding` per measure with its evidence, compares against the 2026-09-27 retrieval, seals with your key, and verifies the result.
- About 30 seconds. On a network error it retries, and if it still fails it writes nothing: run it again.
- At the end it prints an **anchor** line. Publish it next to your public key: it's what makes deleting records from the end of the pack detectable.

**What the pack says today (checked 2026-09-29 03:28 UTC):** the API now returns `Vetoed: true` on all 27 measures. On 2026-09-27 at 13:04 UTC it returned `false` on 26 of them, 23 of which were vetoes that stood. The pack records each change. The "before" values come from the 2026-09-27 pack, which was only ever signed with a throwaway key: the pack binds those bytes by hash but can't independently prove what the API said that day. Say so wherever you publish it.

## Checking a pack (what a recipient does)

```bash
python3 bin/verify.py or_veto_pack_2026-09-29/chain --pubkey <your published public key> --anchor or_veto_pack_2026-09-29/anchor.json
```

Exit 0 is a pass. Exit 5 means no key was pinned: not a pass.

## Rotating the key (only if the key is lost or exposed)

See SCHEMA §10: generate a new key, publish it, add it to the keyring with `effective_from` = now, set the old key's `retired_at` to the same instant, seal with the new key from then on.
