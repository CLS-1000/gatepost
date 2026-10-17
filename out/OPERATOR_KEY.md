# Notitia Civica operator signing key

Notitia Civica signs its evidence packs with this Ed25519 key, in the gp-canon/1 format.

| Field | Value |
|---|---|
| key_id | `f7b1282a4a9ccf50` |
| public key (hex) | `c7dbbf86b2e014fad70190276f4e20969743d2fa2bc7c13e48c95fdd91a7d0ad` |
| effective from | 2026-10-02T01:31:32Z |
| retired | — |

The key_id is the first 16 hex characters of the SHA-256 hash of the public key bytes.

## Anchors

An anchor is the last sealed record of a pack. If records are deleted from the end of a pack, the verifier detects it against the published anchor.

### or_veto_pack_2026-10-01 (Oregon veto field)

```json
{
  "chain_id": "proc_track.findings",
  "seq": 55,
  "h": "3db6ad6e56b8086b60a9b9f124e6770aceebeb8ed64b24ce8334f716b5a3f663",
  "sig": "13dcccf7f02e0bd4e1b5dd0397c99654253425808e4b48ef70b846a412bb008c5a65f8ed88cecbf435b28d233975de11771d9878c6cc62944e11351a960afd09"
}
```

## Verify

Requires Python 3.11 or later, standard library only. The verifier is `verify.py` in this folder.

```
python3 verify.py or_veto_pack_2026-10-01/chain \
  --pubkey c7dbbf86b2e014fad70190276f4e20969743d2fa2bc7c13e48c95fdd91a7d0ad \
  --anchor or_veto_pack_2026-10-01/anchor.json
```

Exit code 0 means the pack verifies. Exit code 5 means no key was pinned, which is not a pass.

A pass shows that the records are unchanged since they were sealed. It does not show that they were true when they were written.
