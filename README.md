# Gatepost

A single-operator, tamper-evident governance and decision-record engine for Google Workspace and Python environments.

## Standing Rules
- Single-operator architecture: zero multi-tenancy, zero hosted service dependencies, zero SLA burden.
- Append-only: never update or delete against the decision record store.
- Cryptographic integrity: deterministic JSON canonical payload hashing with SHA-256 linear chain and HMAC session head signing.
- Failure-first: unrunnable checks fail loudly and record explicit failure events.

## Directory Layout
- `gas/`: Google Apps Script sources (`clasp`-managed)
- `docs/`: Deployment instructions, schema specifications, and compliance obligation mapping
- `tools/`: Local Python utilities (`index_drive.py`, `build_manifest.py`, etc.)
- `test/`: Python unit/integration test suite

## Development
```bash
# Run test suite
npm test

# Push code to Apps Script project (requires clasp login)
npm run push
```
