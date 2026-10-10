# Changelog

## 0.1.0

- Add `gatepost brief` CLI: ingest signals JSON, score against `ELEVATED_THRESHOLD`, render a deterministic Markdown daily brief.
- Add config loading/validation (`COMM_*`, `ELEVATED_THRESHOLD`) with fail-fast errors.
- Add `src/` layout packaging, pytest suite, ruff/black, and CI workflow.
