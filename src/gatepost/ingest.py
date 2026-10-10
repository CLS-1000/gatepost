"""Signal ingestion from a JSON file."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from gatepost.models import Signal


class IngestError(ValueError):
    """Raised when the input file cannot be read or is invalid."""


_STR_FIELDS = ("id", "source", "category", "summary", "timestamp")


def parse_signal(item: object, index: int) -> Signal:
    where = f"signal #{index}"
    if not isinstance(item, dict):
        raise IngestError(f"{where}: expected an object, got {type(item).__name__}")
    for name in (*_STR_FIELDS, "confidence"):
        if name not in item:
            raise IngestError(f"{where}: missing field '{name}'")
    for name in _STR_FIELDS:
        if not isinstance(item[name], str) or not item[name].strip():
            raise IngestError(f"{where}: '{name}' must be a non-empty string")
    confidence = item["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise IngestError(f"{where}: 'confidence' must be a number")
    if not 0.0 <= confidence <= 1.0:
        raise IngestError(f"{where}: 'confidence' must be between 0 and 1")
    try:
        datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
    except ValueError:
        raise IngestError(f"{where}: 'timestamp' must be ISO 8601") from None
    return Signal(
        id=item["id"],
        source=item["source"],
        category=item["category"],
        confidence=float(confidence),
        summary=item["summary"],
        timestamp=item["timestamp"],
    )


def load_signals(path: str | Path) -> list[Signal]:
    """Load signals from a JSON array (or ``{"signals": [...]}``)."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IngestError(f"Cannot read input file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise IngestError(f"Invalid JSON in {path}: {exc}") from exc
    if isinstance(data, dict) and "signals" in data:
        data = data["signals"]
    if not isinstance(data, list):
        raise IngestError(f"{path}: expected a JSON array of signals")
    signals = [parse_signal(item, i) for i, item in enumerate(data)]
    ids = [s.id for s in signals]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise IngestError(f"Duplicate signal ids: {', '.join(duplicates)}")
    return signals
