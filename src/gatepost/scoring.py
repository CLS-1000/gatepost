"""Signal classification."""

from __future__ import annotations

from collections.abc import Iterable

from gatepost.models import Signal


def is_elevated(signal: Signal, threshold: float) -> bool:
    return signal.confidence >= threshold


def _order(signal: Signal) -> tuple[float, str]:
    return (-signal.confidence, signal.id)


def classify_signals(
    signals: Iterable[Signal], threshold: float
) -> tuple[list[Signal], list[Signal]]:
    """Split signals into (elevated, below_threshold), deterministically ordered
    by descending confidence then id."""
    ordered = sorted(signals, key=_order)
    elevated = [s for s in ordered if is_elevated(s, threshold)]
    below = [s for s in ordered if not is_elevated(s, threshold)]
    return elevated, below
