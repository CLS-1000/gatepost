from datetime import date

from gatepost.ingest import load_signals
from gatepost.models import Communication, Signal
from gatepost.renderer import render_brief
from gatepost.scoring import classify_signals

COMM = Communication("formal", "en", "official monitoring systems", "markdown")


def test_matches_expected_fixture(fixtures_dir) -> None:
    signals = load_signals(fixtures_dir / "signals_low_confidence.json")
    elevated, _ = classify_signals(signals, 0.70)
    out = render_brief(date(2026, 4, 12), elevated, len(signals), 0.70, COMM)
    assert out == (fixtures_dir / "expected_brief_2026-04-12.md").read_text()


def test_zero_signals_wording() -> None:
    out = render_brief(date(2026, 4, 12), [], 0, 0.70, COMM)
    assert "No elevated signals triggered today" in out
    assert "No signals were harvested" in out


def test_elevated_rendering_and_sections() -> None:
    s = Signal("x1", "src", "cat", 0.9, "Bad thing", "2026-04-12T00:00:00Z")
    out = render_brief(date(2026, 4, 12), [s], 3, 0.70, COMM)
    for section in (
        "## SPEC-1 DAILY BRIEF — 2026-04-12",
        "### Executive Summary",
        "### Elevated Signals",
        "Communication:",
    ):
        assert section in out
    assert "1 of 3" in out
    assert "**x1**" in out
    assert "below threshold" not in out
