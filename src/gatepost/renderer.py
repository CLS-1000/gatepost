"""Markdown brief rendering."""

from __future__ import annotations

from datetime import date

from gatepost.models import Communication, Signal

NO_ELEVATED = (
    "No elevated signals triggered today. "
    "All harvested signals were below threshold ({threshold:.2f})."
)


def _summary(total: int, elevated: int, threshold: float) -> str:
    if elevated == 0:
        if total == 0:
            return "No elevated signals triggered today. " "No signals were harvested."
        return NO_ELEVATED.format(threshold=threshold) + f" Signals reviewed: {total}."
    return (
        f"{elevated} of {total} harvested signals met or exceeded "
        f"the elevated threshold ({threshold:.2f})."
    )


def _signal_line(signal: Signal) -> str:
    return (
        f"- **{signal.id}** [{signal.category}] confidence {signal.confidence:.2f} "
        f"— {signal.summary} (source: {signal.source}, {signal.timestamp})"
    )


def render_brief(
    brief_date: date,
    elevated: list[Signal],
    total: int,
    threshold: float,
    communication: Communication,
) -> str:
    lines = [
        f"## SPEC-1 DAILY BRIEF — {brief_date.isoformat()}",
        "",
        "### Executive Summary",
        _summary(total, len(elevated), threshold),
        "",
        "### Elevated Signals",
    ]
    if elevated:
        lines.extend(_signal_line(s) for s in elevated)
    else:
        lines.append("None.")
    lines += [
        "",
        "Communication:",
        f"- tone: {communication.tone}",
        f"- language: {communication.language}",
        f"- source_type: {communication.source_type}",
        f"- format: {communication.format}",
        "",
    ]
    return "\n".join(lines)
