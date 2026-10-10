"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import date
from pathlib import Path

from gatepost import __version__
from gatepost.config import ConfigError, load_config
from gatepost.ingest import IngestError, load_signals
from gatepost.renderer import render_brief
from gatepost.scoring import classify_signals


def _valid_date(raw: str) -> date:
    try:
        return date.fromisoformat(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid date {raw!r}; expected YYYY-MM-DD"
        ) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gatepost")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    brief = sub.add_parser("brief", help="generate a daily brief in Markdown")
    brief.add_argument("--date", required=True, type=_valid_date, help="YYYY-MM-DD")
    brief.add_argument("--input", required=True, type=Path, help="signals JSON file")
    brief.add_argument("--output", required=True, type=Path, help="brief.md path")
    return parser


def run_brief(brief_date: date, input_path: Path, output_path: Path) -> str:
    config = load_config()
    signals = load_signals(input_path)
    elevated, _ = classify_signals(signals, config.elevated_threshold)
    markdown = render_brief(
        brief_date,
        elevated,
        len(signals),
        config.elevated_threshold,
        config.communication,
    )
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise OSError(f"Cannot write output file {output_path}: {exc}") from exc
    return (
        f"gatepost: {brief_date.isoformat()} signals={len(signals)} "
        f"elevated={len(elevated)} threshold={config.elevated_threshold:.2f} "
        f"-> {output_path}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        print(run_brief(args.date, args.input, args.output))
    except (ConfigError, IngestError, OSError) as exc:
        print(f"gatepost: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
