"""Configuration loading and validation.

Precedence (highest first): process environment, ``.env`` file, defaults file.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path

from gatepost.models import Communication, Config

REQUIRED_KEYS = ("COMM_TONE", "COMM_LANGUAGE", "COMM_SOURCE_TYPE", "COMM_FORMAT")
THRESHOLD_KEY = "ELEVATED_THRESHOLD"
DEFAULT_THRESHOLD = 0.70
DEFAULTS_ENV_VAR = "GATEPOST_DEFAULTS_FILE"


class ConfigError(ValueError):
    """Raised when configuration is missing or invalid."""


def parse_dotenv(path: Path) -> dict[str, str]:
    """Parse simple KEY=VALUE lines; blank lines and ``#`` comments are ignored."""
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not key.strip():
            raise ConfigError(f"{path}:{number}: expected KEY=VALUE, got {raw!r}")
        values[key.strip()] = value.strip().strip("\"'")
    return values


def load_defaults_file(path: Path) -> dict[str, str]:
    """Load a TOML defaults file (flat table of KEY = value)."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Cannot read defaults file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in defaults file {path}: {exc}") from exc
    return {str(k): str(v) for k, v in data.items()}


def _parse_threshold(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(
            f"{THRESHOLD_KEY} must be a number between 0 and 1, got {raw!r}"
        ) from None
    if not 0.0 <= value <= 1.0:
        raise ConfigError(f"{THRESHOLD_KEY} must be between 0 and 1, got {value}")
    return value


def build_config(values: Mapping[str, str]) -> Config:
    """Validate a flat key/value mapping and build a ``Config``."""
    missing = [k for k in REQUIRED_KEYS if not values.get(k, "").strip()]
    if missing:
        raise ConfigError(
            "Missing required config: "
            + ", ".join(missing)
            + ". Set them in the environment or a .env file (see .env.example)."
        )
    threshold = values.get(THRESHOLD_KEY, "").strip()
    return Config(
        communication=Communication(
            tone=values["COMM_TONE"].strip(),
            language=values["COMM_LANGUAGE"].strip(),
            source_type=values["COMM_SOURCE_TYPE"].strip(),
            format=values["COMM_FORMAT"].strip(),
        ),
        elevated_threshold=(
            _parse_threshold(threshold) if threshold else DEFAULT_THRESHOLD
        ),
    )


def load_config(
    env: Mapping[str, str] | None = None,
    dotenv_path: Path | None = Path(".env"),
    defaults_path: Path | None = None,
) -> Config:
    """Load, merge and validate configuration."""
    env = os.environ if env is None else env
    merged: dict[str, str] = {}
    defaults_path = defaults_path or (
        Path(env[DEFAULTS_ENV_VAR]) if env.get(DEFAULTS_ENV_VAR) else None
    )
    if defaults_path is not None:
        merged.update(load_defaults_file(defaults_path))
    if dotenv_path is not None and dotenv_path.is_file():
        merged.update(parse_dotenv(dotenv_path))
    merged.update(
        {k: v for k, v in env.items() if k in (*REQUIRED_KEYS, THRESHOLD_KEY)}
    )
    return build_config(merged)
