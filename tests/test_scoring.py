import pytest

from gatepost.config import ConfigError, build_config, load_config
from gatepost.models import Signal
from gatepost.scoring import classify_signals


def sig(id_: str, confidence: float) -> Signal:
    return Signal(id_, "src", "cat", confidence, "s", "2026-04-12T00:00:00Z")


def test_zero_signals() -> None:
    assert classify_signals([], 0.7) == ([], [])


def test_no_elevated() -> None:
    elevated, below = classify_signals([sig("a", 0.1), sig("b", 0.69)], 0.7)
    assert elevated == []
    assert [s.id for s in below] == ["b", "a"]


def test_boundary_is_elevated() -> None:
    elevated, below = classify_signals([sig("a", 0.70), sig("b", 0.6999)], 0.70)
    assert [s.id for s in elevated] == ["a"]
    assert [s.id for s in below] == ["b"]


def test_order_is_deterministic() -> None:
    signals = [sig("b", 0.9), sig("a", 0.9), sig("c", 0.95)]
    assert [s.id for s in classify_signals(signals, 0.7)[0]] == ["c", "a", "b"]
    assert classify_signals(signals, 0.7) == classify_signals(signals[::-1], 0.7)


def test_missing_config_is_actionable() -> None:
    with pytest.raises(ConfigError, match="COMM_TONE.*COMM_FORMAT"):
        build_config({"COMM_LANGUAGE": "en", "COMM_SOURCE_TYPE": "x"})


def test_threshold_default_and_validation(comm_env: dict[str, str]) -> None:
    assert build_config(comm_env).elevated_threshold == 0.70
    with pytest.raises(ConfigError, match="ELEVATED_THRESHOLD"):
        build_config({**comm_env, "ELEVATED_THRESHOLD": "abc"})
    with pytest.raises(ConfigError, match="between 0 and 1"):
        build_config({**comm_env, "ELEVATED_THRESHOLD": "1.5"})


def test_env_overrides_dotenv(tmp_path, comm_env: dict[str, str]) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text("COMM_TONE=casual\nELEVATED_THRESHOLD=0.5\n")
    cfg = load_config(env=comm_env, dotenv_path=dotenv)
    assert cfg.communication.tone == "formal"
    assert cfg.elevated_threshold == 0.5
