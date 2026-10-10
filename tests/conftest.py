from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def comm_env() -> dict[str, str]:
    return {
        "COMM_TONE": "formal",
        "COMM_LANGUAGE": "en",
        "COMM_SOURCE_TYPE": "official monitoring systems",
        "COMM_FORMAT": "markdown",
    }
