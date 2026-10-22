import pytest
from pydantic import ValidationError

from app.config import Settings
from app.schemas import IncidentAnalysisSchema


def valid_payload():
    return dict(
        title="OOM",
        severity="critical",
        affected_service="linux_os",
        summary="Process killed",
        recommended_actions=["Check dmesg"],
    )


@pytest.mark.parametrize(
    "change",
    [
        {"title": "   "},
        {"summary": ""},
        {"affected_service": "invented"},
        {"recommended_actions": [""]},
        {"recommended_actions": ["x" * 1001]},
        {"unexpected": "ignored?"},
        {"title": 42},
    ],
)
def test_invalid_model_output_is_blocked(change):
    with pytest.raises(ValidationError):
        IncidentAnalysisSchema(**(valid_payload() | change))


def test_configuration_is_safe_without_environment(monkeypatch):
    for key in ("OPENAI_API_KEY", "ENABLE_MOCK_FALLBACK", "ENABLE_SQLITE_FALLBACK"):
        monkeypatch.delenv(key, raising=False)
    config = Settings(_env_file=None)
    assert config.ENABLE_MOCK_FALLBACK is False
    assert config.ENABLE_SQLITE_FALLBACK is False


@pytest.mark.parametrize(
    "change",
    [
        {"ALLOWED_TELEGRAM_IDS": [0]},
        {"ALLOWED_TELEGRAM_IDS": [-1]},
        {"MAX_INPUT_CHARS": 0},
        {"LLM_TIMEOUT_SECONDS": -1},
        {"MAX_CONCURRENT_ANALYSES": 0},
        {"DATABASE_URL": "postgresql://localhost/db"},
        {"OPENAI_MODEL": "   "},
        {"OPENAI_BASE_URL": "https://provider.test/v1?api_key=private"},
    ],
)
def test_invalid_configuration_is_rejected(change):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **change)
