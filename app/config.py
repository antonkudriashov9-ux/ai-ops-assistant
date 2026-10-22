from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )

    TELEGRAM_BOT_TOKEN: str = Field(default="", repr=False)
    ALLOWED_TELEGRAM_IDS: list[Annotated[int, Field(gt=0, strict=True)]] = Field(default_factory=list)
    OPENAI_API_KEY: str = Field(default="", repr=False)
    OPENAI_BASE_URL: str | None = None
    OPENAI_MODEL: str = Field(default="gpt-4o-mini", min_length=1, max_length=100)
    ENABLE_MOCK_FALLBACK: bool = False
    LLM_TIMEOUT_SECONDS: float = Field(default=30, gt=0, le=120)
    MAX_INPUT_CHARS: int = Field(default=12000, ge=100, le=20000)
    MAX_CONCURRENT_ANALYSES: int = Field(default=4, ge=1, le=32)
    USER_COOLDOWN_SECONDS: float = Field(default=3, ge=0, le=300)

    DATABASE_URL: str = Field(default="sqlite+aiosqlite:///./data/aiops_audit.db", repr=False)
    ENABLE_SQLITE_FALLBACK: bool = False
    SQLITE_FALLBACK_URL: str = Field(default="sqlite+aiosqlite:///./data/aiops_audit.db", repr=False)
    DATABASE_TIMEOUT_SECONDS: float = Field(default=5, gt=0, le=60)

    @field_validator("DATABASE_URL", "SQLITE_FALLBACK_URL")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        from sqlalchemy.engine import make_url

        try:
            url = make_url(value)
        except Exception:
            raise ValueError("Use a valid asynchronous PostgreSQL or SQLite URL") from None
        if url.drivername not in {"postgresql+asyncpg", "sqlite+aiosqlite"}:
            raise ValueError("Use postgresql+asyncpg:// or sqlite+aiosqlite://")
        return value

    @field_validator("OPENAI_BASE_URL")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        from urllib.parse import urlparse

        if not value:
            return None
        url = urlparse(value)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError("OPENAI_BASE_URL must be an HTTP(S) URL without credentials")
        return value


settings = Settings()
