import os
from typing import List, Optional

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseModel as BaseSettings


class Settings(BaseSettings):
    # Telegram Configuration
    TELEGRAM_BOT_TOKEN: str = "mock-telegram-token"
    ALLOWED_TELEGRAM_IDS: List[int] = []

    # LLM Provider Configuration
    OPENAI_API_KEY: str = "mock-openai-key"
    OPENAI_BASE_URL: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"
    ENABLE_MOCK_FALLBACK: bool = True  # Allows offline/demo testing without API credits

    # Database Configuration (PostgreSQL with SQLite fallback for local testing)
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/aiops"
    SQLITE_FALLBACK_URL: str = "sqlite+aiosqlite:///./aiops_audit.db"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
