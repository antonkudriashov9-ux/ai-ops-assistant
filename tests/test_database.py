import logging

import pytest
import pytest_asyncio
from sqlalchemy import select, text

from app import database as db
from app.config import settings


@pytest_asyncio.fixture
async def storage(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}")
    monkeypatch.setattr(settings, "ENABLE_SQLITE_FALLBACK", False)
    # Current implementation binds the engine on import. Also configure it for the regression baseline.
    if db.engine is not None:
        await db.engine.dispose()
    monkeypatch.setattr(db, "engine", db.create_async_engine(settings.DATABASE_URL))
    monkeypatch.setattr(db, "active_db_url", settings.DATABASE_URL)
    monkeypatch.setattr(
        db, "AsyncSessionLocal", db.sessionmaker(db.engine, class_=db.AsyncSession, expire_on_commit=False)
    )
    await db.init_db()
    yield db
    if db.engine is not None:
        await db.engine.dispose()


@pytest.mark.asyncio
async def test_audit_commits_redacted_data_and_large_telegram_ids(storage):
    success = await storage.log_action(
        987654321012, "password=private OOM", True, "token=private-value", "critical", "linux_os"
    )
    assert success is True
    async with storage.AsyncSessionLocal() as session:
        row = (await session.execute(select(storage.AgentAuditLog))).scalar_one()
        assert row.user_id == 987654321012
        assert "private" not in row.prompt
        assert "private-value" not in row.summary


@pytest.mark.asyncio
async def test_stats_are_scoped_to_engineer(storage):
    await storage.log_action(42, "OOM", True, "OK")
    await storage.log_action(42, "bad", False, "Rejected")
    await storage.log_action(43, "other", True, "Other engineer")
    stats = await storage.get_audit_stats(user_id=42)
    assert stats["total_queries"] == 2
    assert stats["validated_queries"] == 1
    assert stats["failed_queries"] == 1


@pytest.mark.asyncio
async def test_real_database_health(storage):
    health = await storage.check_db_health()
    assert health["healthy"] is True
    assert "SQLite" in health["db_engine"]


@pytest.mark.asyncio
async def test_write_failure_is_visible_and_does_not_leak_input(storage, caplog):
    async with storage.engine.begin() as connection:
        await connection.execute(text("DROP TABLE agent_audit_logs"))
    with caplog.at_level(logging.WARNING):
        assert await storage.log_action(42, "secret-private-prompt", True, "secret-summary") is False
    assert "secret-private-prompt" not in caplog.text
    assert "secret-summary" not in caplog.text
    with pytest.raises(RuntimeError):
        await storage.get_audit_stats()


@pytest.mark.asyncio
async def test_failed_primary_does_not_silently_enable_fallback(storage, monkeypatch, tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("not a directory")
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite+aiosqlite:///{blocked / 'audit.db'}")
    monkeypatch.setattr(settings, "SQLITE_FALLBACK_URL", f"sqlite+aiosqlite:///{tmp_path / 'fallback.db'}")
    with pytest.raises(RuntimeError):
        await storage.init_db()
    assert not (tmp_path / "fallback.db").exists()


@pytest.mark.asyncio
async def test_explicit_fallback_initializes_writable_storage(storage, monkeypatch, tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("not a directory")
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite+aiosqlite:///{blocked / 'audit.db'}")
    monkeypatch.setattr(settings, "ENABLE_SQLITE_FALLBACK", True)
    monkeypatch.setattr(settings, "SQLITE_FALLBACK_URL", f"sqlite+aiosqlite:///{tmp_path / 'fallback.db'}")
    await storage.init_db()
    assert await storage.log_action(42, "OOM", True, "OK") is True
    assert "Fallback" in (await storage.check_db_health())["db_engine"]


@pytest.mark.asyncio
async def test_postgresql_roundtrip_when_configured(monkeypatch):
    import os
    import uuid

    url = os.environ.get("DATABASE_TEST_URL")
    if not url:
        pytest.skip("DATABASE_TEST_URL is not configured")
    monkeypatch.setattr(settings, "DATABASE_URL", url)
    monkeypatch.setattr(settings, "ENABLE_SQLITE_FALLBACK", False)
    await db.init_db()
    user_id = int(uuid.uuid4().int % 10**12) + 10**12
    try:
        assert await db.log_action(user_id, "OOM", True, "PG roundtrip", "critical", "linux_os")
        stats = await db.get_audit_stats(user_id)
        assert stats["total_queries"] == 1
        assert stats["validated_queries"] == 1
        assert (await db.check_db_health())["healthy"]
    finally:
        from sqlalchemy import delete

        async with db.AsyncSessionLocal() as session:
            await session.execute(delete(db.AgentAuditLog).where(db.AgentAuditLog.user_id == user_id))
            await session.commit()
        await db.close_db()
