import asyncio
import datetime
import logging
from pathlib import Path
from typing import Any

from sqlalchemy import BigInteger, Boolean, Column, DateTime, Integer, String, Text, case, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings
from app.privacy import redact_secrets

logger = logging.getLogger(__name__)
Base = declarative_base()


def utc_now():
    # Preserve the existing timestamp-without-time-zone database column, stored in UTC.
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class AgentAuditLog(Base):
    __tablename__ = "agent_audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    user_id = Column(BigInteger, nullable=False)
    prompt = Column(Text, nullable=False)
    is_valid = Column(Boolean, default=True, nullable=False)
    severity = Column(String(20), nullable=True)
    affected_service = Column(String(50), nullable=True)
    summary = Column(Text, nullable=True)


engine: AsyncEngine | None = None
AsyncSessionLocal = None
active_db_url = settings.DATABASE_URL
_using_fallback = False


def database_label() -> str:
    name = "PostgreSQL" if make_url(active_db_url).get_backend_name() == "postgresql" else "SQLite"
    return name + (" (Fallback)" if _using_fallback else "")


def _create_engine(url: str) -> AsyncEngine:
    parsed = make_url(url)
    if parsed.get_backend_name() == "sqlite":
        if parsed.database and parsed.database != ":memory:":
            Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)
        connect_args = {"timeout": settings.DATABASE_TIMEOUT_SECONDS}
    else:
        connect_args = {
            "timeout": settings.DATABASE_TIMEOUT_SECONDS,
            "command_timeout": settings.DATABASE_TIMEOUT_SECONDS,
        }
    return create_async_engine(
        url, echo=False, pool_pre_ping=True, hide_parameters=True, connect_args=connect_args
    )


async def _open_database(url: str) -> AsyncEngine:
    candidate = _create_engine(url)
    try:
        async with asyncio.timeout(settings.DATABASE_TIMEOUT_SECONDS):
            async with candidate.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
    except BaseException:
        await candidate.dispose()
        raise
    return candidate


async def close_db():
    global engine, AsyncSessionLocal
    previous = engine
    engine, AsyncSessionLocal = None, None
    if previous is not None:
        await previous.dispose()


async def init_db():
    global engine, AsyncSessionLocal, active_db_url, _using_fallback
    await close_db()
    active_db_url, _using_fallback = settings.DATABASE_URL, False
    try:
        engine = await _open_database(active_db_url)
    except Exception:
        if not settings.ENABLE_SQLITE_FALLBACK or settings.SQLITE_FALLBACK_URL == active_db_url:
            logger.error("Primary audit database unavailable; fallback disabled")
            raise RuntimeError("Audit database unavailable") from None
        logger.warning("Primary audit database unavailable; explicit SQLite fallback enabled")
        active_db_url, _using_fallback = settings.SQLITE_FALLBACK_URL, True
        try:
            if make_url(active_db_url).drivername != "sqlite+aiosqlite":
                raise ValueError("Fallback must use SQLite")
            engine = await _open_database(active_db_url)
        except Exception:
            logger.error("Fallback audit database unavailable")
            raise RuntimeError("Audit fallback database unavailable") from None
    AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    logger.info("Audit database initialized: %s", database_label())


async def log_action(
    user_id: int,
    prompt: str,
    is_valid: bool,
    summary: str,
    severity: str = "medium",
    affected_service: str = "app",
) -> bool:
    if AsyncSessionLocal is None:
        logger.warning("Audit write unavailable: database not initialized")
        return False
    try:
        async with asyncio.timeout(settings.DATABASE_TIMEOUT_SECONDS):
            async with AsyncSessionLocal() as session:
                async with session.begin():
                    session.add(
                        AgentAuditLog(
                            user_id=user_id,
                            prompt=redact_secrets(prompt),
                            is_valid=is_valid,
                            severity=severity,
                            affected_service=affected_service,
                            summary=redact_secrets(summary),
                        )
                    )
        return True
    except Exception:
        logger.error("Audit write failed; sensitive details withheld")
        return False


async def check_db_health() -> dict[str, Any]:
    if engine is None:
        return {"healthy": False, "db_engine": database_label()}
    try:
        async with asyncio.timeout(settings.DATABASE_TIMEOUT_SECONDS):
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        return {"healthy": True, "db_engine": database_label()}
    except Exception:
        logger.warning("Audit database health check failed")
        return {"healthy": False, "db_engine": database_label()}


async def get_audit_stats(user_id: int | None = None) -> dict[str, Any]:
    if AsyncSessionLocal is None:
        raise RuntimeError("Audit statistics unavailable")
    query = select(
        func.count(AgentAuditLog.id),
        func.coalesce(func.sum(case((AgentAuditLog.is_valid.is_(True), 1), else_=0)), 0),
    )
    if user_id is not None:
        query = query.where(AgentAuditLog.user_id == user_id)
    try:
        async with asyncio.timeout(settings.DATABASE_TIMEOUT_SECONDS):
            async with AsyncSessionLocal() as session:
                total, valid = (await session.execute(query)).one()
        return {
            "total_queries": total,
            "validated_queries": valid,
            "failed_queries": total - valid,
            "db_engine": database_label(),
        }
    except Exception:
        logger.warning("Audit statistics unavailable")
        raise RuntimeError("Audit statistics unavailable") from None
