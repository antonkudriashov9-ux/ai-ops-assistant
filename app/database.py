import datetime
import logging
from typing import Dict, Any
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, Integer, BigInteger, String, Text, Boolean, DateTime, select, func
from app.config import settings

logger = logging.getLogger(__name__)
Base = declarative_base()


class AgentAuditLog(Base):
    __tablename__ = "agent_audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    user_id = Column(BigInteger, nullable=False)
    prompt = Column(Text, nullable=False)
    is_valid = Column(Boolean, default=True, nullable=False)
    severity = Column(String(20), nullable=True)
    affected_service = Column(String(50), nullable=True)
    summary = Column(Text, nullable=True)


# Поддержка автоматического переключения на SQLite при недоступности PostgreSQL
active_db_url = settings.DATABASE_URL
engine = create_async_engine(active_db_url, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    global engine, AsyncSessionLocal, active_db_url
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info(f"Database initialized successfully with URL: {active_db_url}")
    except Exception as e:
        logger.warning(f"Failed to connect to primary DB ({e}). Falling back to SQLite local storage.")
        active_db_url = settings.SQLITE_FALLBACK_URL
        engine = create_async_engine(active_db_url, echo=False)
        AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info(f"Fallback SQLite DB initialized successfully at: {active_db_url}")


async def log_action(
    user_id: int,
    prompt: str,
    is_valid: bool,
    summary: str,
    severity: str = "medium",
    affected_service: str = "general"
):
    try:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                log_entry = AgentAuditLog(
                    user_id=user_id,
                    prompt=prompt,
                    is_valid=is_valid,
                    severity=severity,
                    affected_service=affected_service,
                    summary=summary
                )
                session.add(log_entry)
            await session.commit()
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")


async def get_audit_stats() -> Dict[str, Any]:
    """Возвращает агрегированную статистику инцидентов для команды /stats."""
    try:
        async with AsyncSessionLocal() as session:
            total_stmt = select(func.count(AgentAuditLog.id))
            total_res = await session.execute(total_stmt)
            total = total_res.scalar() or 0

            valid_stmt = select(func.count(AgentAuditLog.id)).where(AgentAuditLog.is_valid == True)
            valid_res = await session.execute(valid_stmt)
            valid = valid_res.scalar() or 0

            return {
                "total_queries": total,
                "validated_queries": valid,
                "failed_queries": total - valid,
                "db_engine": "PostgreSQL" if "postgres" in active_db_url else "SQLite (Fallback)"
            }
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return {
            "total_queries": 0,
            "validated_queries": 0,
            "failed_queries": 0,
            "db_engine": "Error: " + str(e)
        }
