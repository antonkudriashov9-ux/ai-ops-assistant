"""Executed inside the runtime image by CI, without dev packages or live credentials."""

import asyncio
import os

from app.agent import IncidentAgent
from app.database import check_db_health, close_db, get_audit_stats, init_db, log_action


async def smoke():
    assert os.getuid() != 0
    agent = IncidentAgent()
    try:
        await init_db()
        result = await agent.analyze_incident("kernel: Out of memory", demo=True)
        assert result.is_valid and result.source == "demo"
        assert result.analysis.affected_service == "linux_os"
        assert await log_action(42, "container smoke", True, result.analysis.summary)
        assert (await check_db_health())["healthy"]
        assert (await get_audit_stats(42))["validated_queries"] >= 1
    finally:
        await agent.close()
        await close_db()
    print("Non-root read-only container: database and demo analysis passed")


asyncio.run(smoke())
