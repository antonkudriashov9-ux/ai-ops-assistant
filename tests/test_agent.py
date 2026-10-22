import pytest
from app.schemas import IncidentAnalysisSchema
from app.agent import IncidentAgent


@pytest.mark.asyncio
async def test_schema_valid_data():
    valid_data = {
        "title": "Kernel OOM Killer",
        "severity": "critical",
        "affected_service": "linux_os",
        "summary": "Process was killed due to insufficient memory.",
        "recommended_actions": ["Check dmesg", "Restart service with memory limits"]
    }
    schema = IncidentAnalysisSchema(**valid_data)
    assert schema.title == "Kernel OOM Killer"
    assert schema.severity == "critical"
    assert schema.affected_service == "linux_os"
    assert len(schema.recommended_actions) == 2


@pytest.mark.asyncio
async def test_agent_oom_detection():
    agent = IncidentAgent()
    oom_log = "kernel: Out of memory: Killed process 9999 (postgres) total-vm:4GB"
    analysis, is_valid, raw = await agent.analyze_incident(oom_log)

    assert is_valid is True
    assert analysis is not None
    assert analysis.severity == "critical"
    assert analysis.affected_service == "linux_os"
    assert len(analysis.recommended_actions) > 0


@pytest.mark.asyncio
async def test_agent_postgres_detection():
    agent = IncidentAgent()
    pg_log = "FATAL: remaining connection slots are reserved for non-replication superuser connections"
    analysis, is_valid, raw = await agent.analyze_incident(pg_log)

    assert is_valid is True
    assert analysis is not None
    assert analysis.affected_service == "postgresql"
