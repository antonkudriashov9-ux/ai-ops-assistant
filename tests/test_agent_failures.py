import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.agent import IncidentAgent
from app.config import settings


@pytest.fixture
def agent(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "")
    monkeypatch.setattr(settings, "ENABLE_MOCK_FALLBACK", False)
    return IncidentAgent()


def provider(agent, content, finish_reason="stop"):
    response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=content, refusal=None), finish_reason=finish_reason
            )
        ]
    )
    create = AsyncMock(return_value=response)
    agent.client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    agent.has_real_key = True
    return create


@pytest.mark.asyncio
async def test_missing_key_does_not_ignore_disabled_fallback(agent):
    analysis, valid, _ = await agent.analyze_incident("kernel: Out of memory")
    assert analysis is None
    assert valid is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content,finish",
    [
        ("not json", "stop"),
        ("{}", "stop"),
        (None, "stop"),
        (
            json.dumps(
                dict(
                    title="OOM",
                    severity="critical",
                    affected_service="linux_os",
                    summary="Killed",
                    recommended_actions=["dmesg"],
                )
            ),
            "length",
        ),
    ],
)
async def test_bad_provider_output_never_becomes_a_heuristic_success(agent, monkeypatch, content, finish):
    monkeypatch.setattr(settings, "ENABLE_MOCK_FALLBACK", True)
    provider(agent, content, finish)
    analysis, valid, raw = await agent.analyze_incident("OOM")
    assert analysis is None
    assert valid is False
    assert "not json" not in raw


@pytest.mark.asyncio
async def test_provider_failure_does_not_expose_credentials(agent):
    create = provider(agent, "{}")
    create.side_effect = RuntimeError("secret-api-key and private prompt")
    analysis, valid, error = await agent.analyze_incident("OOM")
    assert analysis is None and valid is False
    assert "secret-api-key" not in error


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["", "   ", "x" * 20001])
async def test_bad_input_is_rejected_before_provider(agent, text):
    create = provider(agent, "{}")
    analysis, valid, _ = await agent.analyze_incident(text)
    assert analysis is None and valid is False
    create.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancellation_propagates(agent):
    create = provider(agent, "{}")
    create.side_effect = asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await agent.analyze_incident("OOM")


@pytest.mark.asyncio
async def test_network_refusal_is_not_claimed_to_be_postgresql(agent, monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_MOCK_FALLBACK", True)
    analysis, valid, _ = await agent.analyze_incident("nginx: connection refused to upstream 10.0.0.1:8080")
    assert valid and analysis.affected_service == "network"


@pytest.mark.asyncio
async def test_successful_provider_output_is_validated_and_has_provenance(agent):
    create = provider(
        agent,
        json.dumps(
            dict(
                title="OOM",
                severity="critical",
                affected_service="linux_os",
                summary="Killed",
                recommended_actions=["dmesg"],
            )
        ),
    )
    result = await agent.analyze_incident("api_key=private-value OOM")
    assert result.is_valid and result.source == "llm"
    assert result.analysis.title == "OOM"
    request = create.call_args.kwargs
    assert "private-value" not in request["messages"][1]["content"]
    assert request["response_format"]["json_schema"]["strict"] is True
    assert request["response_format"]["json_schema"]["schema"]["additionalProperties"] is False


@pytest.mark.asyncio
async def test_provider_request_has_an_overall_deadline(agent, monkeypatch):
    async def hung_provider(**kwargs):
        await asyncio.Event().wait()

    create = provider(agent, "{}")
    create.side_effect = hung_provider
    monkeypatch.setattr(settings, "LLM_TIMEOUT_SECONDS", 0.01)
    result = await asyncio.wait_for(agent.analyze_incident("OOM"), timeout=1)
    assert not result.is_valid and result.error == "provider_unavailable"


@pytest.mark.asyncio
async def test_demo_uses_no_provider_even_with_real_key(agent):
    create = provider(agent, "{}")
    result = await agent.analyze_incident("OOM", demo=True)
    assert result.source == "demo"
    assert result.is_valid
    create.assert_not_awaited()


@pytest.mark.asyncio
async def test_real_sdk_request_and_response_contract(agent):
    import httpx2
    from openai import AsyncOpenAI

    requests = []

    def respond(request):
        requests.append(json.loads(request.content))
        return httpx2.Response(
            200,
            json={
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 0,
                "model": "gpt-4o-mini",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "logprobs": None,
                        "message": {
                            "role": "assistant",
                            "refusal": None,
                            "content": json.dumps(
                                dict(
                                    title="OOM",
                                    severity="critical",
                                    affected_service="linux_os",
                                    summary="Kernel killed process",
                                    recommended_actions=["dmesg"],
                                )
                            ),
                        },
                    }
                ],
                "usage": {"prompt_tokens": 20, "completion_tokens": 20, "total_tokens": 40},
            },
        )

    async with AsyncOpenAI(
        api_key="test-key",
        base_url="https://provider.test/v1",
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(respond)),
    ) as client:
        agent.client = client
        agent.has_real_key = True
        result = await agent.analyze_incident("OOM")
    assert result.is_valid and result.analysis.affected_service == "linux_os"
    assert len(requests) == 1
    assert requests[0]["response_format"]["type"] == "json_schema"
    assert requests[0]["max_completion_tokens"] == 2000
