import asyncio
import importlib
import os
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.agent import AnalysisResult
from app.config import settings
from app.schemas import IncidentAnalysisSchema


@pytest.fixture
def bot_module(monkeypatch):
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "123456:abcdefghijklmnopqrstuvwxyz123456789")
    module = importlib.import_module("app.main")
    monkeypatch.setattr(settings, "ALLOWED_TELEGRAM_IDS", [42])
    monkeypatch.setattr(settings, "USER_COOLDOWN_SECONDS", 0)
    monkeypatch.setattr(module, "log_action", AsyncMock(return_value=True))
    return module


def message(text="OOM", user_id=42, chat_type="private"):
    status = SimpleNamespace(edit_text=AsyncMock())
    return SimpleNamespace(
        text=text,
        from_user=SimpleNamespace(id=user_id, is_bot=False),
        chat=SimpleNamespace(type=chat_type),
        answer=AsyncMock(return_value=status),
    ), status


def analysis(**updates):
    return IncidentAnalysisSchema(
        **(
            dict(
                title="OOM",
                severity="critical",
                affected_service="linux_os",
                summary="RAM < 1 & > 0",
                recommended_actions=["Check <service> & logs"],
            )
            | updates
        )
    )


def test_import_does_not_require_a_bot_token():
    env = os.environ | {"TELEGRAM_BOT_TOKEN": "", "OPENAI_API_KEY": ""}
    result = subprocess.run(
        [sys.executable, "-c", "import app.main"], env=env, capture_output=True, timeout=20
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")


def test_empty_allowlist_denies_access(bot_module, monkeypatch):
    monkeypatch.setattr(settings, "ALLOWED_TELEGRAM_IDS", [])
    assert bot_module.check_auth(42) is False


@pytest.mark.asyncio
async def test_group_chat_cannot_send_incident_to_provider(bot_module, monkeypatch):
    analyze = AsyncMock(return_value=AnalysisResult(analysis(), True, "{}"))
    monkeypatch.setattr(bot_module.agent, "analyze_incident", analyze)
    incoming, _ = message(chat_type="group")
    await bot_module.handle_incoming_text(incoming)
    analyze.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_sender_is_handled(bot_module):
    incoming, _ = message()
    incoming.from_user = None
    await bot_module.handle_incoming_text(incoming)
    assert incoming.answer.await_count <= 1


@pytest.mark.asyncio
async def test_model_text_is_escaped_and_source_is_visible(bot_module, monkeypatch):
    monkeypatch.setattr(
        bot_module.agent,
        "analyze_incident",
        AsyncMock(return_value=AnalysisResult(analysis(), True, "{}", source="heuristic")),
    )
    incoming, status = message()
    await bot_module.process_incident_text(incoming, incoming.text)
    sent = status.edit_text.call_args.args[0]
    assert "&lt;service&gt;" in sent
    assert "<service>" not in sent
    assert "Эвристик" in sent
    assert status.edit_text.call_args.kwargs["parse_mode"] == "HTML"


@pytest.mark.asyncio
async def test_audit_failure_blocks_delivery_of_recommendations(bot_module, monkeypatch):
    monkeypatch.setattr(
        bot_module.agent, "analyze_incident", AsyncMock(return_value=AnalysisResult(analysis(), True, "{}"))
    )
    monkeypatch.setattr(bot_module, "log_action", AsyncMock(return_value=False))
    incoming, status = message()
    await bot_module.process_incident_text(incoming, incoming.text)
    assert "Check" not in status.edit_text.call_args.args[0]
    assert "аудит" in status.edit_text.call_args.args[0].lower()


@pytest.mark.asyncio
async def test_internal_exception_is_not_shown(bot_module, monkeypatch):
    monkeypatch.setattr(
        bot_module.agent, "analyze_incident", AsyncMock(side_effect=RuntimeError("secret-token"))
    )
    incoming, status = message()
    await bot_module.process_incident_text(incoming, incoming.text)
    assert "secret-token" not in status.edit_text.call_args.args[0]


@pytest.mark.asyncio
async def test_health_does_not_claim_all_services_are_healthy(bot_module, monkeypatch):
    monkeypatch.setattr(
        bot_module,
        "check_db_health",
        AsyncMock(return_value={"healthy": False, "db_engine": "PostgreSQL"}),
        raising=False,
    )
    incoming, _ = message()
    await bot_module.handle_health(incoming)
    assert "недоступ" in incoming.answer.call_args.args[0].lower()


def test_long_unicode_output_has_bounded_balanced_html_chunks(bot_module):
    chunks = bot_module.render_analysis(
        analysis(summary="🔥<&" * 600, recommended_actions=["<&🔥" * 300] * 6), source="llm"
    )
    assert len(chunks) > 1
    from html.parser import HTMLParser

    class BalancedHTML(HTMLParser):
        def __init__(self):
            super().__init__()
            self.stack = []

        def handle_starttag(self, tag, attrs):
            self.stack.append(tag)

        def handle_endtag(self, tag):
            assert self.stack.pop() == tag

    for chunk in chunks:
        assert len(chunk.encode("utf-16-le")) // 2 <= 4096
        parser = BalancedHTML()
        parser.feed(chunk)
        assert not parser.stack


@pytest.mark.asyncio
async def test_concurrent_duplicate_request_is_rejected(bot_module, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()

    async def slow_analysis(*args, **kwargs):
        entered.set()
        await release.wait()
        return AnalysisResult(analysis(), True, "{}")

    monkeypatch.setattr(bot_module.agent, "analyze_incident", slow_analysis)
    first, _ = message()
    second, _ = message()
    task = asyncio.create_task(bot_module.process_incident_text(first, "OOM"))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        await asyncio.wait_for(bot_module.process_incident_text(second, "OOM"), 1)
        assert "уже" in second.answer.call_args.args[0].lower()
    finally:
        release.set()
        await task


@pytest.mark.asyncio
async def test_real_dispatcher_routes_demo_and_formats_reply(bot_module, monkeypatch):
    from aiogram import Bot
    from aiogram.client.session.base import BaseSession
    from aiogram.methods import EditMessageText, SendMessage
    from aiogram.types import Chat, Message, Update, User

    from app.agent import IncidentAgent

    class CaptureSession(BaseSession):
        def __init__(self):
            super().__init__()
            self.calls = []

        async def close(self):
            pass

        async def make_request(self, bot, method, timeout=None):  # noqa: ASYNC109 - aiogram session API
            self.calls.append(method)
            if isinstance(method, (SendMessage, EditMessageText)):
                return Message(
                    message_id=len(self.calls), date=0, chat=Chat(id=42, type="private"), text=method.text
                ).as_(bot)
            raise AssertionError(f"Unexpected Telegram request: {type(method).__name__}")

        async def stream_content(self, *args, **kwargs):
            if False:
                yield b""

    session = CaptureSession()
    bot = Bot(token="123456:abcdefghijklmnopqrstuvwxyz123456789", session=session)
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "")
    monkeypatch.setattr(bot_module, "agent", IncidentAgent())
    update = Update(
        update_id=1,
        message=Message(
            message_id=1,
            date=0,
            chat=Chat(id=42, type="private"),
            text="/demo",
            from_user=User(id=42, is_bot=False, first_name="Engineer"),
        ),
    )
    try:
        await bot_module.dp.feed_update(bot, update)
    finally:
        await bot.session.close()
    replies = [call.text for call in session.calls if isinstance(call, EditMessageText)]
    assert len(replies) == 1
    assert "Демонстрация" in replies[0]
    assert "linux_os" in replies[0]


@pytest.mark.asyncio
async def test_shutdown_closes_database_and_telegram_if_llm_close_fails(bot_module, monkeypatch):
    monkeypatch.setattr(bot_module, "validate_runtime_config", lambda: None)
    monkeypatch.setattr(bot_module, "init_db", AsyncMock())
    close_db = AsyncMock()
    close_session = AsyncMock()
    monkeypatch.setattr(bot_module, "close_db", close_db)
    monkeypatch.setattr(bot_module.agent, "close", AsyncMock(side_effect=RuntimeError("close failed")))
    fake_bot = SimpleNamespace(session=SimpleNamespace(close=close_session), set_my_commands=AsyncMock())
    monkeypatch.setattr(bot_module, "Bot", lambda **kwargs: fake_bot)
    monkeypatch.setattr(bot_module.dp, "start_polling", AsyncMock())
    with pytest.raises(RuntimeError, match="close failed"):
        await bot_module.main()
    close_db.assert_awaited_once()
    close_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_capacity_limit_rejects_without_waiting_for_another_user(bot_module, monkeypatch):
    monkeypatch.setattr(settings, "ALLOWED_TELEGRAM_IDS", [42, 43])
    monkeypatch.setattr(settings, "MAX_CONCURRENT_ANALYSES", 1)
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def slow_analysis(*args, **kwargs):
        calls.append(args[0])
        entered.set()
        await release.wait()
        return AnalysisResult(analysis(), True, "{}")

    monkeypatch.setattr(bot_module.agent, "analyze_incident", slow_analysis)
    first, _ = message()
    second, _ = message(user_id=43)
    task = asyncio.create_task(bot_module.process_incident_text(first, "OOM"))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        await asyncio.wait_for(bot_module.process_incident_text(second, "network timeout"), 1)
        assert len(calls) == 1
        assert "занят" in second.answer.call_args.args[0]
    finally:
        release.set()
        await task


@pytest.mark.asyncio
async def test_cooldown_prevents_repeated_llm_calls(bot_module, monkeypatch):
    bot_module._last_request.clear()
    monkeypatch.setattr(settings, "USER_COOLDOWN_SECONDS", 300)
    analyze = AsyncMock(return_value=AnalysisResult(analysis(), True, "{}"))
    monkeypatch.setattr(bot_module.agent, "analyze_incident", analyze)
    first, _ = message()
    second, _ = message()
    await bot_module.process_incident_text(first, "OOM")
    await bot_module.process_incident_text(second, "OOM")
    assert analyze.await_count == 1
    assert "частые" in second.answer.call_args.args[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("user_id,chat_type", [(99, "private"), (42, "supergroup")])
async def test_unauthorized_context_is_rejected_before_analysis(bot_module, monkeypatch, user_id, chat_type):
    analyze = AsyncMock()
    monkeypatch.setattr(bot_module.agent, "analyze_incident", analyze)
    incoming, _ = message(user_id=user_id, chat_type=chat_type)
    await bot_module.handle_incoming_text(incoming)
    analyze.assert_not_awaited()
    assert incoming.answer.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("text", [None, "/unknown"])
async def test_unsupported_messages_get_help_without_llm(bot_module, monkeypatch, text):
    analyze = AsyncMock()
    monkeypatch.setattr(bot_module.agent, "analyze_incident", analyze)
    incoming, _ = message(text=text)
    await bot_module.handle_incoming_text(incoming)
    analyze.assert_not_awaited()
    assert "/help" in incoming.answer.call_args.args[0]


@pytest.mark.asyncio
async def test_stats_requests_only_the_current_engineer(bot_module, monkeypatch):
    get_stats = AsyncMock(return_value={"total_queries": 3, "validated_queries": 2, "failed_queries": 1})
    monkeypatch.setattr(bot_module, "get_audit_stats", get_stats)
    incoming, _ = message(text="/stats")
    await bot_module.handle_stats(incoming)
    assert get_stats.call_args.kwargs == {"user_id": 42}
    assert "<b>3</b>" in incoming.answer.call_args.args[0]


@pytest.mark.asyncio
async def test_start_shows_plain_help_with_html_formatting(bot_module):
    incoming, _ = message(text="/start")
    await bot_module.handle_start(incoming)
    assert "/demo" in incoming.answer.call_args.args[0]
    assert incoming.answer.call_args.kwargs["parse_mode"] == "HTML"


@pytest.mark.parametrize("missing", ["allowlist", "token", "provider"])
def test_startup_refuses_missing_required_configuration(bot_module, monkeypatch, missing):
    if missing == "allowlist":
        monkeypatch.setattr(settings, "ALLOWED_TELEGRAM_IDS", [])
    elif missing == "token":
        monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "placeholder")
    else:
        monkeypatch.setattr(bot_module.agent, "has_real_key", False)
        monkeypatch.setattr(settings, "ENABLE_MOCK_FALLBACK", False)
    with pytest.raises(RuntimeError):
        bot_module.validate_runtime_config()
