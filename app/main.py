import asyncio
import logging
import time
from html import escape

from aiogram import Bot, Dispatcher, types
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.utils.token import TokenValidationError, validate_token

from app.agent import IncidentAgent
from app.config import settings
from app.database import check_db_health, close_db, get_audit_stats, init_db, log_action
from app.presentation import render_analysis
from app.privacy import redact_secrets

logger = logging.getLogger(__name__)
dp = Dispatcher()
agent = IncidentAgent()
_active_users: set[int] = set()
_last_request: dict[int, float] = {}

HELP_TEXT = (
    "<b>AI Ops Assistant</b>\nПомощник дежурного инженера\n\n"
    "Отправьте фрагмент лога или описание сбоя. Вы получите предварительную оценку "
    "критичности, объяснение и шаги диагностики.\n\n"
    "<b>Что можно отправить</b>\n"
    "• Ошибку из <code>journalctl</code> или <code>dmesg</code>\n"
    "• Логи PostgreSQL, Docker или приложения\n"
    "• Что перестало работать и когда началась проблема\n\n"
    "<b>Команды</b>\n/demo — учебный разбор OOM без обращения к LLM\n"
    "/health — состояние БД и режим анализа\n/stats — ваша статистика запросов\n/help — эта инструкция\n\n"
    "Удалите секреты и персональные данные перед отправкой. "
    "Результат — гипотеза для проверки инженером; бот не выполняет команды."
)
SAMPLE_INCIDENT = (
    "kernel: Out of memory: Killed process 14210 (postgres) total-vm:4231880kB, "
    "anon-rss:3189200kB, file-rss:0kB, shmem-rss:215040kB. oom_score_adj: 0"
)


def check_auth(user_id: int) -> bool:
    return user_id in settings.ALLOWED_TELEGRAM_IDS


async def authorize(message: types.Message) -> bool:
    user = message.from_user
    if user is None or user.is_bot:
        return False
    if not check_auth(user.id):
        await log_action(user.id, "[access_denied]", False, "Access denied", "low", "app")
        await message.answer(
            f"Доступ закрыт. Передайте администратору ваш Telegram ID: <code>{user.id}</code>.",
            parse_mode="HTML",
        )
        return False
    if message.chat.type != "private":
        await log_action(user.id, "[group_rejected]", False, "Private chat required", "low", "app")
        await message.answer("Для работы с инцидентами откройте личный чат с ботом.")
        return False
    return True


async def audit_command(message: types.Message, command: str) -> bool:
    return await log_action(message.from_user.id, command, True, "Bot command", "low", "app")


@dp.message(CommandStart())
@dp.message(Command("help"))
async def handle_start(message: types.Message):
    if not await authorize(message):
        return
    if not await audit_command(message, "/help"):
        await message.answer(
            "Хранилище аудита недоступно. Повторите запрос позже; /health покажет состояние БД."
        )
        return
    await message.answer(HELP_TEXT, parse_mode="HTML")


@dp.message(Command("health"))
async def handle_health(message: types.Message):
    if not await authorize(message):
        return
    health = await check_db_health()
    audited = await audit_command(message, "/health")
    state = (
        "Доступна" if health["healthy"] and audited else "Недоступна — обработка инцидентов приостановлена"
    )
    mode = (
        "LLM настроен; доступность API проверяется при запросе" if agent.has_real_key else "LLM не настроен"
    )
    fallback = "включена" if settings.ENABLE_MOCK_FALLBACK else "выключена"
    await message.answer(
        f"<b>Состояние ассистента</b>\n\n"
        f"База аудита: <b>{state}</b>\nХранилище: {escape(health['db_engine'])}\n\n"
        f"Анализ: {mode}\nЛокальная эвристика: {fallback}\n"
        "Telegram: команда получена. Внешние серверы бот не проверяет.",
        parse_mode="HTML",
    )


@dp.message(Command("stats"))
async def handle_stats(message: types.Message):
    if not await authorize(message):
        return
    if not await audit_command(message, "/stats"):
        await message.answer("Статистика недоступна: не удалось записать действие в аудит.")
        return
    try:
        stats = await get_audit_stats(user_id=message.from_user.id)
    except Exception:
        logger.warning("Audit statistics unavailable")
        await message.answer("Статистика временно недоступна. Повторите запрос позже.")
        return
    await message.answer(
        "<b>Ваш журнал запросов</b>\n\n"
        f"Всего действий: <b>{stats['total_queries']}</b>\n"
        f"Успешных: <b>{stats['validated_queries']}</b>\n"
        f"Отклонённых или с ошибкой: <b>{stats['failed_queries']}</b>\n\n"
        "Счётчики включают команды и анализы. Успешная валидация подтверждает структуру ответа, "
        "а не правильность диагноза.",
        parse_mode="HTML",
    )


@dp.message(Command("demo"))
async def handle_demo(message: types.Message):
    if not await authorize(message):
        return
    await process_incident_text(message, SAMPLE_INCIDENT, demo=True)


@dp.message()
async def handle_incoming_text(message: types.Message):
    if not await authorize(message):
        return
    if not message.text:
        await log_action(message.from_user.id, "[unsupported_message]", False, "Text required", "low", "app")
        await message.answer(
            "Отправьте лог текстом. Файлы, голосовые сообщения и изображения пока не анализируются. /help — примеры."
        )
        return
    if message.text.startswith("/"):
        await log_action(message.from_user.id, "[unknown_command]", False, "Unknown command", "low", "app")
        await message.answer("Неизвестная команда. /help — список команд.")
        return
    await process_incident_text(message, message.text)


async def deliver(message: types.Message, status: types.Message, chunks: list[str]):
    try:
        await status.edit_text(chunks[0], parse_mode="HTML")
    except TelegramBadRequest:
        await message.answer(chunks[0], parse_mode="HTML")
    for chunk in chunks[1:]:
        await message.answer(chunk, parse_mode="HTML")


async def process_incident_text(message: types.Message, raw_text: str, *, demo: bool = False):
    if not message.from_user or not check_auth(message.from_user.id) or message.chat.type != "private":
        return
    user_id = message.from_user.id
    if not raw_text.strip() or len(raw_text) > settings.MAX_INPUT_CHARS:
        await log_action(user_id, "[input_rejected]", False, "Input size invalid", "low", "app")
        await message.answer(
            f"Отправьте непустой фрагмент лога до {settings.MAX_INPUT_CHARS} символов. Длинный лог разделите на части."
        )
        return
    if user_id in _active_users:
        await log_action(user_id, "[busy]", False, "Duplicate active request", "low", "app")
        await message.answer("Ваш предыдущий запрос уже обрабатывается. Дождитесь ответа.")
        return
    if len(_active_users) >= settings.MAX_CONCURRENT_ANALYSES:
        await log_action(user_id, "[capacity]", False, "Analysis capacity reached", "low", "app")
        await message.answer("Ассистент занят. Повторите запрос через несколько секунд.")
        return
    now = time.monotonic()
    if now - _last_request.get(user_id, float("-inf")) < settings.USER_COOLDOWN_SECONDS:
        await log_action(user_id, "[rate_limited]", False, "Request cooldown", "low", "app")
        await message.answer("Слишком частые запросы. Подождите несколько секунд и повторите.")
        return
    _active_users.add(user_id)
    _last_request[user_id] = now
    status = None
    safe_text = redact_secrets(raw_text.strip())
    try:
        status = await message.answer(
            "Анализирую лог и проверяю формат ответа…" if not demo else "Готовлю учебный разбор OOM…"
        )
        # Reserve an audit entry before any external LLM call; fail closed if storage is down.
        recorded = await log_action(user_id, safe_text, True, "Analysis started", "low", "app")
        if not recorded:
            await deliver(
                message,
                status,
                ["Не удалось записать запрос в аудит. Анализ приостановлен; проверьте /health."],
            )
            return
        result = await agent.analyze_incident(safe_text, demo=demo)
        analysis, valid, _ = result
        recorded = await log_action(
            user_id=user_id,
            prompt=safe_text,
            is_valid=valid,
            summary=f"[{result.source}] {analysis.summary}"
            if analysis
            else f"Analysis rejected: {result.error}",
            severity=analysis.severity if analysis else "high",
            affected_service=analysis.affected_service if analysis else "app",
        )
        if not recorded:
            await deliver(
                message,
                status,
                ["Результат не сохранён в аудит. Рекомендации временно недоступны; проверьте /health."],
            )
        elif valid and analysis:
            await deliver(message, status, render_analysis(analysis, result.source))
        else:
            errors = {
                "invalid_response": "Ответ модели не прошёл проверку формата. Рекомендации заблокированы. Попробуйте уточнить лог и повторить запрос.",
                "provider_unavailable": "Сервис анализа сейчас недоступен или не ответил вовремя. Повторите запрос позже.",
                "not_configured": "LLM не настроен. Администратору нужно указать API-ключ. /demo доступен как учебный пример.",
                "invalid_input": "Не удалось обработать ввод. Отправьте непустой фрагмент лога допустимой длины.",
            }
            await deliver(message, status, [errors.get(result.error, errors["invalid_response"])])
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.error("Incident processing failed; sensitive details withheld")
        await log_action(user_id, safe_text, False, "Processing error", "high", "app")
        if status:
            try:
                await deliver(
                    message,
                    status,
                    ["Не удалось завершить обработку. Повторите запрос позже или проверьте /health."],
                )
            except TelegramAPIError:
                logger.warning("Could not deliver incident error message")
    finally:
        _active_users.discard(user_id)


def validate_runtime_config():
    if not settings.ALLOWED_TELEGRAM_IDS:
        raise RuntimeError("Set ALLOWED_TELEGRAM_IDS to a non-empty JSON list of engineer IDs")
    try:
        validate_token(settings.TELEGRAM_BOT_TOKEN)
    except (TokenValidationError, TypeError):
        raise RuntimeError("Set a valid TELEGRAM_BOT_TOKEN from BotFather") from None
    if not agent.has_real_key and not settings.ENABLE_MOCK_FALLBACK:
        raise RuntimeError("Set OPENAI_API_KEY or explicitly enable ENABLE_MOCK_FALLBACK for local mode")


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    validate_runtime_config()
    bot = Bot(token=settings.TELEGRAM_BOT_TOKEN)
    try:
        await init_db()
        await bot.set_my_commands(
            [
                types.BotCommand(command="start", description="Начать работу"),
                types.BotCommand(command="help", description="Инструкция и примеры"),
                types.BotCommand(command="demo", description="Учебный разбор OOM без LLM"),
                types.BotCommand(command="health", description="Состояние БД и режим анализа"),
                types.BotCommand(command="stats", description="Ваш журнал запросов"),
            ]
        )
        await dp.start_polling(
            bot, allowed_updates=["message"], close_bot_session=False, tasks_concurrency_limit=32
        )
    finally:
        try:
            await agent.close()
        finally:
            try:
                await close_db()
            finally:
                await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (RuntimeError, TokenValidationError):
        logger.critical("Startup failed. Check bot credentials, allowlist, LLM and database settings.")
        raise SystemExit(1) from None
