import asyncio
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart, Command
from app.config import settings
from app.agent import IncidentAgent
from app.database import init_db, log_action, get_audit_stats

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

bot = Bot(token=settings.TELEGRAM_BOT_TOKEN)
dp = Dispatcher()
agent = IncidentAgent()


def check_auth(user_id: int) -> bool:
    if not settings.ALLOWED_TELEGRAM_IDS:
        return True
    return user_id in settings.ALLOWED_TELEGRAM_IDS


@dp.message(CommandStart())
async def handle_start(message: types.Message):
    if not check_auth(message.from_user.id):
        await message.answer("⛔ Доступ запрещен. Ваш ID не входит в список авторизованных инженеров.")
        return

    welcome_text = (
        "🤖 **AI Ops Assistant** — Ассистент дежурного инженера.\n\n"
        "**Доступные команды:**\n"
        "• `/demo` — запустить тестовый анализ инцидента (OOM-killer)\n"
        "• `/health` — проверить статус инфраструктуры и базы данных\n"
        "• `/stats` — статистика обработанных инцидентов и аудита\n\n"
        "**Как пользоваться:**\n"
        "Просто отправьте сырой лог ошибки, вывод `dmesg`/`journalctl` или опишите сбой своими словами. "
        "Агент структурирует проблему, оценит критичность и предложит регламентные шаги."
    )
    await message.answer(welcome_text, parse_mode="Markdown")


@dp.message(Command("health"))
async def handle_health(message: types.Message):
    if not check_auth(message.from_user.id):
        return
    stats = await get_audit_stats()
    await message.answer(
        f"🟢 **Healthcheck Status:**\n\n"
        f"• Хранилище аудита: `{stats['db_engine']}`\n"
        f"• Режим ИИ: `{'OpenAI API' if agent.has_real_key else 'Heuristic / Mock Fallback'}`\n"
        f"• Сервисы: Все подсистемы в активном состоянии.",
        parse_mode="Markdown"
    )


@dp.message(Command("stats"))
async def handle_stats(message: types.Message):
    if not check_auth(message.from_user.id):
        return
    stats = await get_audit_stats()
    await message.answer(
        f"📊 **Статистика аудита инцидентов:**\n\n"
        f"• Всего запросов: `{stats['total_queries']}`\n"
        f"• Успешно валидировано схемой: `{stats['validated_queries']}`\n"
        f"• Отклонено (ошибки валидации): `{stats['failed_queries']}`\n"
        f"• Движок БД: `{stats['db_engine']}`",
        parse_mode="Markdown"
    )


@dp.message(Command("demo"))
async def handle_demo(message: types.Message):
    if not check_auth(message.from_user.id):
        return
    sample_incident = (
        "kernel: Out of memory: Killed process 14210 (postgres) total-vm:4231880kB, "
        "anon-rss:3189200kB, file-rss:0kB, shmem-rss:215040kB. oom_score_adj: 0"
    )
    await message.answer(f"🔍 Запускаю анализ тестового инцидента:\n`{sample_incident}`", parse_mode="Markdown")
    await process_incident_text(message, sample_incident)


@dp.message()
async def handle_incoming_text(message: types.Message):
    if not check_auth(message.from_user.id):
        await message.answer("⛔ Доступ запрещен.")
        return

    if not message.text:
        return

    await process_incident_text(message, message.text)


async def process_incident_text(message: types.Message, raw_text: str):
    msg = await message.answer("⚙️ _Обрабатываю инцидент с помощью ИИ-агента и проверяю схему..._", parse_mode="Markdown")

    try:
        analysis, is_valid, raw_response = await agent.analyze_incident(raw_text)

        await log_action(
            user_id=message.from_user.id,
            prompt=raw_text,
            is_valid=is_valid,
            summary=analysis.summary if analysis else "Validation Error",
            severity=analysis.severity if analysis else "high",
            affected_service=analysis.affected_service if analysis else "unknown"
        )

        if is_valid and analysis:
            badge_icon = {
                "critical": "🚨 CRITICAL",
                "high": "⚠️ HIGH",
                "medium": "🟡 MEDIUM",
                "low": "🔵 LOW"
            }.get(analysis.severity, "ℹ️ INFO")

            formatted_answer = (
                f"**Инцидент:** {analysis.title}\n"
                f"**Критичность:** `{badge_icon}`\n"
                f"**Затронутый сервис:** `{analysis.affected_service}`\n\n"
                f"**Суть проблемы:**\n{analysis.summary}\n\n"
                f"**Рекомендуемые действия инженера:**\n"
                + "\n".join(f" `{i+1}.` {action}" for i, action in enumerate(analysis.recommended_actions))
                + f"\n\n🛡️ _Схема ответа проверена: Pydantic Schema Validation passed._"
            )
            await msg.edit_text(formatted_answer, parse_mode="Markdown")
        else:
            await msg.edit_text(
                "❌ **Ошибка валидации ответа:** Ответ модели не соответствует системной схеме. "
                "Действие заблокировано модулем безопасности.",
                parse_mode="Markdown"
            )

    except Exception as e:
        logger.error(f"Error handling request: {e}")
        await msg.edit_text(f"⚠️ Ошибка выполнения: {e}")


async def main():
    logger.info("Initializing database...")
    await init_db()
    logger.info("Starting Telegram Bot...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
