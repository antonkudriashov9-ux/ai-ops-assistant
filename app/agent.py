import json
import logging
from typing import Tuple, Optional

try:
    from openai import AsyncOpenAI
except ImportError:
    AsyncOpenAI = None

from app.config import settings
from app.schemas import IncidentAnalysisSchema

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
Ты — AI Ops Assistant, автономный агент для первичной диагностики сбоев серверов и инфраструктуры.
Твоя задача — проанализировать предоставленный лог ошибки, фрагмент конфигурации или описание инцидента.

Требования:
1. Выдели конкретный затронутый сервис (linux_os, postgresql, docker, network, app).
2. Оцени реальный уровень критичности (low, medium, high, critical).
3. Дай краткое, точное техническое резюме проблемы.
4. Предложи 2-4 конкретных шага по диагностике и устранению сбоя (команды Linux, проверки логов, тюнинг параметров).
5. Ответ строго в формате JSON, соответствующем заданной схеме. Без вводных слов и разметки markdown вне JSON.
"""


class IncidentAgent:
    def __init__(self):
        self.api_key = settings.OPENAI_API_KEY
        self.has_real_key = bool(self.api_key and not self.api_key.startswith("mock-") and AsyncOpenAI is not None)
        if self.has_real_key and AsyncOpenAI is not None:
            self.client = AsyncOpenAI(
                api_key=self.api_key,
                base_url=settings.OPENAI_BASE_URL
            )
        else:
            self.client = None
        self.model = settings.OPENAI_MODEL

    async def analyze_incident(self, raw_input: str) -> Tuple[Optional[IncidentAnalysisSchema], bool, str]:
        """
        Запрашивает у LLM разбор инцидента и производит строгую валидацию схемы.
        Если API-ключ не задан или недоступен, включает встроенный эвристический движок (Mock Fallback).
        """
        # Режим с реальным OpenAI API
        if self.has_real_key and self.client:
            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"Входные данные инцидента:\n{raw_input}"}
                    ],
                    temperature=0.2,
                    response_format={"type": "json_object"}
                )

                raw_text = response.choices[0].message.content or "{}"
                data = json.loads(raw_text)
                validated_obj = IncidentAnalysisSchema(**data)
                return validated_obj, True, raw_text

            except Exception as e:
                logger.warning(f"OpenAI API call failed: {e}. Checking fallback mode...")
                if not settings.ENABLE_MOCK_FALLBACK:
                    return None, False, str(e)

        # Интеллектуальный Mock/Heuristic режим (для тестов, CI и демонстраций без расхода токенов)
        return self._heuristic_analysis(raw_input)

    def _heuristic_analysis(self, raw_input: str) -> Tuple[IncidentAnalysisSchema, bool, str]:
        lowered = raw_input.lower()

        if "oom" in lowered or "out of memory" in lowered or "killed process" in lowered:
            data = {
                "title": "Аварийное завершение процесса (Out Of Memory / OOM-Killer)",
                "severity": "critical",
                "affected_service": "linux_os",
                "summary": "Ядро Linux принудительно завершило процесс из-за исчерпания RAM и swap. Возможна утечка памяти или всплеск нагрузки.",
                "recommended_actions": [
                    "Выполнить dmesg -T | grep -i oom для поиска завершенного PID",
                    "Проверить топ потребителей памяти через ps aux --sort=-%mem | head -n 10",
                    "Настроить лимиты MemoryMax в systemd-юните сервиса",
                    "Проверить размер и активность раздела swap: swapon --show"
                ]
            }
        elif "postgres" in lowered or "database" in lowered or "connection refused" in lowered or "deadlock" in lowered:
            data = {
                "title": "Сбой подключений или блокировка в PostgreSQL",
                "severity": "high",
                "affected_service": "postgresql",
                "summary": "Служба БД отклоняет соединения или испытывает взаимные блокировки (deadlocks). Превышен max_connections или забиты ресурсы.",
                "recommended_actions": [
                    "Проверить статус службы: systemctl status postgresql",
                    "Изучить активные блокировки: SELECT * FROM pg_stat_activity WHERE state != 'idle';",
                    "Проверить свободное место на диске под WAL: df -h /var/lib/postgresql",
                    "Изучить лог-файл СУБД: tail -n 100 /var/log/postgresql/postgresql-*.log"
                ]
            }
        elif "docker" in lowered or "container" in lowered:
            data = {
                "title": "Сбой запуска или аварийный перезапуск Docker-контейнера",
                "severity": "medium",
                "affected_service": "docker",
                "summary": "Контейнер завершил работу с ненулевым кодом или не проходит проверку состояния (healthcheck).",
                "recommended_actions": [
                    "Посмотреть логи аварийного контейнера: docker logs --tail 100 <container_id>",
                    "Проверить статус exit code: docker inspect <container_id> --format='{{.State.ExitCode}}'",
                    "Убедиться в доступности монтируемых томов и прав доступа к директориям"
                ]
            }
        else:
            data = {
                "title": "Общий системный инцидент / Нештатное поведение сервиса",
                "severity": "medium",
                "affected_service": "app",
                "summary": f"Обнаружена аномалия в работе приложения или инфраструктуры: {raw_input[:100]}...",
                "recommended_actions": [
                    "Проанализировать системный журнал: journalctl -xe -u <service_name>",
                    "Проверить сетевую связность и открытые порты: ss -tulpn",
                    "Убедиться в валидности конфигурационных файлов и переменных окружения"
                ]
            }

        validated = IncidentAnalysisSchema(**data)
        return validated, True, json.dumps(data, ensure_ascii=False)
