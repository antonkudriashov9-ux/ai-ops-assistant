# AI Ops Assistant 🤖🛠️

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/postgresql-16-336791.svg)](https://www.postgresql.org/)
[![Pydantic v2](https://img.shields.io/badge/validation-pydantic--v2-e92063.svg)](https://docs.pydantic.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AI Ops Assistant** — автономный Telegram-ассистент для дежурных инженеров и команд эксплуатации. 
Помогает первичной диагностике серверных сбоев, анализу дампов ошибок (`dmesg`, `journalctl`, `PostgreSQL`) и формированию регламентных действий по восстановлению с использованием LLM и строгой валидацией схемы (Anti-Hallucination).

---

## 🎯 Какую проблему решает?

Во время инцидентов дежурные инженеры тратят драгоценное время на ручной поиск затронутого компонента в логах, выявление причин сбоя и подбор команд для локализации.

**AI Ops Assistant:**
1. Принимает сырой лог ошибки или текст инцидента прямо в Telegram.
2. Выделяет затронутый сервис (`linux_os`, `postgresql`, `docker`, `network`, `app`).
3. Определяет реальный уровень критичности (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
4. Формирует краткое резюме проблемы и предлагает пошаговые команды для инженера.
5. Логирует каждый запрос и статус валидации в **PostgreSQL** для последующего постмортема (Post-Mortem).

---

## 🏗️ Архитектура системы

```text
[Инженер в Telegram] 
        │
        ▼ (Авторизация по whitelist ID)
[Telegram Bot (aiogram 3)]
        │
        ├──▶ [LLM Agent (JSON Structured Outputs)] 
        │            │
        │            ▼
        ├──▶ [Pydantic Schema Validator] ──(Ошибка схемы)──▶ [Блокировка ответа]
        │            │ (Валидация успешна)
        │            ▼
        ├──▶ [PostgreSQL 16] (Аудит инцидентов, логирование действий, история)
        │
        ▼ (Форматированный ответ)
[Инженер получает регламентный план действий]
```

---

## 🛡️ Контроль качества и безопасности

- **Строгая схема ответов (`app/schemas.py`)**: модель отвечает строго в формате Pydantic-модели. Если структура нарушена или в ответе обнаружена галлюцинация — ответ отбрасывается.
- **Принцип наименьших привилегий (Least Privilege)**: Dockerfile запускает приложение от непривилегированного пользователя `appuser`.
- **Авторизация**: бот отвечает только инженерам из доверенного списка `ALLOWED_TELEGRAM_IDS`.
- **Инструкции для ИИ-агентов (`AGENTS.md`)**: проект готов для совместной разработки и доработки через терминальных агентов (Claude Code, Codex CLI).

---

## 💬 Команды бота

- `/start` — приветствие и краткая инструкция.
- `/demo` — запуск тестового анализа реального OOM-инцидента с демонстрацией работы валидатора.
- `/health` — проверка состояния подключенных баз данных и активного режима работы.
- `/stats` — сводная статистика обработанных инцидентов и аудита валидации.

---

## 🚀 Быстрый запуск

### 1. Клонирование и настройка
```bash
git clone https://github.com/antonkudriashov9-ux/ai-ops-assistant.git
cd ai-ops-assistant

cp .env.example .env
# Отредактируйте .env (укажите TELEGRAM_BOT_TOKEN и OPENAI_API_KEY)
```

### 2. Запуск через Docker Compose
```bash
docker compose up -d --build
```

### 3. Просмотр логов
```bash
docker compose logs -f bot
```

---

## 💾 Резервное копирование базы данных

В папке `scripts/` предусмотрен автоматический скрипт бэкапа базы PostgreSQL со сжатием и ротацией:
```bash
chmod +x scripts/backup.sh
./scripts/backup.sh
```

---

## 🧪 Запуск тестов
```bash
pytest tests/ -v
```

---

## 👨‍💻 Автор
**Антон Кудряшов**  
- Email: [lipais364883@yandex.ru](mailto:lipais364883@yandex.ru)  
- GitHub: [@antonkudriashov9-ux](https://github.com/antonkudriashov9-ux)
