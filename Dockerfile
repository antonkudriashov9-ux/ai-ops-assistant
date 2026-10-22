FROM python:3.11-slim

# Создание непривилегированного пользователя для безопасности (Security Best Practice)
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Установка зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование исходного кода
COPY . .

# Назначение прав
RUN chown -R appuser:appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "app.main"]
