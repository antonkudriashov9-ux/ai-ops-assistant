FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 appuser && useradd --uid 10001 --gid appuser --no-create-home appuser
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY --chown=appuser:appuser app ./app
RUN mkdir /app/data && chown appuser:appuser /app/data
USER appuser
CMD ["python", "-m", "app.main"]
