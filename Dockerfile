FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ai_engine/ ./ai_engine/
COPY scripts/soc_llm_server.py ./scripts/soc_llm_server.py

RUN groupadd -g 1000 socuser \
    && useradd -u 1000 -g 1000 -m -s /bin/bash socuser \
    && mkdir -p /app/ai_engine/logs /app/logs /app/ai_engine/data \
    && chown -R socuser:socuser /app

USER socuser

EXPOSE 8080

CMD ["python", "-m", "ai_engine.dashboard.server"]
