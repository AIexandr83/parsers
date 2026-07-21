FROM python:3.11-slim

WORKDIR /app

# Установка зависимостей для работы с PostgreSQL
RUN apt-get update && apt-get install -y libpq-dev gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY alembic.ini .
COPY migrations/ ./migrations/
COPY app/ ./app/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8000

# При старте контейнера: сначала накатываются миграции, потом поднимается API
ENTRYPOINT ["./entrypoint.sh"]
