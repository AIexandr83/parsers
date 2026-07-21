#!/bin/sh
set -e

echo "[db_api] Применяем миграции Alembic..."
alembic upgrade head

echo "[db_api] Запускаем API..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
