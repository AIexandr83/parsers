## Настройка окружения

В корне проекта должен лежать файл `.env`:

```bash
cat > .env << 'EOF'
DB_USER=cve_user
DB_PASSWORD=cve_password
DB_NAME=cve_database
OPENROUTER_API_KEY=
EOF
```

`OPENROUTER_API_KEY` можно оставить пустым — тогда просто не будет работать опциональный LLM-анализ эксплойтов (`?analyze=true`), всё остальное функционирует без него.

## Запуск

```bash
cd practice_new
docker compose build --no-cache
docker compose up -d
```

Проверить, что всё поднялось:

```bash
docker compose ps
```

Все сервисы должны быть в статусе `Up`.

## Первичный сбор данных

Следить за прогрессом:

```bash
docker compose logs -f
```

Проверить конкретный сервис:

```bash
docker compose logs --tail 20 poc_github_parser
```

## Проверка данных в базе

```bash
docker exec -it postgres_db psql -U cve_user -d cve_database -c \
  "SELECT source, COUNT(*) FROM cves GROUP BY source ORDER BY COUNT(*) DESC;"

docker exec -it postgres_db psql -U cve_user -d cve_database -c \
  "SELECT source, COUNT(*) FROM exploits GROUP BY source ORDER BY COUNT(*) DESC;"
```

## API

По умолчанию доступен на `http://localhost:8080`.

| Метод | Путь | Описание |
|---|---|---|
| GET | `/health` | Проверка живости |
| GET | `/cves/{cve_number}` | Сводная карточка CVE по всем источникам |
| GET | `/cves/search?q=...` | Поиск только по CVE |
| GET | `/exploits/{cve_number}?analyze=true` | Эксплойты для конкретного CVE, с опциональным LLM-анализом |
| GET | `/search?q=...&analyze=true` | Объединённый поиск: CVE + эксплойты |

Примеры:

```bash
curl -s http://localhost:8080/health | jq

curl -s "http://localhost:8080/search?q=ubuntu%20shell" | jq

curl -s "http://localhost:8080/exploits/CVE-2023-2640?analyze=true" | jq
```

## Остановка и очистка

```bash
docker compose down
```

Полная очистка с удалением всех собранных данных (следующий запуск начнёт сбор с нуля):

```bash
docker compose down -v
```