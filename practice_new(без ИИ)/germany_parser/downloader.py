import csv
import io
import time
from datetime import datetime
from typing import List, Optional

import requests

from config import settings
from logger import log

_session = requests.Session()


def fetch_document_urls(since: Optional[datetime] = None) -> List[str]:
    """
    Читает changes.csv. Если since=None — возвращает ВСЕ документы (первый
    запуск). Если since задан — возвращает только те, чей таймстамп в CSV
    новее.
    """
    log("[Загрузка] Скачиваем changes.csv...")
    response = _session.get(settings.CHANGES_URL, timeout=60)
    response.raise_for_status()

    urls = []
    skipped_old = 0
    reader = csv.reader(io.StringIO(response.text))
    for row in reader:
        if not row:
            continue
        relative_path = row[0].strip('"').lstrip("./")
        if not relative_path.endswith(".json"):
            continue

        if since is not None and len(row) > 1:
            try:
                changed_at = datetime.fromisoformat(row[1].strip('"').replace("+0000", "+00:00"))
                if changed_at.replace(tzinfo=None) <= since:
                    skipped_old += 1
                    continue
            except ValueError:
                pass  # не смогли распарсить дату — не пропускаем документ

        urls.append(f"{settings.BASE_URL}/{relative_path}")

    if since is not None:
        log(f"[Загрузка] Найдено новых/изменённых документов: {len(urls)} (пропущено старых: {skipped_old}).")
    else:
        log(f"[Загрузка] Найдено документов (полный сбор): {len(urls)}")
    return urls


def fetch_document(url: str, retries: int = 3, backoff_seconds: int = 3) -> dict:
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            response = _session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            last_error = e
            if attempt < retries:
                time.sleep(backoff_seconds)
    raise last_error