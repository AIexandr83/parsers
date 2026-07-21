import time
from typing import List

import requests

from config import settings
from dto import CVEDto
from logger import log


def send_batch(batch: List[CVEDto], retries: int = 3, backoff_seconds: int = 5) -> bool:
    """Отправляет пакет DTO в db_api. При сетевой ошибке — несколько попыток с паузой."""
    if not batch:
        return True

    payload = {"items": [item.model_dump() for item in batch]}
    url = f"{settings.DB_API_URL}/cves/bulk"

    for attempt in range(1, retries + 1):
        try:
            response = requests.post(url, json=payload, timeout=30)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            log(f"[API Ошибка] Попытка {attempt}/{retries} отправки в db_api не удалась: {e}")
            if attempt < retries:
                time.sleep(backoff_seconds)

    log(f"[API Ошибка] Не удалось отправить пакет из {len(batch)} записей после {retries} попыток.")
    return False