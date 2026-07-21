import requests

from config import settings
from logger import log

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; CVE-Aggregator/1.0)"}


def fetch_kev_catalog(retries: int = 3, backoff_seconds: int = 5) -> list:
    import time

    for attempt in range(1, retries + 1):
        try:
            response = requests.get(settings.FEED_URL, headers=_HEADERS, timeout=60)
            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            log(f"[Загрузка] Получено записей: {len(vulns)}.")
            return vulns
        except (requests.RequestException, ValueError) as e:
            log(f"[Загрузка Ошибка] Попытка {attempt}/{retries} не удалась: {e}")
            if attempt < retries:
                time.sleep(backoff_seconds)

    log("[Загрузка Ошибка] Не удалось получить каталог после всех попыток.")
    return []