import requests

from config import settings
from logger import log

# Без заголовка User-Agent сайт KrCERT отдаёт 404 — подтверждено на практике,
# запрос без него не проходит вообще.
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; CVE-Aggregator/1.0)"}


def fetch_feed() -> str:
    log("[Загрузка] Скачиваем RSS-фид KrCERT...")
    response = requests.get(settings.RSS_URL, headers=_HEADERS, timeout=30)
    response.raise_for_status()
    log("[Загрузка] Фид получен.")
    return response.text