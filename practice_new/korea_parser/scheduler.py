import time

import schedule

from api_client import send_batch
from config import settings
from downloader import fetch_feed
from logger import log
from parser import parse_feed


def run_update_cycle() -> None:
    """
    Фид у KrCERT маленький (десятки записей) и не постраничный — в отличие
    от Германии/Японии, тут не нужна инкрементальная логика с файлом
    состояния: разбираем весь фид целиком каждый раз, upsert сам
    разберётся с уже известными записями.
    """
    log("[Обновление] Запускаем обновление данных KrCERT (Корея)...")

    try:
        xml_text = fetch_feed()
    except Exception as e:
        log(f"[Обновление Ошибка] Не удалось получить фид: {e}")
        return

    batch = list(parse_feed(xml_text))

    if batch:
        send_batch(batch)

    log(f"[Обновление] Цикл завершён, обработано записей: {len(batch)}.")


def run_scheduler() -> None:
    schedule.every(settings.UPDATE_INTERVAL_HOURS).hours.do(run_update_cycle)
    log(f"[Планировщик] Настроено обновление каждые {settings.UPDATE_INTERVAL_HOURS} ч.")
    while True:
        schedule.run_pending()
        time.sleep(1)