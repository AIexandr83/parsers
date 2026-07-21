import time

import schedule

from api_client import send_batch
from config import settings
from downloader import fetch_kev_catalog
from logger import log
from parser import parse_kev_catalog


def run_update_cycle() -> None:
    log("[Обновление] Запускаем обновление данных CISA KEV...")

    vulnerabilities = fetch_kev_catalog()
    if not vulnerabilities:
        log("[Обновление Ошибка] Не удалось получить данные, цикл прерван.")
        return

    batch = list(parse_kev_catalog(vulnerabilities))
    total_sent = 0

    for i in range(0, len(batch), settings.BATCH_SIZE):
        chunk = batch[i:i + settings.BATCH_SIZE]
        send_batch(chunk)
        total_sent += len(chunk)

    log(f"[Обновление] Цикл завершён, отправлено записей: {total_sent}.")


def run_scheduler() -> None:
    schedule.every(settings.UPDATE_INTERVAL_HOURS).hours.do(run_update_cycle)
    log(f"[Планировщик] Настроено обновление каждые {settings.UPDATE_INTERVAL_HOURS} ч.")
    while True:
        schedule.run_pending()
        time.sleep(1)