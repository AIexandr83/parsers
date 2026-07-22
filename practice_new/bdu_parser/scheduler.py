import time

import schedule

from api_client import send_batch
from config import settings
from downloader import download_and_extract
from logger import log
from parser import iter_cve_dtos


def run_update_cycle() -> None:
    """Скачивает свежий vulxml.zip и отправляет все записи в db_api батчами."""
    log("[Обновление] Запускаем плановое обновление данных БДУ...")
    export_path = download_and_extract()

    batch = []
    total_sent = 0

    for dto in iter_cve_dtos(export_path):
        batch.append(dto)
        if len(batch) >= settings.BATCH_SIZE:
            send_batch(batch)
            total_sent += len(batch)
            batch = []

    if batch:
        send_batch(batch)
        total_sent += len(batch)

    log(f"[Обновление] Цикл завершён, отправлено записей: {total_sent}.")


def run_scheduler() -> None:
    schedule.every(settings.UPDATE_INTERVAL_HOURS).hours.do(run_update_cycle)
    log(f"[Планировщик] Настроено обновление каждые {settings.UPDATE_INTERVAL_HOURS} ч.")
    while True:
        schedule.run_pending()
        time.sleep(1)