import time
from datetime import datetime

import schedule

from api_client import send_batch
from config import settings
from downloader import fetch_all_threats
from logger import log
from parser import get_modified_date, parse_threat
from state import get_last_run_date, mark_run_complete


def run_update_cycle() -> None:
    last_run = get_last_run_date()
    now = datetime.utcnow()

    if last_run is None:
        log("[Обновление] Первый запуск — собираем все записи.")
    else:
        log(f"[Обновление] Плановое обновление — только записи новее {last_run.isoformat()}.")

    items = fetch_all_threats()
    if not items:
        log("[Обновление Ошибка] Не удалось получить данные, цикл прерван.")
        return

    batch = []
    total_sent = 0
    skipped_old = 0

    for item in items:
        if last_run is not None:
            modified = get_modified_date(item)
            if modified is not None and modified <= last_run:
                skipped_old += 1
                continue

        for dto in parse_threat(item):
            batch.append(dto)
            if len(batch) >= settings.BATCH_SIZE:
                send_batch(batch)
                total_sent += len(batch)
                batch = []

    if batch:
        send_batch(batch)
        total_sent += len(batch)

    mark_run_complete(now)
    log(f"[Обновление] Цикл завершён, отправлено записей: {total_sent}. Пропущено старых: {skipped_old}.")


def run_scheduler() -> None:
    schedule.every(settings.UPDATE_INTERVAL_HOURS).hours.do(run_update_cycle)
    log(f"[Планировщик] Настроено обновление каждые {settings.UPDATE_INTERVAL_HOURS} ч.")
    while True:
        schedule.run_pending()
        time.sleep(1)