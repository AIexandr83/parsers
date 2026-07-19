import time
from datetime import datetime, timedelta

import schedule

from api_client import send_batch
from config import settings
from downloader import fetch_all_pages
from logger import log
from parser import parse_overview_page
from state import get_last_run_date, mark_run_complete


def run_update_cycle() -> None:

    #Определяет диапазон дат в зависимости от того, первый это запуск или обновление.
    last_run = get_last_run_date()
    today = datetime.utcnow()

    if last_run is None:
        date_from = datetime(settings.HIST_START_YEAR, 1, 1)
        log(f"[Обновление] Первый запуск — собираем полную историю с {date_from.date()}.")
    else:
        date_from = last_run - timedelta(days=settings.INCREMENTAL_LOOKBACK_DAYS)
        log(f"[Обновление] Плановое обновление — собираем данные с {date_from.date()} (с запасом на {settings.INCREMENTAL_LOOKBACK_DAYS} дн.).")

    batch = []
    total_sent = 0
    total_pages = 0

    for xml_page in fetch_all_pages(date_from, today):
        total_pages += 1
        for dto in parse_overview_page(xml_page):
            batch.append(dto)
            if len(batch) >= settings.BATCH_SIZE:
                send_batch(batch)
                total_sent += len(batch)
                batch = []

        if total_pages % 200 == 0:
            log(f"[Обновление] Обработано страниц: {total_pages}...")

    if batch:
        send_batch(batch)
        total_sent += len(batch)

    mark_run_complete(today)
    log(f"[Обновление] Цикл завершён, отправлено записей: {total_sent}. Страниц обработано: {total_pages}.")


def run_scheduler() -> None:
    schedule.every(settings.UPDATE_INTERVAL_HOURS).hours.do(run_update_cycle)
    log(f"[Планировщик] Настроено обновление каждые {settings.UPDATE_INTERVAL_HOURS} ч.")
    while True:
        schedule.run_pending()
        time.sleep(1)