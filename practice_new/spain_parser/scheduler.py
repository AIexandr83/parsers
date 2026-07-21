import time
from datetime import datetime

import schedule

from api_client import send_batch
from config import settings
from downloader import detect_last_page, fetch_page, fetch_pages_parallel
from dto import CVEDto
from logger import log
from parser import parse_list_page
from state import get_last_run_date, mark_run_complete

def _record_to_dto(record) -> CVEDto:
    return CVEDto(
        cve_number=record.cve_number,
        external_id=None,
        description=record.description[:5000],
        cvss_score=None,
        raw_content=record.raw_content[:100000] if record.raw_content else None,
        source=settings.SOURCE_NAME,
    )


def run_update_cycle() -> None:
    last_run = get_last_run_date()
    now = datetime.utcnow()

    first_page_html = fetch_page(0)
    if first_page_html is None:
        log("[Обновление Ошибка] Не удалось получить даже первую страницу, прерываем цикл.")
        return

    last_page = detect_last_page(first_page_html)

    if last_run is None:
        run_full_crawl(first_page_html, last_page, now)
    else:
        run_incremental(first_page_html, last_page, last_run, now)


def run_full_crawl(first_page_html: str, last_page: int, now: datetime) -> None:
    log(f"[Обновление] Первый запуск — полный сбор, страниц: {last_page + 1}, потоков: {settings.MAX_WORKERS}.")
    batch = []
    total_sent = 0

    all_pages = list(range(0, last_page + 1))
    chunk_size = 200

    processed_pages = 0
    for chunk_start in range(0, len(all_pages), chunk_size):
        chunk = all_pages[chunk_start:chunk_start + chunk_size]

        if chunk_start == 0:
            results = fetch_pages_parallel([p for p in chunk if p != 0])
            results[0] = first_page_html
        else:
            results = fetch_pages_parallel(chunk)

        for page in chunk:
            html = results.get(page)
            if html is None:
                continue
            for record in parse_list_page(html):
                batch.append(_record_to_dto(record))
                if len(batch) >= settings.BATCH_SIZE:
                    send_batch(batch)
                    total_sent += len(batch)
                    batch = []

        processed_pages += len(chunk)
        log(f"[Обновление] Обработано страниц: {processed_pages}/{last_page + 1}...")

    if batch:
        send_batch(batch)
        total_sent += len(batch)

    mark_run_complete(now)
    log(f"[Обновление] Полный сбор завершён, отправлено записей: {total_sent}.")


def run_incremental(first_page_html: str, last_page: int, last_run: datetime, now: datetime) -> None:
    log(f"[Обновление] Плановое обновление — идём с новых записей до даты {last_run.date()}.")

    batch = []
    total_sent = 0
    pages_processed = 0
    reached_known_data = False

    html = first_page_html
    page = 0

    while html is not None:
        records = parse_list_page(html)
        pages_processed += 1

        for record in records:
            if record.pub_date is not None and record.pub_date <= last_run:
                reached_known_data = True
                break
            batch.append(_record_to_dto(record))
            if len(batch) >= settings.BATCH_SIZE:
                send_batch(batch)
                total_sent += len(batch)
                batch = []

        if reached_known_data or page >= last_page:
            break

        page += 1
        time.sleep(settings.REQUEST_DELAY_SECONDS)
        html = fetch_page(page)

    if batch:
        send_batch(batch)
        total_sent += len(batch)

    mark_run_complete(now)
    log(f"[Обновление] Цикл завершён, отправлено записей: {total_sent}. Страниц обработано: {pages_processed}.")


def run_scheduler() -> None:
    schedule.every(settings.UPDATE_INTERVAL_HOURS).hours.do(run_update_cycle)
    log(f"[Планировщик] Настроено обновление каждые {settings.UPDATE_INTERVAL_HOURS} ч.")
    while True:
        schedule.run_pending()
        time.sleep(1)