import time
from datetime import datetime

import schedule

from api_client import send_batch
from config import settings
from downloader import fetch_document, fetch_document_urls
from logger import log
from parser import parse_csaf_document
from state import get_last_run_timestamp, mark_run_complete


def run_update_cycle() -> None:
    last_run = get_last_run_timestamp()
    now = datetime.utcnow()

    if last_run is None:
        log("[Обновление] Первый запуск — собираем весь каталог CERT-Bund.")
    else:
        log(f"[Обновление] Плановое обновление — собираем изменения с {last_run.isoformat()}.")

    try:
        urls = fetch_document_urls(since=last_run)
    except Exception as e:
        log(f"[Обновление Ошибка] Не удалось получить список документов: {e}")
        return

    total_urls = len(urls)
    batch = []
    total_sent = 0
    total_failed_docs = 0
    processed_docs = 0

    for url in urls:
        try:
            doc = fetch_document(url)
        except Exception as e:
            log(f"[Парсер Ошибка] Не удалось скачать/разобрать {url}: {e}")
            total_failed_docs += 1
            processed_docs += 1
            continue

        for dto in parse_csaf_document(doc):
            batch.append(dto)
            if len(batch) >= settings.BATCH_SIZE:
                send_batch(batch)
                total_sent += len(batch)
                batch = []

        processed_docs += 1
        if processed_docs % 500 == 0 or processed_docs == total_urls:
            log(f"[Обновление] Обработано документов: {processed_docs}/{total_urls}...")

    if batch:
        send_batch(batch)
        total_sent += len(batch)

    mark_run_complete(now)
    log(
        f"[Обновление] Цикл завершён, отправлено записей: {total_sent}. "
        f"Документов с ошибками: {total_failed_docs}."
    )


def run_scheduler() -> None:
    schedule.every(settings.UPDATE_INTERVAL_HOURS).hours.do(run_update_cycle)
    log(f"[Планировщик] Настроено обновление каждые {settings.UPDATE_INTERVAL_HOURS} ч.")
    while True:
        schedule.run_pending()
        time.sleep(1)