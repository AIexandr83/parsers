import time

import schedule

from api_client import send_batch
from config import settings
from downloader import init_repository, pull_repository
from logger import log
from parser import find_all_cve_files, parse_cve_file


def run_update_cycle() -> None:
    is_first_run = init_repository()
    if not is_first_run:
        if not pull_repository():
            log("[Обновление Ошибка] Не удалось синхронизировать репозиторий.")
            return

    all_files = find_all_cve_files()
    total_files = len(all_files)
    log(f"[Обновление] Найдено файлов CVE: {total_files}.")

    batch = []
    total_sent = 0
    processed = 0

    for file_path in all_files:
        for dto in parse_cve_file(file_path):
            batch.append(dto)
            if len(batch) >= settings.BATCH_SIZE:
                send_batch(batch)
                total_sent += len(batch)
                batch = []

        processed += 1
        if processed % 5000 == 0 or processed == total_files:
            log(f"[Обновление] Обработано файлов: {processed}/{total_files}...")

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