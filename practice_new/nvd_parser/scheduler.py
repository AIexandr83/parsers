import time

import schedule

from api_client import send_batch
from config import settings
from git_utils import pull_repository
from logger import log
from parser import parse_cve_file, read_delta_log


def check_for_updates() -> None:
    """Выполняет git pull и инкрементально обрабатывает изменения через deltaLog.json."""
    log("[Обновление] Проверка обновлений по расписанию...")

    if not pull_repository():
        log("[Обновление Ошибка] Не удалось синхронизировать репозиторий с GitHub.")
        return

    files = read_delta_log()
    if not files:
        return

    batch = []
    for file_path in files:
        dto = parse_cve_file(file_path)
        if dto:
            batch.append(dto)

    if batch:
        if send_batch(batch):
            log(f"[Обновление] Инкрементальное обновление применено: {len(batch)} записей отправлено в db_api.")
    else:
        log("[Обновление] Файлы из дельты прочитаны, но валидных данных не найдено.")


def run_scheduler() -> None:
    schedule.every(settings.UPDATE_INTERVAL_HOURS).hours.do(check_for_updates)
    log(f"[Планировщик] Настроено обновление каждые {settings.UPDATE_INTERVAL_HOURS} ч. Робот засыпает...")
    while True:
        schedule.run_pending()
        time.sleep(1)
