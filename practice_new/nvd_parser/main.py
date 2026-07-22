from api_client import send_batch
from config import settings
from git_utils import init_repository
from logger import log
from parser import find_all_cve_files, parse_cve_file
from scheduler import run_scheduler


def perform_historical_import() -> None:
    """Сканирует все каталоги (с 1999 по текущий год) для первоначального наполнения БД."""
    log("[Инициализация] Запуск ПОЛНОГО исторического импорта CVE за ВСЕ года...")

    all_files = find_all_cve_files()
    total_files = len(all_files)
    log(f"[Инициализация] Найдено всего {total_files} файлов для первичного импорта.")

    batch = []
    processed_count = 0

    for file_path in all_files:
        cve_dto = parse_cve_file(file_path)
        if cve_dto:
            batch.append(cve_dto)

        if len(batch) >= settings.BATCH_SIZE:
            send_batch(batch)
            processed_count += len(batch)
            batch = []
            if processed_count % 5000 == 0 or processed_count == total_files:
                log(f"[Инициализация] Отправлено в db_api: {processed_count}/{total_files} файлов...")

    # Дозаписываем остатки
    if batch:
        send_batch(batch)
        processed_count += len(batch)

    log(f"[Инициализация] Первичный исторический импорт завершён! Отправлено: {processed_count} записей.")


if __name__ == "__main__":
    log("[Парсер] Скрипт запущен.")

    # Клонируем репозиторий, если его нет
    is_first_run = init_repository()

    # Если это самый первый запуск контейнера — выполняем полную заливку всех годов
    if is_first_run:
        perform_historical_import()
    else:
        log("[Инициализация] Репозиторий уже существовал. Пропускаем первичный исторический импорт.")

    # Переходим на ежечасное обновление по deltaLog.json
    run_scheduler()
