from logger import log
from scheduler import run_scheduler, run_update_cycle

if __name__ == "__main__":
    log("[BDU-парсер] Скрипт запущен.")
    run_update_cycle()   # первый запуск — сразу полный импорт
    run_scheduler()       # дальше по расписанию