from logger import log
from scheduler import run_scheduler, run_update_cycle

if __name__ == "__main__":
    log("[Япония-парсер] Скрипт запущен.")
    run_update_cycle()
    run_scheduler()