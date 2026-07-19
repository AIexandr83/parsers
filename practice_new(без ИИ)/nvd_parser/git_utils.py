import os
import subprocess
from typing import Optional

from config import settings
from logger import log


def run_git_command(command: list, cwd: Optional[str] = None) -> bool:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if result.returncode != 0:
        log(f"[Git Ошибка] Команда {' '.join(command)} завершилась с ошибкой: {result.stderr.strip()}")
    return result.returncode == 0


def init_repository() -> bool:
    if not os.path.exists(settings.REPO_PATH) or not os.listdir(settings.REPO_PATH):
        log("[Git] Клонируем официальный репозиторий cvelistV5 (это займёт время)...")
        success = run_git_command(["git", "clone", settings.REPO_URL, settings.REPO_PATH])
        if not success:
            log("[Git КРИТ] Не удалось склонировать репозиторий.")
            raise SystemExit(1)
        log("[Git] Репозиторий успешно склонирован.")
        return True
    return False


def pull_repository() -> bool:
    log("[Git] Выполняем git pull...")
    return run_git_command(["git", "pull"], cwd=settings.REPO_PATH)
