import os
from datetime import datetime
from typing import Optional

from config import settings


def get_last_run_date() -> Optional[datetime]:
    """
    Возвращает дату последнего УСПЕШНО завершённого запуска, или None,
    если это самый первый запуск контейнера за всю историю (маркера ещё нет).
    """
    if not os.path.exists(settings.STATE_FILE):
        return None
    try:
        with open(settings.STATE_FILE, "r") as f:
            content = f.read().strip()
        return datetime.strptime(content, "%Y-%m-%d")
    except (ValueError, OSError):
        return None


def mark_run_complete(run_date: datetime) -> None:
    """Записывает дату успешного завершения — используется для следующего инкрементального запуска."""
    os.makedirs(settings.STATE_DIR, exist_ok=True)
    with open(settings.STATE_FILE, "w") as f:
        f.write(run_date.strftime("%Y-%m-%d"))