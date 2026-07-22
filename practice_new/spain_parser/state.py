import os
from datetime import datetime
from typing import Optional

from config import settings


def get_last_run_date() -> Optional[datetime]:
    if not os.path.exists(settings.STATE_FILE):
        return None
    try:
        with open(settings.STATE_FILE, "r") as f:
            content = f.read().strip()
        return datetime.fromisoformat(content)
    except (ValueError, OSError):
        return None


def mark_run_complete(timestamp: datetime) -> None:
    os.makedirs(settings.STATE_DIR, exist_ok=True)
    with open(settings.STATE_FILE, "w") as f:
        f.write(timestamp.isoformat())