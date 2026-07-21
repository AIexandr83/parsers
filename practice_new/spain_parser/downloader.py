import queue
import re
import threading
import time
from typing import Optional

import requests

from config import settings
from logger import log

_thread_local = threading.local()
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; CVE-Aggregator/1.0)"}
_PAGE_NUM_PATTERN = re.compile(r"page=(\d+)")


def _get_session() -> requests.Session:
    if not hasattr(_thread_local, "session"):
        _thread_local.session = requests.Session()
    return _thread_local.session


def fetch_page(page: int, retries: int = 3, backoff_seconds: int = 5) -> Optional[str]:
    url = f"{settings.BASE_URL}?field_vul_product=&page={page}"
    session = _get_session()
    for attempt in range(1, retries + 1):
        try:
            response = session.get(url, headers=_HEADERS, timeout=30)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            log(f"[Загрузка Ошибка] Попытка {attempt}/{retries} для страницы {page} не удалась: {e}")
            if attempt < retries:
                time.sleep(backoff_seconds)
    log(f"[Загрузка Ошибка] Страница {page} пропущена после {retries} попыток.")
    return None


def detect_last_page(first_page_html: str, fallback: int = 29854) -> int:
    numbers = [int(n) for n in _PAGE_NUM_PATTERN.findall(first_page_html)]
    if numbers:
        return max(numbers)
    log("[Загрузка Ошибка] Не удалось определить последнюю страницу, используем запасное значение.")
    return fallback


def _worker(work_queue: "queue.Queue[int]", results: dict, results_lock: threading.Lock) -> None:
    while True:
        try:
            page = work_queue.get_nowait()
        except queue.Empty:
            return

        html = fetch_page(page)
        with results_lock:
            results[page] = html

        time.sleep(settings.REQUEST_DELAY_SECONDS)


def fetch_pages_parallel(pages: list) -> dict:
    work_queue: "queue.Queue[int]" = queue.Queue()
    for page in pages:
        work_queue.put(page)

    results: dict = {}
    results_lock = threading.Lock()

    threads = [
        threading.Thread(target=_worker, args=(work_queue, results, results_lock), daemon=True)
        for _ in range(settings.MAX_WORKERS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return results