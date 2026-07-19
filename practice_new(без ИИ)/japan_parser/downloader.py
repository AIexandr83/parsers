import queue
import re
import threading
import time
from datetime import datetime
from typing import Optional, Tuple

import requests

from config import settings
from logger import log

_thread_local = threading.local()


def _get_session() -> requests.Session:
    #У каждого потока — своя сессия.
    if not hasattr(_thread_local, "session"):
        _thread_local.session = requests.Session()
    return _thread_local.session


def _build_params(start_item: int, date_from: datetime, date_to: datetime) -> dict:
    return {
        "method": "getVulnOverviewList",
        "feed": "hnd",
        "rangeDatePublished": "n",
        "rangeDatePublic": "n",
        "rangeDateFirstPublished": "n",
        "datePublishedStartY": date_from.year,
        "datePublishedStartM": date_from.month,
        "datePublishedStartD": date_from.day,
        "datePublishedEndY": date_to.year,
        "datePublishedEndM": date_to.month,
        "datePublishedEndD": date_to.day,
        "startItem": start_item,
    }


def fetch_page(
    start_item: int,
    date_from: datetime,
    date_to: datetime,
    retries: int = 3,
    backoff_seconds: int = 5,
) -> Optional[Tuple[str, int]]:
    session = _get_session()
    params = _build_params(start_item, date_from, date_to)

    for attempt in range(1, retries + 1):
        try:
            response = session.get(settings.BASE_URL, params=params, timeout=30)
            response.raise_for_status()
            total_res = _extract_total_res(response.text)

            if total_res == 0:
                log(f"[Загрузка Ошибка] Попытка {attempt}/{retries} для startItem={start_item}: totalRes не найден.")
                if attempt < retries:
                    time.sleep(backoff_seconds)
                continue

            return response.text, total_res
        except requests.RequestException as e:
            log(f"[Загрузка Ошибка] Попытка {attempt}/{retries} для startItem={start_item} не удалась: {e}")
            if attempt < retries:
                time.sleep(backoff_seconds)

    log(f"[Загрузка Ошибка] Страница startItem={start_item} пропущена после {retries} попыток.")
    return None


def _extract_total_res(xml_text: str) -> int:
    match = re.search(r'totalRes="(\d+)"', xml_text)
    return int(match.group(1)) if match else 0


def _worker(work_queue: "queue.Queue[int]", date_from: datetime, date_to: datetime, results: "queue.Queue") -> None:
    # Один поток: последовательно забирает номера страниц из общей очереди и качает их каждый раз с собственной паузой между СВОИМИ
    
    while True:
        try:
            start_item = work_queue.get_nowait()
        except queue.Empty:
            return

        result = fetch_page(start_item, date_from, date_to)
        results.put(result)
        time.sleep(settings.REQUEST_DELAY_SECONDS)


def fetch_all_pages(date_from: datetime, date_to: datetime):

    #Сначала синхронно получаем первую страницу.
    log("[Загрузка] Запрашиваем записи с 1...")
    first = fetch_page(1, date_from, date_to)
    if first is None:
        log("[Загрузка Ошибка] Не удалось получить даже первую страницу, прерываем цикл.")
        return

    xml_text, total_res = first
    yield xml_text

    remaining_items = list(range(1 + settings.PAGE_SIZE, total_res + 1, settings.PAGE_SIZE))
    if not remaining_items:
        return

    log(
        f"[Загрузка] Всего записей: {total_res}, страниц: {len(remaining_items) + 1}. "
        f"Параллельных потоков: {settings.MAX_WORKERS}."
    )

    work_queue: "queue.Queue[int]" = queue.Queue()
    for start_item in remaining_items:
        work_queue.put(start_item)

    results: "queue.Queue" = queue.Queue()
    threads = [
        threading.Thread(target=_worker, args=(work_queue, date_from, date_to, results), daemon=True)
        for _ in range(settings.MAX_WORKERS)
    ]
    for t in threads:
        t.start()

    received = 0
    total_to_receive = len(remaining_items)
    while received < total_to_receive:
        result = results.get()
        received += 1
        if result is not None:
            xml_text, _ = result
            yield xml_text
        if received % 200 == 0:
            log(f"[Загрузка] Получено страниц: {received}/{total_to_receive}...")

    for t in threads:
        t.join()