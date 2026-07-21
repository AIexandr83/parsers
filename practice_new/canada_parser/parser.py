import json
import re
from datetime import datetime
from typing import Iterator, Optional

from bs4 import BeautifulSoup

from config import settings
from dto import CVEDto
from logger import log

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")


def parse_threat(item: dict) -> Iterator[CVEDto]:
    title = item.get("title") or ""
    uuid = item.get("uuid")
    summary = item.get("summary")
    body_html = item.get("body")

    body_text = _strip_html(body_html) if body_html else ""
    description = summary or body_text or "Описание отсутствует"
    raw_content = json.dumps(item, ensure_ascii=False)[:100000]

    combined_text = f"{title}\n{body_text}"
    cve_numbers = sorted(set(_CVE_PATTERN.findall(combined_text)))

    if cve_numbers:
        for cve_number in cve_numbers:
            yield CVEDto(
                cve_number=cve_number,
                external_id=None,
                description=description[:5000],
                cvss_score=None,
                raw_content=raw_content,
                source=settings.SOURCE_NAME,
            )
    else:
        yield CVEDto(
            cve_number=uuid,
            external_id=uuid,
            description=description[:5000],
            cvss_score=None,
            raw_content=raw_content,
            source=settings.SOURCE_NAME,
        )


def _strip_html(html) -> str:
    try:
        if isinstance(html, list):
            html = " ".join(html)
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(" ", strip=True)
    except Exception as e:
        log(f"[Парсер Ошибка] Не удалось разобрать HTML тела записи: {e}")
        return ""


def get_modified_date(item: dict) -> Optional[datetime]:
    ts = item.get("date_modified_ts")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None