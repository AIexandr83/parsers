import re
import xml.etree.ElementTree as ET
from typing import Iterator, Optional

from config import settings
from dto import CVEDto
from logger import log

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")
_SCORE_PATTERN = re.compile(r"\b\d{1,2}\.\d\b")


def parse_feed(xml_text: str) -> Iterator[CVEDto]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        log(f"[Парсер Ошибка] Не удалось разобрать XML фида: {e}")
        return

    for item in root.iter("item"):
        dto = _parse_item(item)
        if dto:
            yield dto


def _parse_item(item) -> Optional[CVEDto]:
    title_elem = item.find("title")
    link_elem = item.find("link")
    description_elem = item.find("description")

    title = title_elem.text.strip() if title_elem is not None and title_elem.text else ""
    link = link_elem.text.strip() if link_elem is not None and link_elem.text else None
    description = description_elem.text.strip() if description_elem is not None and description_elem.text else ""

    if not description:
        return None

    cve_match = _CVE_PATTERN.search(title) or _CVE_PATTERN.search(description)
    cve_number = cve_match.group(0) if cve_match else None

    cvss_score = _extract_cvss(description, cve_number)
    raw_content = ET.tostring(item, encoding="unicode")

    return CVEDto(
        cve_number=cve_number,
        external_id=None if cve_number else link,
        description=description[:5000],
        cvss_score=cvss_score,
        raw_content=raw_content[:100000],
        source=settings.SOURCE_NAME,
    )


def _extract_cvss(description: str, cve_number: Optional[str]) -> Optional[float]:
    if not cve_number:
        return None

    for line in description.split("\n"):
        if cve_number in line:
            match = _SCORE_PATTERN.search(line)
            if match:
                try:
                    score = float(match.group(0))
                    if 0.0 <= score <= 10.0:
                        return score
                except ValueError:
                    continue
    return None