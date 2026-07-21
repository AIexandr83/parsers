import re
from datetime import datetime
from typing import List, Optional

from bs4 import BeautifulSoup

from logger import log

_CVE_HEADING_PATTERN = re.compile(r"^(CVE-\d{4}-\d+)$")
_DATE_PATTERN = re.compile(r"(\d{2}/\d{2}/\d{4})")


class SpainRecord:
    def __init__(self, cve_number: str, description: str, pub_date: Optional[datetime], raw_content: str):
        self.cve_number = cve_number
        self.description = description
        self.pub_date = pub_date
        self.raw_content = raw_content


def parse_list_page(html: str) -> List[SpainRecord]:
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        log(f"[Парсер Ошибка] Не удалось разобрать HTML страницы: {e}")
        return []

    text = soup.get_text("\n")
    lines = [line.strip() for line in text.split("\n") if line.strip()]

    records = []
    i = 0
    while i < len(lines):
        match = _CVE_HEADING_PATTERN.match(lines[i])
        if not match:
            i += 1
            continue

        cve_number = match.group(1)
        block_lines = []
        j = i + 1
        while j < len(lines) and not _CVE_HEADING_PATTERN.match(lines[j]):
            block_lines.append(lines[j])
            j += 1

        pub_date = _extract_pub_date(block_lines)
        description = _extract_description(block_lines)
        raw_content = "\n".join(block_lines)

        records.append(SpainRecord(cve_number, description, pub_date, raw_content))
        i = j

    return records


def _extract_pub_date(block_lines: List[str]) -> Optional[datetime]:
    for idx, line in enumerate(block_lines):
        if "Fecha de publicaci" in line:
            match = _DATE_PATTERN.search(line)
            if not match and idx + 1 < len(block_lines):
                match = _DATE_PATTERN.search(block_lines[idx + 1])
            if match:
                try:
                    return datetime.strptime(match.group(1), "%d/%m/%Y")
                except ValueError:
                    return None
    return None


def _extract_description(block_lines: List[str]) -> str:
    candidates = [line for line in block_lines if len(line) > 60]
    return candidates[0] if candidates else "Описание отсутствует"