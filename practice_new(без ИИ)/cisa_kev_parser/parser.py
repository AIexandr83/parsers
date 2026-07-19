import json
from typing import Iterator, Optional

from config import settings
from dto import ExploitDto


def parse_kev_entry(entry: dict) -> Optional[ExploitDto]:
    cve_number = entry.get("cveID")
    if not cve_number:
        return None

    return ExploitDto(
        exploit_id=cve_number,  # в KEV одна запись = один CVE, отдельного ID нет
        cve_number=cve_number,
        title=entry.get("vulnerabilityName"),
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        published_date=entry.get("dateAdded"),
        raw_content=json.dumps(entry, ensure_ascii=False)[:20000],
        source=settings.SOURCE_NAME,
    )


def parse_kev_catalog(vulnerabilities: list) -> Iterator[ExploitDto]:
    for entry in vulnerabilities:
        dto = parse_kev_entry(entry)
        if dto:
            yield dto