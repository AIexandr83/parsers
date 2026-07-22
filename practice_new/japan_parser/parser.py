import xml.etree.ElementTree as ET
from typing import Iterator, Optional

from config import settings
from dto import CVEDto
from logger import log


def _local_name(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


def _find_by_local_name(elem, name: str):
    for child in elem:
        if _local_name(child.tag) == name:
            return child
    return None


def _find_all_by_local_name(elem, name: str) -> list:
    return [child for child in elem if _local_name(child.tag) == name]


def parse_overview_page(xml_text: str) -> Iterator[CVEDto]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        log(f"[Парсер Ошибка] Не удалось разобрать XML страницы: {e}")
        return

    for elem in root.iter():
        if _local_name(elem.tag) != "item":
            continue
        yield from _parse_item(elem)


def _parse_item(item) -> Iterator[CVEDto]:
    identifier_elem = _find_by_local_name(item, "identifier")
    jvndb_id = identifier_elem.text.strip() if identifier_elem is not None and identifier_elem.text else None
    if not jvndb_id:
        return

    description_elem = _find_by_local_name(item, "description")
    description = description_elem.text.strip() if description_elem is not None and description_elem.text else "Описание отсутствует"

    cvss_score = _extract_cvss(item)
    cve_numbers = _extract_cve_references(item)
    raw_content = ET.tostring(item, encoding="unicode")

    if cve_numbers:
        for cve_number in cve_numbers:
            yield CVEDto(
                cve_number=cve_number,
                external_id=None,
                description=description[:5000],
                cvss_score=cvss_score,
                raw_content=raw_content[:100000],
                source=settings.SOURCE_NAME,
            )
    else:
        yield CVEDto(
            cve_number=jvndb_id,
            external_id=jvndb_id,
            description=description[:5000],
            cvss_score=cvss_score,
            raw_content=raw_content[:100000],
            source=settings.SOURCE_NAME,
        )


def _extract_cve_references(item) -> list:
    cve_numbers = []
    for ref in _find_all_by_local_name(item, "references"):
        if ref.get("source") == "CVE" and ref.get("id"):
            cve_numbers.append(ref.get("id").strip())
    return cve_numbers


def _extract_cvss(item) -> Optional[float]:
    cvss_entries = _find_all_by_local_name(item, "cvss")
    v3_score = None
    v2_score = None

    for entry in cvss_entries:
        version = entry.get("version", "")
        score_attr = entry.get("score")
        if not score_attr:
            continue
        try:
            score = float(score_attr)
        except ValueError:
            continue

        if version.startswith("3"):
            v3_score = score
        elif version.startswith("2"):
            v2_score = score

    return v3_score if v3_score is not None else v2_score