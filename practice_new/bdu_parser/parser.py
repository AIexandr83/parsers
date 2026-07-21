import xml.etree.ElementTree as ET
from typing import Iterator, Optional

from config import settings
from dto import CVEDto
from logger import log


def iter_cve_dtos(export_xml_path: str) -> Iterator[CVEDto]:
    context = ET.iterparse(export_xml_path, events=("end",))

    for _, elem in context:
        if elem.tag != "vul":
            continue

        dto = _parse_vul_element(elem)
        if dto:
            yield dto

        elem.clear()


def _parse_vul_element(elem) -> Optional[CVEDto]:
    try:
        bdu_id = _text(elem, "identifier")
        if not bdu_id:
            return None

        description = _text(elem, "description") or "Описание отсутствует"
        cvss_score = _extract_cvss(elem)
        cve_number = _extract_cve_reference(elem)
        raw_content = ET.tostring(elem, encoding="unicode")

        return CVEDto(
            cve_number=cve_number,
            external_id=bdu_id,
            description=description[:5000],
            cvss_score=cvss_score,
            raw_content=raw_content[:100000],
            source=settings.SOURCE_NAME,
        )
    except Exception as e:
        log(f"[Парсер Ошибка] Не удалось разобрать запись: {e}")
        return None


def _text(elem, tag: str) -> Optional[str]:
    found = elem.find(tag)
    return found.text.strip() if found is not None and found.text else None


def _extract_cvss(elem) -> Optional[float]:
    cvss_elem = elem.find("cvss")
    if cvss_elem is None:
        return None
    vector_elem = cvss_elem.find("vector")
    if vector_elem is None:
        return None
    score_attr = vector_elem.get("score")
    try:
        return float(score_attr) if score_attr else None
    except ValueError:
        return None


def _extract_cve_reference(elem) -> Optional[str]:
    identifiers_elem = elem.find("identifiers")
    if identifiers_elem is None:
        return None
    for ident in identifiers_elem.findall("identifier"):
        if ident.text and ident.text.strip().startswith("CVE-"):
            return ident.text.strip()
    return None