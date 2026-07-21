import json
from typing import Iterator, Optional

from config import settings
from dto import CVEDto
from logger import log


def parse_csaf_document(doc: dict) -> Iterator[CVEDto]:
    document = doc.get("document", {})
    tracking_id = document.get("tracking", {}).get("id")
    if not tracking_id:
        log("[Парсер Ошибка] У документа нет document.tracking.id, пропускаем")
        return

    document_summary = _find_note(document.get("notes", []), category="summary")

    vulnerabilities = doc.get("vulnerabilities", [])
    if not vulnerabilities:
        return

    for index, vuln in enumerate(vulnerabilities):
        cve_number = vuln.get("cve")
        vuln_note = _find_note(vuln.get("notes", []), category="description")
        description = vuln_note or document_summary or "Описание отсутствует"
        cvss_score = _extract_cvss(vuln)
        raw_content = json.dumps(vuln, ensure_ascii=False)

        yield CVEDto(
            cve_number=cve_number,
            external_id=None if cve_number else f"{tracking_id}#{index}",
            description=description[:5000],
            cvss_score=cvss_score,
            raw_content=raw_content[:100000],
            source=settings.SOURCE_NAME,
        )


def _find_note(notes: list, category: str) -> Optional[str]:
    for note in notes:
        if note.get("category") == category and note.get("text"):
            return note["text"].strip()
    return None


def _extract_cvss(vuln: dict) -> Optional[float]:
    scores = vuln.get("scores", [])
    for score_entry in scores:
        cvss_v3 = score_entry.get("cvss_v3")
        if cvss_v3 and "baseScore" in cvss_v3:
            try:
                return float(cvss_v3["baseScore"])
            except (TypeError, ValueError):
                continue
        cvss_v2 = score_entry.get("cvss_v2")
        if cvss_v2 and "baseScore" in cvss_v2:
            try:
                return float(cvss_v2["baseScore"])
            except (TypeError, ValueError):
                continue
    return None