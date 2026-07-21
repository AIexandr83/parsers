from datetime import datetime
from typing import List

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.llm_client import analyze_exploit_text
from app.models import CVEModel, ExploitModel
from app.schemas import (
    CombinedCveResult,
    CombinedSearchResponse,
    CVEIn,
    CVEMergedOut,
    CVERecordOut,
    ExploitIn,
    ExploitOut,
    SearchResultItem,
)


def bulk_upsert_cves(db: Session, items: List[CVEIn]) -> int:
    if not items:
        return 0

    plain_items = [i for i in items if not i.external_id]
    external_items = [i for i in items if i.external_id]

    saved = 0
    if plain_items:
        saved += _blind_upsert(db, plain_items)
    if external_items:
        saved += _upsert_with_external_id(db, external_items)

    return saved


def _blind_upsert(db: Session, items: List[CVEIn]) -> int:
    deduped: dict[tuple, CVEIn] = {}
    for item in items:
        deduped[(item.cve_number, item.source)] = item

    values = [item.model_dump(exclude={"external_id"}) for item in deduped.values()]

    stmt = insert(CVEModel).values(values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["cve_number", "source"],
        index_where=text("external_id IS NULL"),
        set_={
            "description": stmt.excluded.description,
            "cvss_score": stmt.excluded.cvss_score,
            "raw_content": stmt.excluded.raw_content,
            "updated_at": datetime.utcnow(),
        },
    )
    db.execute(stmt)
    db.commit()
    return len(values)


def _upsert_with_external_id(db: Session, items: List[CVEIn]) -> int:
    saved = 0

    for item in items:
        existing = (
            db.query(CVEModel)
            .filter(CVEModel.source == item.source, CVEModel.external_id == item.external_id)
            .first()
        )

        if existing:
            if item.cve_number:
                existing.cve_number = item.cve_number
            existing.description = item.description
            existing.cvss_score = item.cvss_score
            existing.raw_content = item.raw_content
            existing.updated_at = datetime.utcnow()
        else:
            cve_number = item.cve_number or item.external_id
            db.add(
                CVEModel(
                    cve_number=cve_number,
                    external_id=item.external_id,
                    description=item.description,
                    cvss_score=item.cvss_score,
                    raw_content=item.raw_content,
                    source=item.source,
                )
            )

        saved += 1

    db.commit()
    return saved


def get_merged_cve(db: Session, cve_number: str) -> CVEMergedOut | None:
    rows = db.query(CVEModel).filter(CVEModel.cve_number == cve_number).all()

    if not rows:
        return None

    sources: dict[str, list[CVERecordOut]] = {}
    max_cvss: float | None = None

    for row in rows:
        record = CVERecordOut(
            external_id=row.external_id,
            description=row.description,
            cvss_score=row.cvss_score,
            raw_content=row.raw_content,
            updated_at=row.updated_at.isoformat() if row.updated_at else None,
        )
        sources.setdefault(row.source, []).append(record)

        if row.cvss_score is not None:
            if max_cvss is None or row.cvss_score > max_cvss:
                max_cvss = row.cvss_score

    return CVEMergedOut(
        cve_number=cve_number,
        max_cvss_score=max_cvss,
        total_records=len(rows),
        sources=sources,
    )


def search_cves(db: Session, query: str, limit: int = 20) -> tuple[int, list[SearchResultItem]]:
    sql = text(
        """
        SELECT cve_number, source, description, cvss_score
        FROM cves
        WHERE to_tsvector('simple', coalesce(description, '') || ' ' || coalesce(raw_content, ''))
              @@ plainto_tsquery('simple', :query)
        LIMIT :limit
        """
    )
    rows = db.execute(sql, {"query": query, "limit": limit}).fetchall()

    count_sql = text(
        """
        SELECT COUNT(*)
        FROM cves
        WHERE to_tsvector('simple', coalesce(description, '') || ' ' || coalesce(raw_content, ''))
              @@ plainto_tsquery('simple', :query)
        """
    )
    total = db.execute(count_sql, {"query": query}).scalar()

    results = [
        SearchResultItem(cve_number=r.cve_number, source=r.source, description=r.description, cvss_score=r.cvss_score)
        for r in rows
    ]
    return total, results


def bulk_upsert_exploits(db: Session, items: List[ExploitIn]) -> int:
    if not items:
        return 0

    deduped: dict[tuple, ExploitIn] = {}
    for item in items:
        deduped[(item.source, item.exploit_id)] = item

    values = [item.model_dump() for item in deduped.values()]

    stmt = insert(ExploitModel).values(values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["source", "exploit_id"],
        set_={
            "cve_number": stmt.excluded.cve_number,
            "title": stmt.excluded.title,
            "url": stmt.excluded.url,
            "published_date": stmt.excluded.published_date,
            "raw_content": stmt.excluded.raw_content,
            "updated_at": datetime.utcnow(),
        },
    )
    db.execute(stmt)
    db.commit()
    return len(values)


def analyze_exploit_if_needed(db: Session, exploit: ExploitModel) -> None:
    """Анализирует эксплойт через LLM, только если ещё не анализировали (кэш в БД)."""
    if exploit.llm_verdict is not None:
        return

    result = analyze_exploit_text(exploit.title, exploit.raw_content)
    if result is None:
        return

    exploit.llm_verdict = result["verdict"]
    exploit.llm_reasoning = result["reasoning"]
    exploit.llm_checked_at = datetime.utcnow()
    db.commit()


def _exploit_to_out(row: ExploitModel) -> ExploitOut:
    return ExploitOut(
        exploit_id=row.exploit_id,
        cve_number=row.cve_number,
        title=row.title,
        url=row.url,
        source=row.source,
        published_date=row.published_date,
        llm_verdict=row.llm_verdict,
        llm_reasoning=row.llm_reasoning,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


def get_exploits_for_cve(db: Session, cve_number: str, analyze: bool = False) -> list[ExploitOut]:
    rows = db.query(ExploitModel).filter(ExploitModel.cve_number == cve_number).all()
    if analyze:
        for row in rows:
            analyze_exploit_if_needed(db, row)
    return [_exploit_to_out(row) for row in rows]


def search_combined(db: Session, query: str, limit: int = 20, analyze: bool = False) -> CombinedSearchResponse:
    cve_sql = text(
        """
        SELECT cve_number, source, description, cvss_score
        FROM cves
        WHERE to_tsvector('simple', coalesce(description, '') || ' ' || coalesce(raw_content, ''))
              @@ plainto_tsquery('simple', :query)
        LIMIT :limit
        """
    )
    cve_rows = db.execute(cve_sql, {"query": query, "limit": limit}).fetchall()

    cve_results: list[CombinedCveResult] = []
    for row in cve_rows:
        exploits = get_exploits_for_cve(db, row.cve_number, analyze=analyze)
        cve_results.append(
            CombinedCveResult(
                cve_number=row.cve_number,
                source=row.source,
                description=row.description,
                cvss_score=row.cvss_score,
                exploits=exploits,
            )
        )

    exploit_sql = text(
        """
        SELECT id
        FROM exploits
        WHERE to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(raw_content, ''))
              @@ plainto_tsquery('simple', :query)
        LIMIT :limit
        """
    )
    exploit_id_rows = db.execute(exploit_sql, {"query": query, "limit": limit}).fetchall()
    exploit_ids = [r.id for r in exploit_id_rows]

    exploit_models = db.query(ExploitModel).filter(ExploitModel.id.in_(exploit_ids)).all()
    if analyze:
        for row in exploit_models:
            analyze_exploit_if_needed(db, row)
    exploit_results = [_exploit_to_out(row) for row in exploit_models]

    return CombinedSearchResponse(query=query, cves=cve_results, exploits=exploit_results)