from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session

from app.crud import (
    bulk_upsert_cves,
    bulk_upsert_exploits,
    get_exploits_for_cve,
    get_merged_cve,
    search_cves,
    search_combined,
)
from app.db_session import get_db
from app.schemas import (
    BulkUpsertResult,
    CombinedSearchResponse,
    CVEBulkIn,
    CVEMergedOut,
    ExploitBulkIn,
    ExploitsForCveOut,
    SearchResponse,
)

app = FastAPI(title="CVE DB API", version="1.0.0")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/cves/bulk", response_model=BulkUpsertResult)
def upsert_cves(payload: CVEBulkIn, db: Session = Depends(get_db)):
    saved = bulk_upsert_cves(db, payload.items)
    return BulkUpsertResult(received=len(payload.items), saved=saved)


@app.get("/cves/search", response_model=SearchResponse)
def search(q: str = Query(..., min_length=2), limit: int = Query(20, le=100), db: Session = Depends(get_db)):
    """Старый эндпоинт — поиск только по CVE, оставлен для обратной совместимости."""
    total, results = search_cves(db, q, limit)
    return SearchResponse(query=q, total_found=total, results=results)


@app.get("/search", response_model=CombinedSearchResponse)
def search_everything(q: str = Query(..., min_length=2), limit: int = Query(20, le=100), db: Session = Depends(get_db)):
    return search_combined(db, q, limit)


@app.get("/cves/{cve_number}", response_model=CVEMergedOut)
def read_merged_cve(cve_number: str, db: Session = Depends(get_db)):
    result = get_merged_cve(db, cve_number)
    if result is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_number} не найден")
    return result


@app.post("/exploits/bulk", response_model=BulkUpsertResult)
def upsert_exploits(payload: ExploitBulkIn, db: Session = Depends(get_db)):
    saved = bulk_upsert_exploits(db, payload.items)
    return BulkUpsertResult(received=len(payload.items), saved=saved)


@app.get("/exploits/{cve_number}", response_model=ExploitsForCveOut)
def read_exploits_for_cve(cve_number: str, db: Session = Depends(get_db)):
    exploits = get_exploits_for_cve(db, cve_number)
    return ExploitsForCveOut(cve_number=cve_number, total_found=len(exploits), exploits=exploits)