from typing import Optional

from pydantic import BaseModel, Field


class CVEIn(BaseModel):
    cve_number: Optional[str] = Field(None, max_length=50)
    external_id: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    raw_content: Optional[str] = None
    source: str = Field(..., max_length=50)


class CVEBulkIn(BaseModel):
    items: list[CVEIn]


class BulkUpsertResult(BaseModel):
    received: int
    saved: int


class CVERecordOut(BaseModel):
    external_id: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    raw_content: Optional[str] = None
    updated_at: Optional[str] = None


class CVEMergedOut(BaseModel):
    cve_number: str
    max_cvss_score: Optional[float] = None
    total_records: int
    sources: dict[str, list[CVERecordOut]]


class SearchResultItem(BaseModel):
    cve_number: str
    source: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None


class SearchResponse(BaseModel):
    query: str
    total_found: int
    results: list[SearchResultItem]


class ExploitIn(BaseModel):
    exploit_id: str = Field(..., max_length=255)
    cve_number: Optional[str] = Field(None, max_length=50)
    title: Optional[str] = None
    url: Optional[str] = Field(None, max_length=500)
    published_date: Optional[str] = Field(None, max_length=50)
    raw_content: Optional[str] = None
    source: str = Field(..., max_length=50)


class ExploitBulkIn(BaseModel):
    items: list[ExploitIn]


class ExploitOut(BaseModel):
    exploit_id: str
    cve_number: Optional[str] = None
    title: Optional[str] = None
    url: Optional[str] = None
    source: str
    published_date: Optional[str] = None
    llm_verdict: Optional[str] = None
    llm_reasoning: Optional[str] = None
    updated_at: Optional[str] = None


class ExploitsForCveOut(BaseModel):
    cve_number: str
    total_found: int
    exploits: list[ExploitOut]


class CombinedCveResult(BaseModel):
    cve_number: str
    source: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    exploits: list[ExploitOut] = []


class CombinedSearchResponse(BaseModel):
    query: str
    cves: list[CombinedCveResult]
    exploits: list[ExploitOut]