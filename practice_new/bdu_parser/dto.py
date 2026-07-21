from typing import Optional

from pydantic import BaseModel


class CVEDto(BaseModel):
    cve_number: Optional[str] = None
    external_id: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    raw_content: Optional[str] = None
    source: str