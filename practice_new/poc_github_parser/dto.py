from typing import Optional

from pydantic import BaseModel


class ExploitDto(BaseModel):
    exploit_id: str
    cve_number: Optional[str] = None
    title: Optional[str] = None
    url: Optional[str] = None
    published_date: Optional[str] = None
    raw_content: Optional[str] = None
    source: str