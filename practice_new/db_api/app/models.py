from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Index, Integer, String, Text

from app.db_session import Base


class CVEModel(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_number = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    source = Column(String(50), nullable=False)
    external_id = Column(String(255), nullable=True)
    raw_content = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index(
            "uq_cve_source_no_external_id",
            "cve_number",
            "source",
            unique=True,
            postgresql_where=(external_id.is_(None)),
        ),
        Index(
            "uq_source_external_id",
            "source",
            "external_id",
            unique=True,
            postgresql_where=(external_id.isnot(None)),
        ),
    )

    def __repr__(self) -> str:
        return f"<CVE {self.cve_number} ({self.source}): {self.cvss_score}>"


class ExploitModel(Base):
    __tablename__ = "exploits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    exploit_id = Column(String(255), nullable=False)
    cve_number = Column(String(50), nullable=True, index=True)
    title = Column(Text, nullable=True)
    url = Column(String(500), nullable=True)
    source = Column(String(50), nullable=False)
    published_date = Column(String(50), nullable=True)
    raw_content = Column(Text, nullable=True)
    llm_verdict = Column(String(30), nullable=True)
    llm_reasoning = Column(Text, nullable=True)
    llm_checked_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("uq_exploit_source_id", "source", "exploit_id", unique=True),
    )

    def __repr__(self) -> str:
        return f"<Exploit {self.exploit_id} ({self.source}) -> {self.cve_number}>"