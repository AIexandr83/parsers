"""initial schema — cves and exploits tables with full-text search

Revision ID: 0001_init_schema
Revises:
Create Date: 2026-07-19 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001_init_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Таблица cves -------------------------------------------------
    op.create_table(
        "cves",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_number", sa.String(length=50), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("raw_content", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_cves_cve_number", "cves", ["cve_number"])

    # Уникальность (cve_number, source) — только для записей БЕЗ external_id
    # (обычные источники: NVD, Германия, Испания, Канада, JVN с CVE и т.д.)
    op.execute(
        """
        CREATE UNIQUE INDEX uq_cve_source_no_external_id
        ON cves (cve_number, source)
        WHERE external_id IS NULL
        """
    )
    # Уникальность (source, external_id) — только для записей С external_id
    # (БДУ ФСТЭК, JVN и Германия без известного CVE — свои родные номера)
    op.execute(
        """
        CREATE UNIQUE INDEX uq_source_external_id
        ON cves (source, external_id)
        WHERE external_id IS NOT NULL
        """
    )
    # Полнотекстовый поиск по краткому описанию + сырому документу источника
    op.execute(
        """
        CREATE INDEX ix_cves_fulltext ON cves
        USING GIN (to_tsvector('simple', coalesce(description, '') || ' ' || coalesce(raw_content, '')))
        """
    )

    # --- Таблица exploits -----------------------------------------------
    op.create_table(
        "exploits",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("exploit_id", sa.String(length=255), nullable=False),
        sa.Column("cve_number", sa.String(length=50), nullable=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("url", sa.String(length=500), nullable=True),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("published_date", sa.String(length=50), nullable=True),
        sa.Column("raw_content", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_exploits_cve_number", "exploits", ["cve_number"])
    op.create_index("uq_exploit_source_id", "exploits", ["source", "exploit_id"], unique=True)
    op.execute(
        """
        CREATE INDEX ix_exploits_fulltext ON exploits
        USING GIN (to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(raw_content, '')))
        """
    )


def downgrade() -> None:
    op.drop_table("exploits")
    op.execute("DROP INDEX IF EXISTS ix_cves_fulltext")
    op.execute("DROP INDEX IF EXISTS uq_source_external_id")
    op.execute("DROP INDEX IF EXISTS uq_cve_source_no_external_id")
    op.drop_table("cves")