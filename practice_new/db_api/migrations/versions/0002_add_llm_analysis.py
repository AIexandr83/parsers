"""add LLM analysis fields to exploits

Revision ID: 0002_add_llm_analysis
Revises: 0001_init_schema
Create Date: 2026-07-19 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_add_llm_analysis"
down_revision: Union[str, None] = "0001_init_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("exploits", sa.Column("llm_verdict", sa.String(length=30), nullable=True))
    op.add_column("exploits", sa.Column("llm_reasoning", sa.Text(), nullable=True))
    op.add_column("exploits", sa.Column("llm_checked_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("exploits", "llm_checked_at")
    op.drop_column("exploits", "llm_reasoning")
    op.drop_column("exploits", "llm_verdict")