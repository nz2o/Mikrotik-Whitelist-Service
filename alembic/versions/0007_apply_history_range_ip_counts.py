"""Add applyHistory range and covered IP count columns

Revision ID: 0007_apply_ip_counts
Revises: 0006_add_performance_indexes
Create Date: 2026-04-12 00:00:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0007_apply_ip_counts"
down_revision = "0006_add_performance_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "applyHistory",
        sa.Column("totalRangeCount", sa.Integer(), nullable=True),
        schema="iplist",
    )
    op.add_column(
        "applyHistory",
        sa.Column("totalIpCount", sa.BigInteger(), nullable=True),
        schema="iplist",
    )


def downgrade() -> None:
    op.drop_column("applyHistory", "totalIpCount", schema="iplist")
    op.drop_column("applyHistory", "totalRangeCount", schema="iplist")
