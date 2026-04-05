"""Add description and comment to ipAddresses

Revision ID: 0003_ipaddr_desc_comment
Revises: 0002_manual_ip_lists
Create Date: 2026-04-04 01:00:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_ipaddr_desc_comment"
down_revision = "0002_manual_ip_lists"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ipAddresses",
        sa.Column("description", sa.Text(), nullable=True),
        schema="iplist",
    )
    op.add_column(
        "ipAddresses",
        sa.Column("comment", sa.Text(), nullable=True),
        schema="iplist",
    )


def downgrade() -> None:
    op.drop_column("ipAddresses", "comment", schema="iplist")
    op.drop_column("ipAddresses", "description", schema="iplist")
