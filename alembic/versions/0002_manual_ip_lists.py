"""Add user-defined IP lists and manual address editing support

Revision ID: 0002_manual_ip_lists
Revises: 0001_initial
Create Date: 2026-04-04 00:30:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_manual_ip_lists"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "iplists",
        sa.Column("flagUserDefined", sa.SmallInteger(), nullable=False, server_default="0"),
        schema="iplist",
    )
    op.alter_column("iplists", "url", existing_type=sa.Text(), nullable=True, schema="iplist")


def downgrade() -> None:
    op.alter_column("iplists", "url", existing_type=sa.Text(), nullable=False, schema="iplist")
    op.drop_column("iplists", "flagUserDefined", schema="iplist")
