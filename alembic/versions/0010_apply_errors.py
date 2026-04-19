"""Add applyErrors table for per-command applicator failures.

Revision ID: 0010_apply_errors
Revises: 0009_firewall_list_state
Create Date: 2026-04-19 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0010_apply_errors"
down_revision = "0009_firewall_list_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "applyErrors",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("applyHistoryId", sa.BigInteger(), nullable=False),
        sa.Column("firewallsId", sa.BigInteger(), nullable=False),
        sa.Column("chunkIndex", sa.Integer(), nullable=True),
        sa.Column("lineIndex", sa.Integer(), nullable=True),
        sa.Column("commandText", sa.Text(), nullable=False),
        sa.Column("errorMessage", sa.Text(), nullable=False),
        sa.Column("occurredAt", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["applyHistoryId"], ["iplist.applyHistory.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["firewallsId"], ["iplist.firewalls.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="iplist",
    )
    op.create_index(
        "ix_applyErrors_flagInactive",
        "applyErrors",
        ["flagInactive"],
        schema="iplist",
    )
    op.create_index(
        "ix_applyErrors_applyHistoryId_occurredAt",
        "applyErrors",
        ["applyHistoryId", "occurredAt"],
        schema="iplist",
    )
    op.create_index(
        "ix_applyErrors_firewallsId_occurredAt",
        "applyErrors",
        ["firewallsId", "occurredAt"],
        schema="iplist",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_applyErrors_firewallsId_occurredAt",
        table_name="applyErrors",
        schema="iplist",
    )
    op.drop_index(
        "ix_applyErrors_applyHistoryId_occurredAt",
        table_name="applyErrors",
        schema="iplist",
    )
    op.drop_index(
        "ix_applyErrors_flagInactive",
        table_name="applyErrors",
        schema="iplist",
    )
    op.drop_table("applyErrors", schema="iplist")
