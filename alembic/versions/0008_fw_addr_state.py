"""Add firewallAddressState table for delta push tracking

Revision ID: 0008_fw_addr_state
Revises: 0007_apply_ip_counts
Create Date: 2026-04-12 00:00:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0008_fw_addr_state"
down_revision = "0007_apply_ip_counts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "firewallAddressState",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("firewallsId", sa.BigInteger(), sa.ForeignKey("iplist.firewalls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("listName", sa.Text(), nullable=False),
        sa.Column("ipAddress", sa.Text(), nullable=False),
        sa.Column("ttlDays", sa.Integer(), nullable=False, server_default="7"),
        sa.Column("generationTag", sa.Text(), nullable=False),
        sa.Column("lastPushedAt", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        schema="iplist",
    )
    op.create_index("ix_firewallAddressState_flagInactive", "firewallAddressState", ["flagInactive"], schema="iplist")
    op.create_index("ix_firewallAddressState_firewallsId", "firewallAddressState", ["firewallsId"], schema="iplist")
    op.create_index(
        "ux_firewallAddressState_firewall_list_addr",
        "firewallAddressState",
        ["firewallsId", "listName", "ipAddress"],
        unique=True,
        schema="iplist",
    )


def downgrade() -> None:
    op.drop_index("ux_firewallAddressState_firewall_list_addr", table_name="firewallAddressState", schema="iplist")
    op.drop_index("ix_firewallAddressState_firewallsId", table_name="firewallAddressState", schema="iplist")
    op.drop_index("ix_firewallAddressState_flagInactive", table_name="firewallAddressState", schema="iplist")
    op.drop_table("firewallAddressState", schema="iplist")
