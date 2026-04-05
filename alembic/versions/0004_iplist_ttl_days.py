"""Move TTL days from global configuration to per-IP-list

Revision ID: 0004_iplist_ttl_days
Revises: 0003_ipaddr_desc_comment
Create Date: 2026-04-04 12:00:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_iplist_ttl_days"
down_revision = "0003_ipaddr_desc_comment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add ttlDays column to iplists (nullable — app defaults to 7 when NULL)
    op.add_column(
        "iplists",
        sa.Column("ttlDays", sa.Integer(), nullable=True),
        schema="iplist",
    )
    # Remove the now-redundant global configuration row
    op.execute(
        "DELETE FROM iplist.configuration WHERE \"configurationItem\" = 'applicatorTTLDays'"
    )


def downgrade() -> None:
    op.drop_column("iplists", "ttlDays", schema="iplist")
    # Re-insert the global TTL config row with its default value
    op.execute(
        """
        INSERT INTO iplist.configuration
            ("configurationItem", "configurationHelp", "configurationItemValue",
             "createDate", "updateDate", "flagInactive")
        VALUES
            ('applicatorTTLDays',
             'How long MikroTik keeps the dynamic address-list entries in memory.',
             '7',
             NOW(), NOW(), 0)
        ON CONFLICT DO NOTHING
        """
    )
