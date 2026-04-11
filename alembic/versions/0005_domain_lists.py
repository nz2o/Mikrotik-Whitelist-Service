"""Add domainLists and domains tables for domain-based feeds

Revision ID: 0005_domain_lists
Revises: 0004_iplist_ttl_days
Create Date: 2026-04-10 00:00:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_domain_lists"
down_revision = "0004_iplist_ttl_days"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "domainLists",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("flagUserDefined", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("listType", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("lastSync", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fetchFrequencyHours", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ttlDays", sa.Integer(), nullable=True),
        schema="iplist",
    )
    op.create_index("ix_domainLists_flagInactive", "domainLists", ["flagInactive"], schema="iplist")
    op.execute(
        """
        CREATE TRIGGER trg_domainLists_update_date
        BEFORE UPDATE ON iplist."domainLists"
        FOR EACH ROW EXECUTE FUNCTION iplist.set_update_date();
        """
    )

    op.create_table(
        "domains",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("domainName", sa.Text(), nullable=False),
        sa.Column("ipAddress", sa.Text(), nullable=False),
        sa.Column("domainListsId", sa.BigInteger(), sa.ForeignKey("iplist.domainLists.id", ondelete="CASCADE"), nullable=False),
        schema="iplist",
    )
    op.create_index("ix_domains_flagInactive", "domains", ["flagInactive"], schema="iplist")
    op.create_index(
        "ix_domains_domainListsId_flagInactive",
        "domains",
        ["domainListsId", "flagInactive"],
        schema="iplist",
    )
    op.execute(
        """
        CREATE TRIGGER trg_domains_update_date
        BEFORE UPDATE ON iplist.domains
        FOR EACH ROW EXECUTE FUNCTION iplist.set_update_date();
        """
    )


def downgrade() -> None:
    op.execute('DROP TABLE IF EXISTS iplist.domains CASCADE')
    op.execute('DROP TABLE IF EXISTS iplist."domainLists" CASCADE')
