"""Initial schema: iplist schema, all tables, triggers, indexes, seed data

Revision ID: 0001_initial
Revises: 
Create Date: 2026-04-04 00:00:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Schema ────────────────────────────────────────────────────────────────
    op.execute("CREATE SCHEMA IF NOT EXISTS iplist")

    # ── updateDate trigger function ──────────────────────────────────────────
    op.execute("""
        CREATE OR REPLACE FUNCTION iplist.set_update_date()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW."updateDate" = NOW();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # ── iplists ───────────────────────────────────────────────────────────────
    op.create_table(
        "iplists",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("flagBlacklist", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("lastSync", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fetchFrequencyHours", sa.Integer(), nullable=False, server_default="0"),
        schema="iplist",
    )
    op.create_index("ix_iplists_flagInactive", "iplists", ["flagInactive"], schema="iplist")
    op.execute("""
        CREATE TRIGGER trg_iplists_update_date
        BEFORE UPDATE ON iplist.iplists
        FOR EACH ROW EXECUTE FUNCTION iplist.set_update_date();
    """)

    # ── ipAddresses ───────────────────────────────────────────────────────────
    op.create_table(
        "ipAddresses",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("ipAddress", sa.Text(), nullable=False),
        sa.Column("iplistsId", sa.BigInteger(), sa.ForeignKey("iplist.iplists.id", ondelete="CASCADE"), nullable=False),
        schema="iplist",
    )
    op.create_index("ix_ipAddresses_flagInactive", "ipAddresses", ["flagInactive"], schema="iplist")
    op.create_index("ix_ipAddresses_iplistsId_flagInactive", "ipAddresses", ["iplistsId", "flagInactive"], schema="iplist")
    op.execute("""
        CREATE TRIGGER trg_ipAddresses_update_date
        BEFORE UPDATE ON iplist."ipAddresses"
        FOR EACH ROW EXECUTE FUNCTION iplist.set_update_date();
    """)

    # ── firewallTypes ─────────────────────────────────────────────────────────
    op.create_table(
        "firewallTypes",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("firewallTypeDescription", sa.Text(), nullable=False),
        schema="iplist",
    )
    op.create_index("ix_firewallTypes_flagInactive", "firewallTypes", ["flagInactive"], schema="iplist")
    op.execute("""
        CREATE TRIGGER trg_firewallTypes_update_date
        BEFORE UPDATE ON iplist."firewallTypes"
        FOR EACH ROW EXECUTE FUNCTION iplist.set_update_date();
    """)

    # ── firewalls ─────────────────────────────────────────────────────────────
    op.create_table(
        "firewalls",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("firewallAddress", sa.Text(), nullable=False),
        sa.Column("firewallPort", sa.Integer(), nullable=False),
        sa.Column("firewallUser", sa.Text(), nullable=False),
        sa.Column("firewallSecret", sa.Text(), nullable=False),
        sa.Column("firewallTypeId", sa.BigInteger(), sa.ForeignKey("iplist.firewallTypes.id"), nullable=False),
        sa.Column("applyFrequencyHours", sa.Integer(), nullable=False, server_default="0"),
        schema="iplist",
    )
    op.create_index("ix_firewalls_flagInactive", "firewalls", ["flagInactive"], schema="iplist")
    op.execute("""
        CREATE TRIGGER trg_firewalls_update_date
        BEFORE UPDATE ON iplist.firewalls
        FOR EACH ROW EXECUTE FUNCTION iplist.set_update_date();
    """)

    # ── configuration ─────────────────────────────────────────────────────────
    op.create_table(
        "configuration",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("configurationItem", sa.Text(), nullable=False),
        sa.Column("configurationHelp", sa.Text(), nullable=True),
        sa.Column("configurationItemValue", sa.Text(), nullable=True),
        schema="iplist",
    )
    op.create_index("ix_configuration_flagInactive", "configuration", ["flagInactive"], schema="iplist")
    op.execute("""
        CREATE TRIGGER trg_configuration_update_date
        BEFORE UPDATE ON iplist.configuration
        FOR EACH ROW EXECUTE FUNCTION iplist.set_update_date();
    """)

    # ── fetchJobs ─────────────────────────────────────────────────────────────
    op.create_table(
        "fetchJobs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("iplistsId", sa.BigInteger(), sa.ForeignKey("iplist.iplists.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("startedAt", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completedAt", sa.DateTime(timezone=True), nullable=True),
        sa.Column("errorMessage", sa.Text(), nullable=True),
        sa.Column("entriesParsed", sa.Integer(), nullable=True),
        sa.Column("entriesLoaded", sa.Integer(), nullable=True),
        schema="iplist",
    )
    op.create_index("ix_fetchJobs_flagInactive", "fetchJobs", ["flagInactive"], schema="iplist")
    op.create_index("ix_fetchJobs_iplistsId_status", "fetchJobs", ["iplistsId", "status"], schema="iplist")
    op.execute("""
        CREATE TRIGGER trg_fetchJobs_update_date
        BEFORE UPDATE ON iplist."fetchJobs"
        FOR EACH ROW EXECUTE FUNCTION iplist.set_update_date();
    """)

    # ── fetchErrors ───────────────────────────────────────────────────────────
    op.create_table(
        "fetchErrors",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("iplistsId", sa.BigInteger(), sa.ForeignKey("iplist.iplists.id", ondelete="CASCADE"), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("errorMessage", sa.Text(), nullable=False),
        sa.Column("occurredAt", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        schema="iplist",
    )
    op.create_index("ix_fetchErrors_flagInactive", "fetchErrors", ["flagInactive"], schema="iplist")
    op.create_index("ix_fetchErrors_iplistsId_occurredAt", "fetchErrors", ["iplistsId", "occurredAt"], schema="iplist")
    op.execute("""
        CREATE TRIGGER trg_fetchErrors_update_date
        BEFORE UPDATE ON iplist."fetchErrors"
        FOR EACH ROW EXECUTE FUNCTION iplist.set_update_date();
    """)

    # ── applyHistory ──────────────────────────────────────────────────────────
    op.create_table(
        "applyHistory",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("createDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updateDate", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("flagInactive", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("firewallsId", sa.BigInteger(), sa.ForeignKey("iplist.firewalls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("startedAt", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completedAt", sa.DateTime(timezone=True), nullable=True),
        sa.Column("whitelistHash", sa.Text(), nullable=True),
        sa.Column("blacklistHash", sa.Text(), nullable=True),
        sa.Column("whitelistCount", sa.Integer(), nullable=True),
        sa.Column("blacklistCount", sa.Integer(), nullable=True),
        sa.Column("errorMessage", sa.Text(), nullable=True),
        schema="iplist",
    )
    op.create_index("ix_applyHistory_flagInactive", "applyHistory", ["flagInactive"], schema="iplist")
    op.create_index("ix_applyHistory_firewallsId_startedAt", "applyHistory", ["firewallsId", "startedAt"], schema="iplist")
    op.execute("""
        CREATE TRIGGER trg_applyHistory_update_date
        BEFORE UPDATE ON iplist."applyHistory"
        FOR EACH ROW EXECUTE FUNCTION iplist.set_update_date();
    """)

    # ── Seed: configuration ───────────────────────────────────────────────────
    op.execute("""
        INSERT INTO iplist.configuration ("configurationItem", "configurationHelp", "configurationItemValue")
        VALUES
            ('fetcherEnabled',    'Whether the scheduled fetcher is running (0=off, 1=on)', '0'),
            ('applicatorEnabled', 'Whether the scheduled applicator is running (0=off, 1=on)', '0'),
            ('applicatorTTLDays', 'Days MikroTik dynamic address-list entries stay active', '7');
    """)

    # ── Seed: firewallTypes ───────────────────────────────────────────────────
    op.execute("""
        INSERT INTO iplist."firewallTypes" ("firewallTypeDescription")
        VALUES ('MikroTik RouterOS 7');
    """)


def downgrade() -> None:
    op.execute('DROP TABLE IF EXISTS iplist."applyHistory" CASCADE')
    op.execute('DROP TABLE IF EXISTS iplist."fetchErrors" CASCADE')
    op.execute('DROP TABLE IF EXISTS iplist."fetchJobs" CASCADE')
    op.execute('DROP TABLE IF EXISTS iplist.configuration CASCADE')
    op.execute('DROP TABLE IF EXISTS iplist.firewalls CASCADE')
    op.execute('DROP TABLE IF EXISTS iplist."firewallTypes" CASCADE')
    op.execute('DROP TABLE IF EXISTS iplist."ipAddresses" CASCADE')
    op.execute('DROP TABLE IF EXISTS iplist.iplists CASCADE')
    op.execute("DROP FUNCTION IF EXISTS iplist.set_update_date() CASCADE")
    op.execute("DROP SCHEMA IF EXISTS iplist CASCADE")
