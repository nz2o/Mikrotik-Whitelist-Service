"""Add performance indexes for common query patterns

Revision ID: 0006_add_performance_indexes
Revises: 0005_domain_lists
Create Date: 2026-04-12 00:00:00

## Analysis
Execution plan analysis identified these slow query patterns:
1. page_iplists N+1: SELECT FetchJob WHERE iplistsId=X ORDER BY startedAt DESC -> SORT overhead
2. page_status filtering: SELECT ApplyHistory WHERE firewallsId=X AND status=Y ORDER BY startedAt DESC -> filter applied after index scan
3. Bulk dataset generation: SELECT ipAddresses WHERE flagInactive=0 AND iplistsId IN (...) -> seq scan due to low selectivity of first column
4. Domain bulk fetch: SELECT domains WHERE flagInactive=0 AND domainListsId IN (...) -> seq scan

## Recommendations
- fetchJobs: Add (iplistsId, startedAt DESC) to avoid SORT in N+1 query
- applyHistory: Add (firewallsId, status, startedAt DESC) for status page filtering with descending sort
- ipAddresses: Add (flagInactive, iplistsId) to prioritize high-selectivity column first
- domains: Add (flagInactive, domainListsId) to prioritize high-selectivity column first
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_add_performance_indexes"
down_revision = "0005_domain_lists"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Index for fetchJobs: avoid SORT in "last fetch job per iplist" N+1 query
    op.create_index(
        "ix_fetchJobs_iplistsId_startedAt",
        "fetchJobs",
        ["iplistsId", "startedAt"],
        schema="iplist"
    )

    # Index for applyHistory: support status filtering on status page without SORT
    # Note: Using raw SQL for descending index to work around column quoting issues
    op.execute(
        """
        CREATE INDEX "ix_applyHistory_firewallsId_status_startedAt" 
        ON iplist."applyHistory" ("firewallsId", status, "startedAt" DESC)
        """
    )

    # Index for ipAddresses: improve bulk dataset fetch selectivity by column order
    # (prioritize high-selectivity flagInactive=0 to reduce rows scanned)
    op.create_index(
        "ix_ipAddresses_flagInactive_iplistsId",
        "ipAddresses",
        ["flagInactive", "iplistsId"],
        schema="iplist"
    )

    # Index for domains: improve bulk domain fetch selectivity by column order
    op.create_index(
        "ix_domains_flagInactive_domainListsId",
        "domains",
        ["flagInactive", "domainListsId"],
        schema="iplist"
    )


def downgrade() -> None:
    op.drop_index("ix_domains_flagInactive_domainListsId", schema="iplist")
    op.drop_index("ix_ipAddresses_flagInactive_iplistsId", schema="iplist")
    op.drop_index("ix_applyHistory_firewallsId_status_startedAt", schema="iplist")
    op.drop_index("ix_fetchJobs_iplistsId_startedAt", schema="iplist")
