"""Firewall Policy Applicator Service.

Responsibilities:
- Schedule a push per active firewall based on applyFrequencyHours.
- Consolidate whitelist and blacklist CIDRs from ipAddresses.
- Generate split RouterOS address-list scripts.
- Push via SSH (paramiko); atomic list replacement.
- Log progress to applyHistory.
- Expose apply_firewall(id) and apply_all() for API triggers.
"""

import hashlib
import ipaddress
import logging
import socket
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import paramiko
from apscheduler.schedulers.background import BackgroundScheduler

from app.config import APPLY_TIMEOUT_SECONDS, FETCH_RETRIES, configure_logging
from app.crypto import decrypt_secret
from app.database import SessionLocal
from app.models import (
    ApplyHistory,
    Configuration,
    Domain,
    DomainList,
    Firewall,
    FirewallAddressState,
    FirewallListState,
    IpAddress,
    IpList,
)

log = logging.getLogger(__name__)


class _SshAuthError(Exception):
    """SSH authentication failure — retrying will not help."""


CHUNK_SIZE = 30  # reduced for faster RouterOS execution; prioritize latency over throughput
MAX_CHUNK_BYTES = 2000  # keep chunks small for better RouterOS responsiveness
TTL_REFRESH_THRESHOLD_DAYS = 4
MAX_DELETE_OPS_PER_APPLY = 300
CHUNK_WARN_THRESHOLD_SECONDS = 30  # log warning if chunk execution exceeds this
_APPLY_STATUS_LOCK = threading.Lock()
_APPLY_STATUS: dict[int, dict[str, object]] = {}
IN_PROGRESS_APPLY_STATUSES = {
    "starting",
    "connecting",
    "generating",
    "collapsing",
    "pushing",
}


# ---------------------------------------------------------------------------
# CIDR consolidation
# ---------------------------------------------------------------------------


DEFAULT_TTL_DAYS = 7
TYPE_TO_KIND = {
    IpList.TYPE_ALLOW: "allow",
    IpList.TYPE_DENY: "deny",
    IpList.TYPE_LOG: "log",
    IpList.TYPE_OUTBOUND_DENY: "outbound-deny",
    IpList.TYPE_ALL_DENY: "all-deny",
}
KIND_TO_TYPE = {v: k for k, v in TYPE_TO_KIND.items()}
KIND_TO_TYPE.update({"whitelist": IpList.TYPE_ALLOW, "blacklist": IpList.TYPE_DENY})
TYPE_TO_LIST_NAME = {
    IpList.TYPE_ALLOW: "ip-whitelist-dynamic",
    IpList.TYPE_DENY: "ip-blacklist-dynamic",
    IpList.TYPE_LOG: "ip-log-dynamic",
    IpList.TYPE_OUTBOUND_DENY: "ip-outbound-deny-dynamic",
    IpList.TYPE_ALL_DENY: "ip-all-deny-dynamic",
}
IGNORED_HOST_ADDRESSES = {
    ipaddress.IPv4Address("0.0.0.0"),
    ipaddress.IPv4Address("255.255.255.255"),
}


def _should_ignore_network(net: ipaddress.IPv4Network) -> bool:
    return net.prefixlen == 32 and net.network_address in IGNORED_HOST_ADDRESSES


def _consolidate(cidrs: list[str]) -> list[str]:
    """Deduplicate and supernet-collapse a list of IPv4 CIDR strings."""
    nets = []
    for c in cidrs:
        try:
            net = ipaddress.IPv4Network(c, strict=False)
            if _should_ignore_network(net):
                log.info("Ignoring special host address during consolidation", extra={"cidr": c})
                continue
            nets.append(net)
        except ValueError:
            log.warning("Skipping invalid CIDR during consolidation", extra={"cidr": c})
    collapsed = list(ipaddress.collapse_addresses(nets))
    return [str(n) for n in collapsed]


def _collapse_entries(entries: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """Collapse entries quickly while preserving per-TTL behavior.

    Strategy:
    - Group by effective TTL and collapse each bucket independently.
    - Merge exact duplicate networks across buckets using max TTL.

    This avoids expensive cross-product subnet checks that can stall large exports
    while still honoring list TTL defaults.
    """
    if not entries:
        return []

    ttl_groups: dict[int, list[ipaddress.IPv4Network]] = defaultdict(list)
    for cidr, ttl in entries:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            if _should_ignore_network(net):
                log.info("Ignoring special host address during collapse", extra={"cidr": cidr})
                continue
            ttl_groups[_normalize_ttl(ttl)].append(net)
        except ValueError:
            log.warning("Skipping invalid CIDR during collapse", extra={"cidr": cidr})

    if not ttl_groups:
        return []

    # Collapse within each TTL bucket, then dedupe exact-network collisions.
    by_network: dict[str, int] = {}
    for effective_ttl, nets in ttl_groups.items():
        for collapsed_net in ipaddress.collapse_addresses(nets):
            key = str(collapsed_net)
            by_network[key] = max(by_network.get(key, 0), effective_ttl)

    return [(cidr, ttl) for cidr, ttl in by_network.items()]


def _update_apply_status(firewall_id: int, **updates) -> None:
    with _APPLY_STATUS_LOCK:
        current = dict(_APPLY_STATUS.get(firewall_id, {}))
        current.update(updates)
        _APPLY_STATUS[firewall_id] = current


def get_apply_status(firewall_id: int) -> dict[str, object]:
    with _APPLY_STATUS_LOCK:
        return dict(_APPLY_STATUS.get(firewall_id, {}))


def trigger_apply_async(
    firewall_id: int,
    force: bool = False,
    override_in_progress: bool = False,
) -> bool:
    with _APPLY_STATUS_LOCK:
        current = _APPLY_STATUS.get(firewall_id, {})
        if current.get("active"):
            return False
    threading.Thread(
        target=apply_firewall,
        args=(firewall_id, force, override_in_progress),
        daemon=True,
    ).start()
    return True


def _build_datasets(on_list_done=None) -> dict[int, list[tuple[str, int]]]:
    """Return map of list_type -> [(cidr, ttl_days), ...].

    CIDRs are consolidated within each IP list separately so that per-list TTL
    values are preserved. Entries from different lists are NOT merged together.

    on_list_done: optional callable(done: int, total: int) called after each list is processed.
    """
    t0 = time.perf_counter()
    db = SessionLocal()
    try:
        active_lists = [
            (row.id, row.ttlDays, row.flagBlacklist)
            for row in db.query(IpList.id, IpList.ttlDays, IpList.flagBlacklist)
            .filter(IpList.flagInactive == 0)
            .all()
        ]
        active_domain_lists = [
            (row.id, row.ttlDays, row.listType)
            for row in db.query(DomainList.id, DomainList.ttlDays, DomainList.listType)
            .filter(DomainList.flagInactive == 0)
            .all()
        ]

        # Bulk-load all active row data once, then group in-memory to avoid
        # N+1 query overhead when many lists are configured.
        ip_rows_by_list: dict[int, list[str]] = defaultdict(list)
        if active_lists:
            active_ip_list_ids = [list_id for list_id, _ttl, _list_type in active_lists]
            ip_rows = (
                db.query(IpAddress.iplistsId, IpAddress.ipAddress)
                .filter(
                    IpAddress.flagInactive == 0,
                    IpAddress.iplistsId.in_(active_ip_list_ids),
                )
                .all()
            )
            for row in ip_rows:
                ip_rows_by_list[row.iplistsId].append(row.ipAddress)

        domain_rows_by_list: dict[int, list[str]] = defaultdict(list)
        if active_domain_lists:
            active_domain_list_ids = [list_id for list_id, _ttl, _list_type in active_domain_lists]
            domain_rows = (
                db.query(Domain.domainListsId, Domain.ipAddress)
                .filter(
                    Domain.flagInactive == 0,
                    Domain.domainListsId.in_(active_domain_list_ids),
                )
                .all()
            )
            for row in domain_rows:
                domain_rows_by_list[row.domainListsId].append(row.ipAddress)
    finally:
        db.close()

    t_fetch = time.perf_counter()
    total = len(active_lists) + len(active_domain_lists)
    done = 0
    datasets: dict[int, list[tuple[str, int]]] = {
        code: [] for code, _label in IpList.TYPE_OPTIONS
    }
    for list_id, ttl_days, list_flag in active_lists:
        ttl = ttl_days if ttl_days is not None else DEFAULT_TTL_DAYS
        list_type = list_flag if list_flag in datasets else IpList.TYPE_ALLOW
        raw = ip_rows_by_list.get(list_id, [])
        consolidated = _consolidate(raw)
        entries = [(cidr, ttl) for cidr in consolidated]
        datasets[list_type].extend(entries)
        done += 1
        if on_list_done:
            on_list_done(done, total)

    for list_id, ttl_days, list_kind in active_domain_lists:
        ttl = ttl_days if ttl_days is not None else DEFAULT_TTL_DAYS
        list_type = list_kind if list_kind in datasets else IpList.TYPE_ALLOW
        raw = domain_rows_by_list.get(list_id, [])
        consolidated = _consolidate(raw)
        entries = [(cidr, ttl) for cidr in consolidated]
        datasets[list_type].extend(entries)
        done += 1
        if on_list_done:
            on_list_done(done, total)
    t_done = time.perf_counter()
    log.info(
        "Dataset build timings",
        extra={
            "ipLists": len(active_lists),
            "domainLists": len(active_domain_lists),
            "ipRows": sum(len(v) for v in ip_rows_by_list.values()),
            "domainRows": sum(len(v) for v in domain_rows_by_list.values()),
            "fetchSeconds": round(t_fetch - t0, 3),
            "consolidateSeconds": round(t_done - t_fetch, 3),
            "totalSeconds": round(t_done - t0, 3),
        },
    )

    return datasets


def _sha256_of(entries: list[tuple[str, int]]) -> str:
    joined = "\n".join(sorted(f"{cidr}:{ttl}" for cidr, ttl in entries))
    return hashlib.sha256(joined.encode()).hexdigest()


def _routeros_address_literal(cidr: str) -> str:
    """Return RouterOS-friendly canonical address literal."""
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        if net.prefixlen == 32:
            return str(net.network_address)
        return str(net)
    except ValueError:
        return cidr


def _pack_script_units(units: list[list[str]]) -> list[str]:
    """Pack multi-line units without splitting a unit across chunks."""
    packed: list[str] = []
    current_units: list[list[str]] = []
    current_bytes = 0
    for unit in units:
        unit_text = "\n".join(unit) + "\n"
        unit_bytes = len(unit_text.encode("utf-8"))
        if current_units and current_bytes + unit_bytes > MAX_CHUNK_BYTES:
            chunk_lines: list[str] = []
            for u in current_units:
                chunk_lines.extend(u)
            packed.append("\n".join(chunk_lines) + "\n")
            current_units = []
            current_bytes = 0
        current_units.append(unit)
        current_bytes += unit_bytes
    if current_units:
        chunk_lines = []
        for u in current_units:
            chunk_lines.extend(u)
        packed.append("\n".join(chunk_lines) + "\n")
    return packed


# ---------------------------------------------------------------------------
# RouterOS script generation
# ---------------------------------------------------------------------------


def _make_rsc_chunks(
    list_name: str,
    entries: list[tuple[str, int]],
    generation_tag: str | None = None,
    safe_update: bool = False,
) -> list[str]:
    """
    Return a list of RouterOS script strings.

    safe_update=False (default):
    - Fast export mode: remove then add entries in chunks.

    safe_update=True:
    - No-gap apply mode: upsert/tag desired entries, then prune stale entries.

    No-gap mode keeps old entries in place until the new set is fully present.

    Each entry is a (cidr, ttl_days) tuple so different IP lists can carry
    different TTL values within the same RouterOS address list.
    Split into CHUNK_SIZE batches to avoid SSH/execution timeouts.
    """
    chunks: list[str] = []

    if not safe_update:
        all_lines: list[str] = []
        for batch_index, start in enumerate(range(0, len(entries), CHUNK_SIZE)):
            batch = entries[start : start + CHUNK_SIZE]
            lines: list[str] = []
            if batch_index == 0:
                lines.append(f'/ip firewall address-list remove [find list="{list_name}"]')
            for cidr, ttl in batch:
                effective_ttl = _normalize_ttl(ttl)
                ros_addr = _routeros_address_literal(cidr)
                lines.append(
                    f'/ip firewall address-list add list="{list_name}" '
                    f'address={ros_addr} timeout={effective_ttl}d'
                )
            all_lines.extend(lines)

        if not entries:
            chunks = [f'/ip firewall address-list remove [find list="{list_name}"]\n']
            return chunks
        return _pack_script_units([[line] for line in all_lines])

    if generation_tag is None:
        generation_tag = f"mws-{int(time.time())}"

    units: list[list[str]] = []
    for batch_index, start in enumerate(range(0, len(entries), CHUNK_SIZE)):
        _ = batch_index
        batch = entries[start : start + CHUNK_SIZE]
        for cidr, ttl in batch:
            effective_ttl = _normalize_ttl(ttl)
            ros_addr = _routeros_address_literal(cidr)
            units.append(
                [
                    f':do {{ /ip firewall address-list add list="{list_name}" '
                    f'address={ros_addr} timeout={effective_ttl}d comment="{generation_tag}" }} '
                    f'on-error={{ '
                    f'/ip firewall address-list remove [find where list="{list_name}" and address={ros_addr}]; '
                    f'/ip firewall address-list add list="{list_name}" address={ros_addr} timeout={effective_ttl}d comment="{generation_tag}" '
                    f'}}',
                ]
            )

    # Final prune pass removes stale entries only after all desired entries are present.
    if entries:
        units.append(
            [
                f':foreach i in=[/ip firewall address-list find list="{list_name}"] do={{ '
                f':local c [/ip firewall address-list get $i comment]; '
                f':if ((([:pick $c 0 4] = "mws:") and ($c != "{generation_tag}"))) do={{ /ip firewall address-list remove $i }} '
                f'}}'
            ]
        )

    # Edge case: if desired entries are empty, clear list.
    if not entries:
        chunks = [f'/ip firewall address-list remove [find list="{list_name}"]\n']
        return chunks
    return _pack_script_units(units)


def _kind_to_list_name(kind: str) -> str:
    if kind not in KIND_TO_TYPE:
        raise ValueError("unsupported kind")
    return TYPE_TO_LIST_NAME[KIND_TO_TYPE[kind]]


def _normalize_ttl(ttl_days: Optional[int]) -> int:
    if ttl_days is None:
        return DEFAULT_TTL_DAYS
    if ttl_days < 1:
        return DEFAULT_TTL_DAYS
    return ttl_days


def _remaining_ttl_days(ttl_days: int, last_pushed_at: datetime, now: datetime) -> float:
    elapsed_seconds = (now - last_pushed_at).total_seconds()
    return ttl_days - (elapsed_seconds / 86400.0)


def _build_desired_entries_by_list(
    datasets: dict[int, list[tuple[str, int]]]
) -> dict[str, dict[str, int]]:
    desired_by_list: dict[str, dict[str, int]] = {}
    for code, _label in IpList.TYPE_OPTIONS:
        list_name = TYPE_TO_LIST_NAME[code]
        by_addr: dict[str, int] = {}
        for cidr, ttl in datasets.get(code, []):
            addr = _routeros_address_literal(cidr)
            eff_ttl = _normalize_ttl(ttl)
            by_addr[addr] = max(by_addr.get(addr, 0), eff_ttl)
        desired_by_list[list_name] = by_addr
    return desired_by_list


def _compute_list_hash(addresses: dict[str, int]) -> str:
    """Compute SHA256 hash of sorted address list for change detection."""
    sorted_addrs = sorted(addresses.keys())
    content = "\n".join(sorted_addrs)
    return hashlib.sha256(content.encode()).hexdigest()


def _get_changed_lists(
    db,
    firewall_id: int,
    desired_by_list: dict[str, dict[str, int]],
) -> set[str]:
    """Identify which lists have changed (hash mismatch) since last push.
    
    Returns: set of list names that need to be re-pushed.
    """
    existing_rows = (
        db.query(FirewallListState)
        .filter(FirewallListState.firewallsId == firewall_id)
        .all()
    )
    existing_hashes = {r.listName: r.contentHash for r in existing_rows}

    changed = set()
    for list_name, addresses in desired_by_list.items():
        desired_hash = _compute_list_hash(addresses)
        if existing_hashes.get(list_name) != desired_hash:
            changed.add(list_name)

    return changed


def _plan_delta_units(
    existing_rows: list[FirewallAddressState],
    desired_by_list: dict[str, dict[str, int]],
    generation_tag: str,
    now: datetime,
) -> tuple[list[list[str]], dict[tuple[str, str], tuple[int, int | None]], set[int], int]:
    """Plan incremental RouterOS operations and DB state changes.

    Returns:
    - script units to send
    - upsert map key=(list_name, addr) -> (ttl_days, existing_row_id_or_none)
    - row IDs to delete from state
    """
    existing_by_key = {(r.listName, r.ipAddress): r for r in existing_rows}
    desired_keys = {
        (list_name, addr)
        for list_name, by_addr in desired_by_list.items()
        for addr in by_addr.keys()
    }

    add_or_refresh_units: list[list[str]] = []
    delete_units: list[list[str]] = []
    upserts: dict[tuple[str, str], tuple[int, int | None]] = {}
    delete_candidates: list[tuple[tuple[str, str], int]] = []

    # Identify entries no longer desired; removals are throttled per apply.
    for key, row in existing_by_key.items():
        if key not in desired_keys:
            delete_candidates.append((key, row.id))

    # Add or refresh entries that are new/changed/near expiry.
    for list_name, by_addr in desired_by_list.items():
        for addr, ttl_days in by_addr.items():
            key = (list_name, addr)
            row = existing_by_key.get(key)
            needs_refresh = False
            if row is None:
                needs_refresh = True
            else:
                if row.ttlDays != ttl_days:
                    needs_refresh = True
                elif not row.generationTag or not row.generationTag.startswith("mws:"):
                    needs_refresh = True
                elif row.lastPushedAt is None:
                    needs_refresh = True
                else:
                    remaining = _remaining_ttl_days(row.ttlDays, row.lastPushedAt, now)
                    if remaining < TTL_REFRESH_THRESHOLD_DAYS:
                        needs_refresh = True

            if needs_refresh:
                if row is None:
                    # New key: keep the command cheap; ignore duplicate races safely.
                    add_or_refresh_units.append(
                        [
                            f':do {{ /ip firewall address-list add list="{list_name}" '
                            f'address={addr} timeout={ttl_days}d comment="{generation_tag}" }} on-error={{}}'
                        ]
                    )
                else:
                    # Existing key needs refresh/repair: remove and re-add deterministically.
                    add_or_refresh_units.append(
                        [
                            f':do {{ /ip firewall address-list add list="{list_name}" '
                            f'address={addr} timeout={ttl_days}d comment="{generation_tag}" }} '
                            f'on-error={{ '
                            f'/ip firewall address-list remove [find where list="{list_name}" and address={addr}]; '
                            f'/ip firewall address-list add list="{list_name}" address={addr} timeout={ttl_days}d comment="{generation_tag}" '
                            f'}}'
                        ]
                    )
                upserts[key] = (ttl_days, row.id if row else None)

    delete_ids: set[int] = set()
    for key, row_id in delete_candidates[:MAX_DELETE_OPS_PER_APPLY]:
        list_name, addr = key
        delete_units.append(
            [
                f':do {{ /ip firewall address-list remove [find where list="{list_name}" and address={addr}] }} on-error={{}}'
            ]
        )
        delete_ids.add(row_id)

    deferred_delete_count = max(0, len(delete_candidates) - len(delete_ids))
    units = add_or_refresh_units + delete_units
    return units, upserts, delete_ids, deferred_delete_count


def _apply_delta_state(
    db,
    firewall_id: int,
    upserts: dict[tuple[str, str], tuple[int, int | None]],
    delete_ids: set[int],
    generation_tag: str,
    now: datetime,
) -> None:
    if delete_ids:
        db.query(FirewallAddressState).filter(FirewallAddressState.id.in_(list(delete_ids))).delete(
            synchronize_session=False
        )

    for (list_name, addr), (ttl_days, row_id) in upserts.items():
        if row_id is None:
            db.add(
                FirewallAddressState(
                    firewallsId=firewall_id,
                    listName=list_name,
                    ipAddress=addr,
                    ttlDays=ttl_days,
                    generationTag=generation_tag,
                    lastPushedAt=now,
                    flagInactive=0,
                )
            )
        else:
            db.query(FirewallAddressState).filter(FirewallAddressState.id == row_id).update(
                {
                    "ttlDays": ttl_days,
                    "generationTag": generation_tag,
                    "lastPushedAt": now,
                    "flagInactive": 0,
                }
            )

    db.commit()


def _update_list_state_hashes(
    db,
    firewall_id: int,
    desired_by_list: dict[str, dict[str, int]],
    now: datetime,
) -> None:
    """Update FirewallListState hashes after a successful push."""
    for list_name, addresses in desired_by_list.items():
        content_hash = _compute_list_hash(addresses)
        entry_count = len(addresses)
        
        existing = (
            db.query(FirewallListState)
            .filter(
                FirewallListState.firewallsId == firewall_id,
                FirewallListState.listName == list_name,
            )
            .first()
        )
        
        if existing:
            db.query(FirewallListState).filter(
                FirewallListState.firewallsId == firewall_id,
                FirewallListState.listName == list_name,
            ).update(
                {
                    "contentHash": content_hash,
                    "entryCount": entry_count,
                    "lastPushedAt": now,
                    "flagInactive": 0,
                }
            )
        else:
            db.add(
                FirewallListState(
                    firewallsId=firewall_id,
                    listName=list_name,
                    contentHash=content_hash,
                    entryCount=entry_count,
                    lastPushedAt=now,
                    flagInactive=0,
                )
            )
    db.commit()


def get_combined_entries(
    on_list_done=None,
    on_collapse_started=None,
    on_collapse_done=None,
) -> dict[int, list[tuple[str, int]]]:
    """Public helper for export and apply consumers."""
    t0 = time.perf_counter()
    datasets = _build_datasets(on_list_done=on_list_done)
    t_built = time.perf_counter()
    collapsed: dict[int, list[tuple[str, int]]] = {}
    total_buckets = len(datasets)
    if on_collapse_started:
        on_collapse_started(total_buckets)
    for idx, (list_type, entries) in enumerate(datasets.items(), start=1):
        collapsed[list_type] = _collapse_entries(entries)
        if on_collapse_done:
            on_collapse_done(idx, total_buckets)
    t_done = time.perf_counter()
    log.info(
        "Global collapse timings",
        extra={
            "bucketCount": total_buckets,
            "buildSeconds": round(t_built - t0, 3),
            "collapseSeconds": round(t_done - t_built, 3),
            "totalSeconds": round(t_done - t0, 3),
        },
    )
    return collapsed


def get_all_active_applies() -> list[dict]:
    """Return status dicts for all currently running applies."""
    with _APPLY_STATUS_LOCK:
        return [dict(v) for v in _APPLY_STATUS.values() if v.get("active")]


def build_combined_rsc(kind: str) -> str:
    """Build full RouterOS script for a combined list type."""
    datasets = get_combined_entries()
    if kind not in KIND_TO_TYPE:
        raise ValueError("unsupported kind")
    entries = datasets[KIND_TO_TYPE[kind]]
    list_name = _kind_to_list_name(kind)
    return "".join(_make_rsc_chunks(list_name, entries, safe_update=False))


def build_combined_plain(kind: str) -> str:
    """Build globally collapsed/de-duplicated CIDR list for a combined type."""
    datasets = get_combined_entries()
    if kind not in KIND_TO_TYPE:
        raise ValueError("unsupported kind")
    entries = datasets[KIND_TO_TYPE[kind]]
    collapsed = _consolidate([cidr for cidr, _ttl in entries])
    if not collapsed:
        return ""
    return "\n".join(collapsed) + "\n"


def _get_iplist_for_export(iplist_id: int) -> Optional[IpList]:
    db = SessionLocal()
    try:
        return db.query(IpList).filter(IpList.id == iplist_id).first()
    finally:
        db.close()


def _get_iplist_entries(iplist_id: int) -> list[tuple[str, int]]:
    db = SessionLocal()
    try:
        iplist = db.query(IpList).filter(IpList.id == iplist_id).first()
        if not iplist:
            return []
        ttl = _normalize_ttl(iplist.ttlDays)
        raw = [
            r.ipAddress
            for r in db.query(IpAddress.ipAddress)
            .filter(
                IpAddress.iplistsId == iplist_id,
                IpAddress.flagInactive == 0,
            )
            .all()
        ]
        return [(cidr, ttl) for cidr in _consolidate(raw)]
    finally:
        db.close()


def build_iplist_rsc(iplist_id: int) -> str:
    """Build RouterOS script for one IP list using that list's TTL value."""
    iplist = _get_iplist_for_export(iplist_id)
    if not iplist:
        raise ValueError("iplist not found")
    list_type = iplist.flagBlacklist if iplist.flagBlacklist in TYPE_TO_LIST_NAME else IpList.TYPE_ALLOW
    list_name = TYPE_TO_LIST_NAME[list_type]
    entries = _get_iplist_entries(iplist_id)
    return "".join(_make_rsc_chunks(list_name, entries, safe_update=False))


def build_iplist_plain(iplist_id: int) -> str:
    """Build collapsed/de-duplicated CIDR list for a single IP list."""
    iplist = _get_iplist_for_export(iplist_id)
    if not iplist:
        raise ValueError("iplist not found")
    entries = _get_iplist_entries(iplist_id)
    collapsed = _consolidate([cidr for cidr, _ttl in entries])
    if not collapsed:
        return ""
    return "\n".join(collapsed) + "\n"


# ---------------------------------------------------------------------------
# SSH push
# ---------------------------------------------------------------------------


def _probe_ssh_port(fw: "Firewall", timeout: float) -> tuple[str | None, str | None]:
    """TCP-connect to the firewall's SSH port.

    Returns (source_ip, error_message).  source_ip is the local address the
    OS chose for the connection (i.e. what the router sees as the origin).
    error_message is None on success.
    """
    try:
        with socket.create_connection(
            (fw.firewallAddress, fw.firewallPort), timeout=timeout
        ) as sock:
            source_ip = sock.getsockname()[0]
        return source_ip, None
    except OSError as exc:
        return None, str(exc)


def _push_chunks(fw: "Firewall", chunks: list[str], on_chunk_done=None) -> None:
    """Connect to firewall via SSH and execute all script chunks."""
    plaintext_secret = decrypt_secret(fw.firewallSecret)
    # APPLY_TIMEOUT_SECONDS can be tuned low for connect/auth behavior, but
    # RouterOS chunk execution may legitimately take longer on large lists.
    chunk_timeout_seconds = max(APPLY_TIMEOUT_SECONDS, 90)  # floor for individual chunk execution
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=fw.firewallAddress,
                port=fw.firewallPort,
                username=fw.firewallUser,
                password=plaintext_secret,
                timeout=APPLY_TIMEOUT_SECONDS,
                auth_timeout=APPLY_TIMEOUT_SECONDS,
                banner_timeout=APPLY_TIMEOUT_SECONDS,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException:
            raise _SshAuthError(
                f"SSH authentication failed for {fw.firewallUser}@"
                f"{fw.firewallAddress}:{fw.firewallPort} — check username/password"
            )
        total_chunks = len(chunks)
        for idx, chunk in enumerate(chunks, start=1):
            chunk_start_time = time.monotonic()
            chunk_lines = [line.strip() for line in chunk.splitlines() if line.strip()]
            chunk_preview = chunk_lines[0] if chunk_lines else ""
            chunk_line_count = len(chunk_lines)
            chunk_byte_size = len(chunk.encode("utf-8"))
            if idx == 1 or idx % 20 == 0:
                log.info(
                    "Pushing chunk",
                    extra={
                        "firewallsId": fw.id,
                        "chunk": idx,
                        "totalChunks": total_chunks,
                        "chunkTimeoutSeconds": chunk_timeout_seconds,
                        "chunkPreview": chunk_preview,
                        "chunkLineCount": chunk_line_count,
                        "chunkBytes": chunk_byte_size,
                    },
                )
            _update_apply_status(
                fw.id,
                currentChunk=idx,
                currentChunkTotal=total_chunks,
                currentChunkPreview=chunk_preview,
                currentChunkText=chunk,
                currentChunkLineCount=chunk_line_count,
                currentChunkBytes=chunk_byte_size,
                routerFeedback="sending chunk",
            )
            stdin, stdout, stderr = client.exec_command(chunk, timeout=chunk_timeout_seconds)
            deadline = time.monotonic() + chunk_timeout_seconds
            channel = stdout.channel
            out_buf: list[str] = []
            err_buf: list[str] = []
            while not stdout.channel.exit_status_ready():
                if channel.recv_ready():
                    data = channel.recv(4096).decode(errors="replace")
                    if data:
                        out_buf.append(data)
                        snippet = data.strip().splitlines()[-1][:220] if data.strip() else ""
                        if snippet:
                            _update_apply_status(
                                fw.id,
                                routerFeedback=f"stdout: {snippet[:500]}",
                            )
                            log.info(
                                "RouterOS stdout",
                                extra={
                                    "firewallsId": fw.id,
                                    "chunk": idx,
                                    "message": snippet,
                                },
                            )
                if channel.recv_stderr_ready():
                    data = channel.recv_stderr(4096).decode(errors="replace")
                    if data:
                        err_buf.append(data)
                        snippet = data.strip().splitlines()[-1][:220] if data.strip() else ""
                        if snippet:
                            _update_apply_status(
                                fw.id,
                                routerFeedback=f"stderr: {snippet[:500]}",
                            )
                            log.warning(
                                "RouterOS stderr",
                                extra={
                                    "firewallsId": fw.id,
                                    "chunk": idx,
                                    "message": snippet,
                                },
                            )
                if time.monotonic() > deadline:
                    raise TimeoutError(
                        f"RouterOS chunk {idx}/{total_chunks} timed out after {chunk_timeout_seconds}s"
                    )
                time.sleep(0.1)
            while channel.recv_ready():
                out_buf.append(channel.recv(4096).decode(errors="replace"))
            while channel.recv_stderr_ready():
                err_buf.append(channel.recv_stderr(4096).decode(errors="replace"))
            exit_code = stdout.channel.recv_exit_status()
            chunk_elapsed = time.monotonic() - chunk_start_time
            err_output = "".join(err_buf).strip() or stderr.read().decode(errors="replace").strip()
            out_output = "".join(out_buf).strip()
            if chunk_elapsed > 30:
                log.warning(
                    "Slow chunk execution",
                    extra={
                        "firewallsId": fw.id,
                        "chunk": idx,
                        "totalChunks": total_chunks,
                        "elapsedSeconds": round(chunk_elapsed, 2),
                        "chunkLineCount": chunk_line_count,
                        "chunkBytes": chunk_byte_size,
                    },
                )
            if exit_code != 0:
                raise RuntimeError(
                    f"RouterOS command failed (exit {exit_code}): {err_output}"
                )
            _update_apply_status(
                fw.id,
                routerFeedback=(out_output or "ok")[:500],
            )
            if on_chunk_done:
                on_chunk_done(idx, total_chunks)
        client.close()
    finally:
        # Ensure the plaintext is not held in memory after this point
        del plaintext_secret


def _get_router_managed_entry_count(fw: "Firewall") -> int | None:
    """Return count of router entries tagged with mws:, or None if probe fails."""
    plaintext_secret = decrypt_secret(fw.firewallSecret)
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=fw.firewallAddress,
                port=fw.firewallPort,
                username=fw.firewallUser,
                password=plaintext_secret,
                timeout=APPLY_TIMEOUT_SECONDS,
                auth_timeout=APPLY_TIMEOUT_SECONDS,
                banner_timeout=APPLY_TIMEOUT_SECONDS,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException:
            raise _SshAuthError(
                f"SSH authentication failed for {fw.firewallUser}@"
                f"{fw.firewallAddress}:{fw.firewallPort} — check username/password"
            )

        cmd = ':put [:len [/ip firewall address-list find where comment~"^mws:"]]'
        _stdin, stdout, stderr = client.exec_command(cmd, timeout=max(APPLY_TIMEOUT_SECONDS, 20))
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            err_output = stderr.read().decode(errors="replace").strip()
            log.warning(
                "Managed entry probe failed",
                extra={"firewallsId": fw.id, "error": err_output},
            )
            return None
        out = stdout.read().decode(errors="replace").strip()
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.isdigit():
                return int(line)
        return None
    finally:
        try:
            client.close()
        except Exception:
            pass
        del plaintext_secret


# ---------------------------------------------------------------------------
# Apply lifecycle
# ---------------------------------------------------------------------------


def apply_firewall(
    firewall_id: int,
    force: bool = False,
    override_in_progress: bool = False,
) -> None:
    """Apply address lists to a single firewall.
    
    Args:
        firewall_id: The firewalls.id to apply to.
        force: If True, skip idempotency hash check (used for manual Apply Now).
    """
    with _APPLY_STATUS_LOCK:
        current = _APPLY_STATUS.get(firewall_id, {})
        if current.get("active"):
            log.info("Apply already running", extra={"firewallsId": firewall_id})
            return
        _APPLY_STATUS[firewall_id] = {
            "firewallsId": firewall_id,
            "active": True,
            "status": "starting",
            "startedAt": datetime.now(timezone.utc).isoformat(),
            "finishedAt": None,
            "whitelistCount": 0,
            "blacklistCount": 0,
            "totalRangeCount": 0,
            "totalIpCount": 0,
            "processedLists": 0,
            "totalLists": 0,
            "processedBuckets": 0,
            "totalBuckets": 0,
            "pushChunksDone": 0,
            "pushChunksTotal": 0,
            "currentChunk": 0,
            "currentChunkTotal": 0,
            "currentChunkPreview": None,
            "currentChunkText": None,
            "currentChunkLineCount": 0,
            "currentChunkBytes": 0,
            "routerFeedback": None,
            "sourceIp": None,
            "lastError": None,
        }

    db = SessionLocal()
    record_id: int | None = None
    try:
        fw = db.query(Firewall).filter(Firewall.id == firewall_id).first()
        if not fw:
            log.error("Firewall not found", extra={"firewallsId": firewall_id})
            _update_apply_status(
                firewall_id,
                active=False,
                status="failed",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                lastError="firewall not found",
            )
            return
        if fw.flagInactive == 1:
            log.info("Skipping inactive firewall", extra={"firewallsId": firewall_id})
            _update_apply_status(
                firewall_id,
                active=False,
                status="skipped",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                lastError="inactive firewall",
            )
            return

        # Cross-process guard: another container (e.g. applicator vs api) may have
        # started an apply for this firewall that the in-memory _APPLY_STATUS does not
        # know about.  Check the DB before creating a new history record.
        existing_in_progress = (
            db.query(ApplyHistory.id)
            .filter(
                ApplyHistory.firewallsId == firewall_id,
                ApplyHistory.status.in_(tuple(IN_PROGRESS_APPLY_STATUSES)),
                ApplyHistory.completedAt.is_(None),
            )
            .first()
        )
        if existing_in_progress is not None:
            if not override_in_progress:
                log.info(
                    "Apply already in progress (cross-process guard)",
                    extra={
                        "firewallsId": firewall_id,
                        "existingRecordId": existing_in_progress.id,
                    },
                )
                _update_apply_status(
                    firewall_id,
                    active=False,
                    status="skipped",
                    finishedAt=datetime.now(timezone.utc).isoformat(),
                    lastError="apply already in progress in another process",
                )
                return

            now = datetime.now(timezone.utc)
            db.query(ApplyHistory).filter(
                ApplyHistory.firewallsId == firewall_id,
                ApplyHistory.status.in_(tuple(IN_PROGRESS_APPLY_STATUSES)),
                ApplyHistory.completedAt.is_(None),
            ).update(
                {
                    ApplyHistory.status: "failed",
                    ApplyHistory.completedAt: now,
                    ApplyHistory.errorMessage: "overridden by manual force apply",
                },
                synchronize_session=False,
            )
            db.commit()
            log.warning(
                "Override in-progress guard and continue apply",
                extra={
                    "firewallsId": firewall_id,
                    "existingRecordId": existing_in_progress.id,
                },
            )

        record = ApplyHistory(
            firewallsId=firewall_id,
            status="connecting",
            startedAt=datetime.now(timezone.utc),
            whitelistHash=None,
            blacklistHash=None,
            whitelistCount=0,
            blacklistCount=0,
            totalRangeCount=0,
            totalIpCount=0,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        record_id = record.id

        _update_apply_status(firewall_id, status="connecting", processedLists=0, totalLists=0)
        source_ip, probe_err = _probe_ssh_port(fw, timeout=min(APPLY_TIMEOUT_SECONDS, 10))
        if probe_err is not None:
            _update_history(
                db,
                record_id,
                status="failed",
                completedAt=datetime.now(timezone.utc),
                errorMessage=f"Unreachable: {probe_err}",
            )
            _update_apply_status(
                firewall_id,
                active=False,
                status="failed",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                lastError=f"Unreachable: {probe_err}",
            )
            log.error(
                "Firewall unreachable",
                extra={"firewallsId": firewall_id, "error": probe_err},
            )
            return

        log.info(
            "Firewall reachable",
            extra={
                "firewallsId": firewall_id,
                "sourceIp": source_ip,
                "target": f"{fw.firewallAddress}:{fw.firewallPort}",
            },
        )

        _update_history(db, record_id, status="generating")
        _update_apply_status(
            firewall_id,
            status="generating",
            sourceIp=source_ip,
            processedLists=0,
            totalLists=0,
            processedBuckets=0,
            totalBuckets=0,
        )
        datasets = get_combined_entries(
            on_list_done=lambda done, total: _update_apply_status(
                firewall_id, processedLists=done, totalLists=total
            ),
            on_collapse_started=lambda total: _update_apply_status(
                firewall_id,
                status="collapsing",
                processedBuckets=0,
                totalBuckets=total,
            ),
            on_collapse_done=lambda done, total: _update_apply_status(
                firewall_id,
                status="collapsing",
                processedBuckets=done,
                totalBuckets=total,
            ),
        )
        allow_entries = datasets.get(IpList.TYPE_ALLOW, [])
        other_entries = []
        for code, _label in IpList.TYPE_OPTIONS:
            if code != IpList.TYPE_ALLOW:
                other_entries.extend(datasets.get(code, []))

        total_range_count = sum(len(bucket_entries) for bucket_entries in datasets.values())
        total_ip_count = 0
        for bucket_entries in datasets.values():
            for cidr, _ttl in bucket_entries:
                total_ip_count += ipaddress.IPv4Network(cidr, strict=False).num_addresses

        wl_hash = _sha256_of(allow_entries)  # includes cidr+ttl in hash
        bl_hash = _sha256_of(other_entries)

        now_utc = datetime.now(timezone.utc)
        generation_tag = f"mws:{firewall_id}:{time.time_ns()}:{uuid.uuid4().hex[:10]}"
        desired_by_list = _build_desired_entries_by_list(datasets)

        existing_list_state_count = (
            db.query(FirewallListState.id)
            .filter(
                FirewallListState.firewallsId == firewall_id,
                FirewallListState.flagInactive == 0,
            )
            .count()
        )
        existing_state_count_all = (
            db.query(FirewallAddressState.id)
            .filter(
                FirewallAddressState.firewallsId == firewall_id,
                FirewallAddressState.flagInactive == 0,
            )
            .count()
        )

        managed_count = _get_router_managed_entry_count(fw)
        if existing_list_state_count == 0 and existing_state_count_all > 0 and (managed_count or 0) > 0:
            _update_list_state_hashes(
                db,
                firewall_id=firewall_id,
                desired_by_list=desired_by_list,
                now=now_utc,
            )
            _update_history(
                db,
                record_id,
                status="skipped",
                completedAt=datetime.now(timezone.utc),
                errorMessage="initialized list hash state from existing router/state; no push needed",
            )
            _update_apply_status(
                firewall_id,
                active=False,
                status="skipped",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                lastError="initialized list hash state from existing router/state",
            )
            log.info(
                "Initialized list hash state from existing router/state; skipped push",
                extra={
                    "firewallsId": firewall_id,
                    "stateRows": existing_state_count_all,
                    "routerManagedCount": managed_count,
                },
            )
            return
        
        # Check which lists have actually changed since last push (hash-based).
        # Skip unchanged lists entirely to save CPU on collapse/push operations.
        changed_lists = _get_changed_lists(db, firewall_id, desired_by_list)
        if not changed_lists:
            log.info(
                "Skipping apply: no lists have changed since last push",
                extra={"firewallsId": firewall_id},
            )
            _update_apply_status(
                firewall_id,
                active=False,
                status="skipped",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                lastError="no lists changed since last push",
            )
            return

        desired_by_list_for_apply = {
            list_name: entries
            for list_name, entries in desired_by_list.items()
            if list_name in changed_lists
        }
        
        log.info(
            "Detected list changes; proceeding with push",
            extra={
                "firewallsId": firewall_id,
                "changedLists": sorted(changed_lists),
                "totalLists": len(desired_by_list),
            },
        )
        
        existing_state_rows = (
            db.query(FirewallAddressState)
            .filter(
                FirewallAddressState.firewallsId == firewall_id,
                FirewallAddressState.flagInactive == 0,
                FirewallAddressState.listName.in_(list(desired_by_list_for_apply.keys())),
            )
            .all()
        )

        existing_state_count = existing_state_count_all

        # If router reboot/power loss cleared dynamic lists, local delta state is stale.
        # Detect this by probing router-side managed entry count and reseed from scratch.
        if existing_state_count > 0 and managed_count == 0:
            stale_count = existing_state_count
            db.query(FirewallAddressState).filter(
                FirewallAddressState.firewallsId == firewall_id,
                FirewallAddressState.flagInactive == 0,
            ).delete(synchronize_session=False)
            db.commit()
            existing_state_rows = []
            desired_by_list_for_apply = desired_by_list
            _update_apply_status(
                firewall_id,
                routerFeedback="router dynamic lists appear reset; reseeding full state",
            )
            log.warning(
                "Detected router-side dynamic list reset; forcing full reseed",
                extra={
                    "firewallsId": firewall_id,
                    "clearedLocalStateRows": stale_count,
                },
            )

        delta_units, delta_upserts, delta_delete_ids, deferred_delete_count = _plan_delta_units(
            existing_rows=existing_state_rows,
            desired_by_list=desired_by_list_for_apply,
            generation_tag=generation_tag,
            now=now_utc,
        )
        all_chunks = _pack_script_units(delta_units)
        if deferred_delete_count:
            log.info(
                "Deferred stale deletions for next apply runs",
                extra={
                    "firewallsId": firewall_id,
                    "deferredDeletes": deferred_delete_count,
                    "deleteCap": MAX_DELETE_OPS_PER_APPLY,
                },
            )

        # Idempotency check (skipped when force=True)
        if not force and not all_chunks:
            last = (
                db.query(ApplyHistory)
                .filter(
                    ApplyHistory.firewallsId == firewall_id,
                    ApplyHistory.status == "complete",
                )
                .order_by(ApplyHistory.startedAt.desc())
                .first()
            )
            if last and last.whitelistHash == wl_hash and last.blacklistHash == bl_hash:
                log.info(
                    "Address lists unchanged; skipping apply",
                    extra={"firewallsId": firewall_id},
                )
                _update_apply_status(
                    firewall_id,
                    active=False,
                    status="skipped",
                    finishedAt=datetime.now(timezone.utc).isoformat(),
                    whitelistCount=len(allow_entries),
                    blacklistCount=len(other_entries),
                    totalRangeCount=total_range_count,
                    totalIpCount=total_ip_count,
                    lastError="address lists unchanged",
                )
                return

        _update_history(
            db,
            record_id,
            whitelistHash=wl_hash,
            blacklistHash=bl_hash,
            whitelistCount=len(allow_entries),
            blacklistCount=len(other_entries),
            totalRangeCount=total_range_count,
            totalIpCount=total_ip_count,
        )

        _update_history(db, record_id, status="pushing")
        _update_apply_status(
            firewall_id,
            status="pushing",
            sourceIp=source_ip,
            whitelistCount=len(allow_entries),
            blacklistCount=len(other_entries),
            totalRangeCount=total_range_count,
            totalIpCount=total_ip_count,
            pushChunksDone=0,
            pushChunksTotal=len(all_chunks),
            currentChunk=0,
            currentChunkTotal=len(all_chunks),
            currentChunkPreview=None,
            currentChunkText=None,
            currentChunkLineCount=0,
            currentChunkBytes=0,
            routerFeedback="starting push",
            deferredDeletes=deferred_delete_count,
            lastError=None,
        )

        last_err: str | None = None
        pushed = False
        for attempt in range(1, FETCH_RETRIES + 1):
            try:
                _push_chunks(
                    fw,
                    all_chunks,
                    on_chunk_done=lambda done, total: _update_apply_status(
                        firewall_id,
                        pushChunksDone=done,
                        pushChunksTotal=total,
                    ),
                )
                pushed = True
                break
            except _SshAuthError as exc:
                last_err = str(exc)
                log.error(
                    "SSH authentication failed; aborting retries",
                    extra={"firewallsId": firewall_id, "error": last_err},
                )
                break  # credentials won't change; no point retrying
            except Exception as exc:
                last_err = str(exc)
                log.warning(
                    "Apply attempt failed",
                    extra={"firewallsId": firewall_id, "attempt": attempt, "error": last_err},
                )
                if attempt < FETCH_RETRIES:
                    time.sleep(2 ** attempt)

        if pushed:
            _apply_delta_state(
                db,
                firewall_id=firewall_id,
                upserts=delta_upserts,
                delete_ids=delta_delete_ids,
                generation_tag=generation_tag,
                now=now_utc,
            )
            # Update list state hashes so we skip unchanged lists on next apply
            _update_list_state_hashes(
                db,
                firewall_id=firewall_id,
                desired_by_list=desired_by_list_for_apply,
                now=now_utc,
            )
            _update_history(
                db,
                record_id,
                status="complete",
                completedAt=datetime.now(timezone.utc),
            )
            _update_apply_status(
                firewall_id,
                active=False,
                status="complete",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                whitelistCount=len(allow_entries),
                blacklistCount=len(other_entries),
                totalRangeCount=total_range_count,
                totalIpCount=total_ip_count,
                lastError=None,
            )
            log.info(
                "Apply complete",
                extra={
                    "firewallsId": firewall_id,
                    "whitelistCount": len(allow_entries),
                    "blacklistCount": len(other_entries),
                    "totalRangeCount": total_range_count,
                    "totalIpCount": total_ip_count,
                },
            )
        else:
            _update_history(
                db,
                record_id,
                status="failed",
                completedAt=datetime.now(timezone.utc),
                errorMessage=last_err,
            )
            _update_apply_status(
                firewall_id,
                active=False,
                status="failed",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                whitelistCount=len(allow_entries),
                blacklistCount=len(other_entries),
                totalRangeCount=total_range_count,
                totalIpCount=total_ip_count,
                lastError=last_err,
            )
            log.error(
                "Apply failed",
                extra={"firewallsId": firewall_id, "error": last_err},
            )
    except Exception as exc:
        if record_id is not None:
            try:
                _update_history(
                    db,
                    record_id,
                    status="failed",
                    completedAt=datetime.now(timezone.utc),
                    errorMessage=str(exc),
                )
            except Exception:
                db.rollback()
        _update_apply_status(
            firewall_id,
            active=False,
            status="failed",
            finishedAt=datetime.now(timezone.utc).isoformat(),
            lastError=str(exc),
        )
        log.exception("Unhandled apply failure", extra={"firewallsId": firewall_id})
        raise
    finally:
        db.close()


def apply_all(force: bool = False) -> None:
    """Apply to all active firewalls."""
    db = SessionLocal()
    try:
        ids = [
            r.id
            for r in db.query(Firewall.id)
            .filter(Firewall.flagInactive == 0)
            .all()
        ]
    finally:
        db.close()
    for fw_id in ids:
        apply_firewall(fw_id, force=force)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _update_history(db, record_id: int, **kwargs) -> None:
    db.query(ApplyHistory).filter(ApplyHistory.id == record_id).update(kwargs)
    db.commit()


def reconcile_interrupted_applies(source: str = "startup") -> int:
    """Mark stale in-progress apply rows as failed after service restart."""
    db = SessionLocal()
    try:
        stale_ids = [
            row.id
            for row in db.query(ApplyHistory.id)
            .filter(
                ApplyHistory.status.in_(tuple(IN_PROGRESS_APPLY_STATUSES)),
                ApplyHistory.completedAt.is_(None),
            )
            .all()
        ]
        if not stale_ids:
            return 0

        now_utc = datetime.now(timezone.utc)
        reason = f"interrupted by service restart ({source})"
        db.query(ApplyHistory).filter(ApplyHistory.id.in_(stale_ids)).update(
            {
                "status": "failed",
                "completedAt": now_utc,
                "errorMessage": reason,
            },
            synchronize_session=False,
        )
        db.commit()
        log.warning(
            "Reconciled interrupted applies",
            extra={"count": len(stale_ids), "source": source},
        )
        return len(stale_ids)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


_scheduler = BackgroundScheduler()
_scheduled_ids: dict[int, str] = {}


def _sync_schedule() -> None:
    db = SessionLocal()
    try:
        rows = (
            db.query(Firewall.id, Firewall.applyFrequencyHours)
            .filter(Firewall.flagInactive == 0, Firewall.applyFrequencyHours > 0)
            .all()
        )
    finally:
        db.close()

    desired: dict[int, int] = {r.id: r.applyFrequencyHours for r in rows}
    current_ids = set(_scheduled_ids.keys())
    desired_ids = set(desired.keys())

    for remove_id in current_ids - desired_ids:
        _scheduler.remove_job(_scheduled_ids.pop(remove_id))

    for add_id in desired_ids - current_ids:
        hours = desired[add_id]
        job = _scheduler.add_job(
            apply_firewall,
            "interval",
            hours=hours,
            args=[add_id, False],
            id=f"apply_{add_id}",
            replace_existing=True,
        )
        _scheduled_ids[add_id] = job.id

    for update_id in current_ids & desired_ids:
        job = _scheduler.get_job(_scheduled_ids[update_id])
        if job and job.trigger.interval.total_seconds() != desired[update_id] * 3600:
            _scheduler.reschedule_job(
                _scheduled_ids[update_id], trigger="interval", hours=desired[update_id]
            )


def _is_applicator_enabled() -> bool:
    db = SessionLocal()
    try:
        row = (
            db.query(Configuration)
            .filter(Configuration.configurationItem == "applicatorEnabled")
            .first()
        )
        return (row.configurationItemValue or "0") == "1"
    finally:
        db.close()


def _schedule_check() -> None:
    if _is_applicator_enabled():
        _sync_schedule()
    else:
        for fw_id, job_id in list(_scheduled_ids.items()):
            _scheduler.remove_job(job_id)
            del _scheduled_ids[fw_id]


def run() -> None:
    """Entry point for the applicator container."""
    configure_logging()
    log.info("Applicator service starting")
    reconcile_interrupted_applies(source="applicator-startup")

    _scheduler.add_job(_schedule_check, "interval", seconds=60, id="schedule_check")
    _scheduler.start()

    log.info("Applicator scheduler running")
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        _scheduler.shutdown()
        log.info("Applicator service stopped")


if __name__ == "__main__":
    run()
