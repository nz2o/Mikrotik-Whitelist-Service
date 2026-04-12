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
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import paramiko
from apscheduler.schedulers.background import BackgroundScheduler

from app.config import APPLY_TIMEOUT_SECONDS, FETCH_RETRIES, configure_logging
from app.crypto import decrypt_secret
from app.database import SessionLocal
from app.models import ApplyHistory, Configuration, Domain, DomainList, Firewall, IpAddress, IpList

log = logging.getLogger(__name__)


class _SshAuthError(Exception):
    """SSH authentication failure — retrying will not help."""


CHUNK_SIZE = 500  # max CIDRs per RouterOS script chunk
_APPLY_STATUS_LOCK = threading.Lock()
_APPLY_STATUS: dict[int, dict[str, object]] = {}


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


def _consolidate(cidrs: list[str]) -> list[str]:
    """Deduplicate and supernet-collapse a list of IPv4 CIDR strings."""
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.IPv4Network(c, strict=False))
        except ValueError:
            log.warning("Skipping invalid CIDR during consolidation", extra={"cidr": c})
    collapsed = list(ipaddress.collapse_addresses(nets))
    return [str(n) for n in collapsed]


def _collapse_entries(entries: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """Collapse combined entries to minimal set of non-overlapping CIDRs.
    
    Since every push replaces the entire list, TTL semantics don't need to be 
    preserved across different sources. Just deduplicate and supernet-collapse all CIDRs.
    Returns all collapsed networks with a default TTL of 0 (immaterial since replaced on next push).
    """
    if not entries:
        return []
    
    # Extract unique CIDRs and parse as networks
    unique_cidrs = set()
    for cidr, _ttl in entries:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            unique_cidrs.add(str(net))
        except ValueError:
            log.warning("Skipping invalid CIDR during collapse", extra={"cidr": cidr})
    
    if not unique_cidrs:
        return []
    
    # Collapse all at once (highly optimized C code)
    networks = [ipaddress.IPv4Network(cidr, strict=False) for cidr in unique_cidrs]
    collapsed = list(ipaddress.collapse_addresses(networks))
    
    # Return with default TTL (irrelevant since entire list is replaced each push)
    return [(str(net), 0) for net in collapsed]


def _update_apply_status(firewall_id: int, **updates) -> None:
    with _APPLY_STATUS_LOCK:
        current = dict(_APPLY_STATUS.get(firewall_id, {}))
        current.update(updates)
        _APPLY_STATUS[firewall_id] = current


def get_apply_status(firewall_id: int) -> dict[str, object]:
    with _APPLY_STATUS_LOCK:
        return dict(_APPLY_STATUS.get(firewall_id, {}))


def trigger_apply_async(firewall_id: int, force: bool = False) -> bool:
    with _APPLY_STATUS_LOCK:
        current = _APPLY_STATUS.get(firewall_id, {})
        if current.get("active"):
            return False
    threading.Thread(target=apply_firewall, args=(firewall_id, force), daemon=True).start()
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


# ---------------------------------------------------------------------------
# RouterOS script generation
# ---------------------------------------------------------------------------


def _make_rsc_chunks(list_name: str, entries: list[tuple[str, int]]) -> list[str]:
    """
    Return a list of RouterOS script strings. The first chunk removes the
    existing address list atomically, subsequent chunks append.
    Each entry is a (cidr, ttl_days) tuple so different IP lists can carry
    different TTL values within the same RouterOS address list.
    Split into CHUNK_SIZE batches to avoid SSH/execution timeouts.
    """
    chunks: list[str] = []
    for batch_index, start in enumerate(range(0, len(entries), CHUNK_SIZE)):
        batch = entries[start : start + CHUNK_SIZE]
        lines: list[str] = []
        if batch_index == 0:
            # Atomic removal of old list before inserting new entries
            lines.append(f'/ip firewall address-list remove [find list="{list_name}"]')
        for cidr, ttl in batch:
            lines.append(
                f'/ip firewall address-list add list="{list_name}" '
                f'address={cidr} timeout={ttl}d'
            )
        chunks.append("\n".join(lines) + "\n")
    # Edge case: if entries is empty, still remove old list
    if not entries:
        chunks = [f'/ip firewall address-list remove [find list="{list_name}"]\n']
    return chunks


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
    return "".join(_make_rsc_chunks(list_name, entries))


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
    return "".join(_make_rsc_chunks(list_name, entries))


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
            stdin, stdout, stderr = client.exec_command(chunk, timeout=APPLY_TIMEOUT_SECONDS)
            exit_code = stdout.channel.recv_exit_status()
            err_output = stderr.read().decode().strip()
            if exit_code != 0:
                raise RuntimeError(
                    f"RouterOS command failed (exit {exit_code}): {err_output}"
                )
            if on_chunk_done:
                on_chunk_done(idx, total_chunks)
        client.close()
    finally:
        # Ensure the plaintext is not held in memory after this point
        del plaintext_secret


# ---------------------------------------------------------------------------
# Apply lifecycle
# ---------------------------------------------------------------------------


def apply_firewall(firewall_id: int, force: bool = False) -> None:
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
            "processedLists": 0,
            "totalLists": 0,
            "processedBuckets": 0,
            "totalBuckets": 0,
            "pushChunksDone": 0,
            "pushChunksTotal": 0,
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

        record = ApplyHistory(
            firewallsId=firewall_id,
            status="connecting",
            startedAt=datetime.now(timezone.utc),
            whitelistHash=None,
            blacklistHash=None,
            whitelistCount=0,
            blacklistCount=0,
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

        wl_hash = _sha256_of(allow_entries)  # includes cidr+ttl in hash
        bl_hash = _sha256_of(other_entries)

        # Idempotency check (skipped when force=True)
        if not force:
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
        )

        all_chunks: list[str] = []
        for code, _label in IpList.TYPE_OPTIONS:
            list_name = TYPE_TO_LIST_NAME[code]
            all_chunks.extend(_make_rsc_chunks(list_name, datasets.get(code, [])))

        _update_history(db, record_id, status="pushing")
        _update_apply_status(
            firewall_id,
            status="pushing",
            sourceIp=source_ip,
            whitelistCount=len(allow_entries),
            blacklistCount=len(other_entries),
            pushChunksDone=0,
            pushChunksTotal=len(all_chunks),
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
                lastError=None,
            )
            log.info(
                "Apply complete",
                extra={
                    "firewallsId": firewall_id,
                    "whitelistCount": len(allow_entries),
                    "blacklistCount": len(other_entries),
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
