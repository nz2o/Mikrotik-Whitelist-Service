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
    """Safely collapse combined entries while preserving TTL semantics.

    Rules:
    - Collapse globally within identical TTL buckets.
    - For exact duplicate CIDRs across TTLs, keep the longest TTL.
    - Drop a narrower CIDR only when it is already covered by a broader CIDR
      with an equal or longer TTL.
    """
    ttl_groups: dict[int, list[str]] = {}
    for cidr, ttl in entries:
        ttl_groups.setdefault(ttl, []).append(cidr)

    by_network: dict[str, int] = {}
    for ttl, cidrs in ttl_groups.items():
        for collapsed_cidr in _consolidate(cidrs):
            by_network[collapsed_cidr] = max(ttl, by_network.get(collapsed_cidr, 0))

    ordered = sorted(
        (
            (ipaddress.IPv4Network(cidr, strict=False), ttl)
            for cidr, ttl in by_network.items()
        ),
        key=lambda item: (item[0].prefixlen, int(item[0].network_address)),
    )

    result: list[tuple[ipaddress.IPv4Network, int]] = []
    for network, ttl in ordered:
        covered = False
        for existing_network, existing_ttl in result:
            if network.subnet_of(existing_network) and existing_ttl >= ttl:
                covered = True
                break
        if covered:
            continue
        result.append((network, ttl))

    return [(str(network), ttl) for network, ttl in result]


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
    db = SessionLocal()
    try:
        active_lists = (
            db.query(IpList)
            .filter(IpList.flagInactive == 0)
            .all()
        )
        active_domain_lists = (
            db.query(DomainList)
            .filter(DomainList.flagInactive == 0)
            .all()
        )
        total = len(active_lists) + len(active_domain_lists)
        done = 0
        datasets: dict[int, list[tuple[str, int]]] = {
            code: [] for code, _label in IpList.TYPE_OPTIONS
        }
        for il in active_lists:
            ttl = il.ttlDays if il.ttlDays is not None else DEFAULT_TTL_DAYS
            list_type = il.flagBlacklist if il.flagBlacklist in datasets else IpList.TYPE_ALLOW
            raw = [
                r.ipAddress
                for r in db.query(IpAddress.ipAddress)
                .filter(
                    IpAddress.iplistsId == il.id,
                    IpAddress.flagInactive == 0,
                )
                .all()
            ]
            consolidated = _consolidate(raw)
            entries = [(cidr, ttl) for cidr in consolidated]
            datasets[list_type].extend(entries)
            done += 1
            if on_list_done:
                on_list_done(done, total)

        for dl in active_domain_lists:
            ttl = dl.ttlDays if dl.ttlDays is not None else DEFAULT_TTL_DAYS
            list_type = dl.listType if dl.listType in datasets else IpList.TYPE_ALLOW
            raw = [
                r.ipAddress
                for r in db.query(Domain.ipAddress)
                .filter(
                    Domain.domainListsId == dl.id,
                    Domain.flagInactive == 0,
                )
                .all()
            ]
            consolidated = _consolidate(raw)
            entries = [(cidr, ttl) for cidr in consolidated]
            datasets[list_type].extend(entries)
            done += 1
            if on_list_done:
                on_list_done(done, total)
    finally:
        db.close()

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


def get_combined_entries(on_list_done=None) -> dict[int, list[tuple[str, int]]]:
    """Public helper for export and apply consumers."""
    datasets = _build_datasets(on_list_done=on_list_done)
    return {list_type: _collapse_entries(entries) for list_type, entries in datasets.items()}


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


def _push_chunks(fw: "Firewall", chunks: list[str]) -> None:
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
        for chunk in chunks:
            stdin, stdout, stderr = client.exec_command(chunk, timeout=APPLY_TIMEOUT_SECONDS)
            exit_code = stdout.channel.recv_exit_status()
            err_output = stderr.read().decode().strip()
            if exit_code != 0:
                raise RuntimeError(
                    f"RouterOS command failed (exit {exit_code}): {err_output}"
                )
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
        )
        datasets = get_combined_entries(
            on_list_done=lambda done, total: _update_apply_status(
                firewall_id, processedLists=done, totalLists=total
            )
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
            lastError=None,
        )

        last_err: str | None = None
        pushed = False
        for attempt in range(1, FETCH_RETRIES + 1):
            try:
                _push_chunks(fw, all_chunks)
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
