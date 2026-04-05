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
import time
from datetime import datetime, timezone
from typing import Optional

import paramiko
from apscheduler.schedulers.background import BackgroundScheduler

from app.config import APPLY_TIMEOUT_SECONDS, FETCH_RETRIES, configure_logging
from app.crypto import decrypt_secret
from app.database import SessionLocal
from app.models import ApplyHistory, Configuration, Firewall, IpAddress, IpList

log = logging.getLogger(__name__)

CHUNK_SIZE = 500  # max CIDRs per RouterOS script chunk


# ---------------------------------------------------------------------------
# CIDR consolidation
# ---------------------------------------------------------------------------


DEFAULT_TTL_DAYS = 7


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


def _build_datasets() -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Return (whitelist_entries, blacklist_entries) where each entry is (cidr, ttl_days).

    CIDRs are consolidated within each IP list separately so that per-list TTL
    values are preserved.  Entries from different lists are NOT merged together.
    """
    db = SessionLocal()
    try:
        active_lists = (
            db.query(IpList)
            .filter(IpList.flagInactive == 0)
            .all()
        )
        whitelist_entries: list[tuple[str, int]] = []
        blacklist_entries: list[tuple[str, int]] = []
        for il in active_lists:
            ttl = il.ttlDays if il.ttlDays is not None else DEFAULT_TTL_DAYS
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
            if il.flagBlacklist == 1:
                blacklist_entries.extend(entries)
            else:
                whitelist_entries.extend(entries)
    finally:
        db.close()

    return whitelist_entries, blacklist_entries


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
    if kind == "whitelist":
        return "ip-whitelist-dynamic"
    if kind == "blacklist":
        return "ip-blacklist-dynamic"
    raise ValueError("kind must be 'whitelist' or 'blacklist'")


def _normalize_ttl(ttl_days: Optional[int]) -> int:
    if ttl_days is None:
        return DEFAULT_TTL_DAYS
    if ttl_days < 1:
        return DEFAULT_TTL_DAYS
    return ttl_days


def get_combined_entries() -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Public helper for export and apply consumers."""
    return _build_datasets()


def build_combined_rsc(kind: str) -> str:
    """Build full RouterOS script for combined whitelist or blacklist."""
    whitelist, blacklist = get_combined_entries()
    if kind == "whitelist":
        entries = whitelist
    elif kind == "blacklist":
        entries = blacklist
    else:
        raise ValueError("kind must be 'whitelist' or 'blacklist'")
    list_name = _kind_to_list_name(kind)
    return "".join(_make_rsc_chunks(list_name, entries))


def build_combined_plain(kind: str) -> str:
    """Build globally collapsed/de-duplicated CIDR list for combined data."""
    whitelist, blacklist = get_combined_entries()
    if kind == "whitelist":
        entries = whitelist
    elif kind == "blacklist":
        entries = blacklist
    else:
        raise ValueError("kind must be 'whitelist' or 'blacklist'")
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
    list_name = "ip-blacklist-dynamic" if iplist.flagBlacklist == 1 else "ip-whitelist-dynamic"
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


def _push_chunks(fw: Firewall, chunks: list[str]) -> None:
    """Connect to firewall via SSH and execute all script chunks."""
    plaintext_secret = decrypt_secret(fw.firewallSecret)
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
    db = SessionLocal()
    try:
        fw = db.query(Firewall).filter(Firewall.id == firewall_id).first()
        if not fw:
            log.error("Firewall not found", extra={"firewallsId": firewall_id})
            return
        if fw.flagInactive == 1:
            log.info("Skipping inactive firewall", extra={"firewallsId": firewall_id})
            return

        whitelist, blacklist = _build_datasets()
        wl_hash = _sha256_of(whitelist)  # includes cidr+ttl in hash
        bl_hash = _sha256_of(blacklist)

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
                return

        record = ApplyHistory(
            firewallsId=firewall_id,
            status="generating",
            startedAt=datetime.now(timezone.utc),
            whitelistHash=wl_hash,
            blacklistHash=bl_hash,
            whitelistCount=len(whitelist),
            blacklistCount=len(blacklist),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        record_id = record.id

        wl_chunks = _make_rsc_chunks("ip-whitelist-dynamic", whitelist)
        bl_chunks = _make_rsc_chunks("ip-blacklist-dynamic", blacklist)

        _update_history(db, record_id, status="pushing")

        last_err: str | None = None
        pushed = False
        for attempt in range(1, FETCH_RETRIES + 1):
            try:
                _push_chunks(fw, wl_chunks + bl_chunks)
                pushed = True
                break
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
            log.info(
                "Apply complete",
                extra={
                    "firewallsId": firewall_id,
                    "whitelistCount": len(whitelist),
                    "blacklistCount": len(blacklist),
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
            log.error(
                "Apply failed",
                extra={"firewallsId": firewall_id, "error": last_err},
            )
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
