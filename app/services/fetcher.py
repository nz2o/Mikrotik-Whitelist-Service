"""HTTP/HTTPS Fetcher Service.

Responsibilities:
- Schedule a fetch per active iplist based on fetchFrequencyHours.
- On each fetch: download raw file, parse CIDRs, atomic DB load, update lastSync.
- Log progress to fetchJobs and errors to fetchErrors.
- Expose fetch_list(iplist_id) and fetch_all() for use by API triggers.
"""

import ipaddress
import logging
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import httpx
from apscheduler.schedulers.background import BackgroundScheduler

from app.config import (
    FETCH_RETRIES,
    FETCH_TIMEOUT_SECONDS,
    RAWIPLISTS_DIR,
    configure_logging,
)
from app.database import SessionLocal
from app.models import Domain, DomainList, FetchError, FetchJob, IpAddress, IpList

log = logging.getLogger(__name__)

DOMAIN_RESOLVE_WORKERS = max(8, min(32, (os.cpu_count() or 4) * 4))
_DOMAIN_FETCH_STATUS_LOCK = threading.Lock()
_DOMAIN_FETCH_STATUS: dict[int, dict[str, object]] = {}


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_lines(lines: list[str]) -> tuple[list[str], int]:
    """Return (valid_cidrs, total_parsed_count).

    Accepts plain IPv4 addresses and IPv4 CIDR notation.
    Bare IPs (no prefix) are normalised to /32.
    Malformed lines are logged and skipped.
    """
    valid: list[str] = []
    parsed = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parsed += 1
        # Strip inline comments
        line = line.split("#")[0].split(";")[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.IPv4Network(line, strict=False)
            valid.append(str(net))
        except ValueError:
            log.warning("Skipping malformed IP/CIDR entry", extra={"entry": line})
    return valid, parsed


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")


def _parse_domain_lines(lines: list[str]) -> tuple[list[str], int]:
    """Return (valid_domains, total_parsed_count)."""
    valid: list[str] = []
    parsed = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parsed += 1
        line = line.split("#")[0].split(";")[0].strip().lower().rstrip(".")
        if not line:
            continue
        if _DOMAIN_RE.match(line):
            valid.append(line)
        else:
            log.warning("Skipping malformed domain entry", extra={"entry": line})
    return valid, parsed


def _resolve_domain_ipv4(domain: str) -> list[str]:
    """Resolve all A records for a domain name."""
    results: set[str] = set()
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        for info in infos:
            addr = info[4][0]
            results.add(str(ipaddress.IPv4Address(addr)))
    except Exception as exc:
        log.warning("DNS resolution failed", extra={"domain": domain, "error": str(exc)})
    return sorted(results)


def _update_domain_fetch_status(domain_list_id: int, **updates) -> None:
    with _DOMAIN_FETCH_STATUS_LOCK:
        current = dict(_DOMAIN_FETCH_STATUS.get(domain_list_id, {}))
        current.update(updates)
        _DOMAIN_FETCH_STATUS[domain_list_id] = current


def get_domain_fetch_status(domain_list_id: int) -> dict[str, object]:
    with _DOMAIN_FETCH_STATUS_LOCK:
        return dict(_DOMAIN_FETCH_STATUS.get(domain_list_id, {}))


def trigger_domain_fetch_async(domain_list_id: int) -> bool:
    with _DOMAIN_FETCH_STATUS_LOCK:
        current = _DOMAIN_FETCH_STATUS.get(domain_list_id, {})
        if current.get("active"):
            return False
    threading.Thread(target=fetch_domain_list, args=[domain_list_id], daemon=True).start()
    return True


# ---------------------------------------------------------------------------
# Core fetch logic
# ---------------------------------------------------------------------------


def fetch_list(iplist_id: int) -> None:
    """Fetch and load a single iplist. Called by scheduler and API trigger."""
    db = SessionLocal()
    try:
        iplist = db.query(IpList).filter(IpList.id == iplist_id).first()
        if not iplist:
            log.error("iplist not found", extra={"iplistsId": iplist_id})
            return
        if iplist.flagInactive == 1:
            log.info("Skipping inactive iplist", extra={"iplistsId": iplist_id})
            return
        if iplist.flagUserDefined == 1:
            log.info("Skipping user-defined iplist", extra={"iplistsId": iplist_id})
            return
        if not iplist.url:
            log.info("Skipping iplist with no URL", extra={"iplistsId": iplist_id})
            return

        # Create fetchJob record
        job = FetchJob(
            iplistsId=iplist_id,
            status="fetching",
            startedAt=datetime.now(timezone.utc),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        job_id = job.id

        raw_path = Path(RAWIPLISTS_DIR) / f"{iplist_id}.iplist"

        # ── Download with retry ──────────────────────────────────────────────
        last_error: str | None = None
        downloaded = False
        for attempt in range(1, FETCH_RETRIES + 1):
            try:
                with httpx.Client(timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=True) as client:
                    resp = client.get(iplist.url)
                    resp.raise_for_status()
                raw_path.parent.mkdir(parents=True, exist_ok=True)
                raw_path.write_bytes(resp.content)
                downloaded = True
                break
            except Exception as exc:
                last_error = str(exc)
                log.warning(
                    "Fetch attempt failed",
                    extra={"iplistsId": iplist_id, "attempt": attempt, "error": last_error},
                )
                db.add(FetchError(iplistsId=iplist_id, attempt=attempt, errorMessage=last_error))
                db.commit()
                if attempt < FETCH_RETRIES:
                    time.sleep(2 ** attempt)

        if not downloaded:
            _fail_job(db, job_id, iplist_id, f"Download failed after {FETCH_RETRIES} attempts: {last_error}")
            return

        # ── Parse ────────────────────────────────────────────────────────────
        _update_job(db, job_id, status="parsing")
        lines = raw_path.read_text(errors="replace").splitlines()
        valid_cidrs, entries_parsed = _parse_lines(lines)

        # ── Atomic DB load ───────────────────────────────────────────────────
        _update_job(db, job_id, status="loading")
        try:
            db.query(IpAddress).filter(IpAddress.iplistsId == iplist_id).delete()
            db.bulk_insert_mappings(
                IpAddress,
                [{"ipAddress": cidr, "iplistsId": iplist_id} for cidr in valid_cidrs],
            )
            iplist.lastSync = datetime.now(timezone.utc)
            _update_job(
                db,
                job_id,
                status="complete",
                completedAt=datetime.now(timezone.utc),
                entriesParsed=entries_parsed,
                entriesLoaded=len(valid_cidrs),
            )
            db.commit()
            log.info(
                "Fetch complete",
                extra={
                    "iplistsId": iplist_id,
                    "url": iplist.url,
                    "entriesParsed": entries_parsed,
                    "entriesLoaded": len(valid_cidrs),
                },
            )
        except Exception as exc:
            db.rollback()
            _fail_job(db, job_id, iplist_id, f"DB load failed: {exc}")
    finally:
        db.close()


def fetch_all() -> None:
    """Trigger an immediate fetch of all active iplists."""
    db = SessionLocal()
    try:
        ids = [
            row.id
            for row in db.query(IpList.id)
            .filter(IpList.flagInactive == 0, IpList.flagUserDefined == 0)
            .all()
        ]
    finally:
        db.close()
    for iplist_id in ids:
        fetch_list(iplist_id)


def fetch_domain_list(domain_list_id: int) -> None:
    """Fetch and resolve a single domain list."""
    with _DOMAIN_FETCH_STATUS_LOCK:
        current = _DOMAIN_FETCH_STATUS.get(domain_list_id, {})
        if current.get("active"):
            log.info("Domain fetch already running", extra={"domainListsId": domain_list_id})
            return
        _DOMAIN_FETCH_STATUS[domain_list_id] = {
            "domainListsId": domain_list_id,
            "active": True,
            "status": "starting",
            "startedAt": datetime.now(timezone.utc).isoformat(),
            "finishedAt": None,
            "parsedDomains": 0,
            "totalDomains": 0,
            "processedDomains": 0,
            "resolvedRows": 0,
            "lastError": None,
        }

    db = SessionLocal()
    try:
        dlist = db.query(DomainList).filter(DomainList.id == domain_list_id).first()
        if not dlist:
            log.error("domain list not found", extra={"domainListsId": domain_list_id})
            _update_domain_fetch_status(
                domain_list_id,
                active=False,
                status="failed",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                lastError="domain list not found",
            )
            return
        if dlist.flagInactive == 1:
            log.info("Skipping inactive domain list", extra={"domainListsId": domain_list_id})
            _update_domain_fetch_status(
                domain_list_id,
                active=False,
                status="skipped",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                lastError="inactive domain list",
            )
            return
        if dlist.flagUserDefined == 1:
            log.info("Skipping user-defined domain list", extra={"domainListsId": domain_list_id})
            _update_domain_fetch_status(
                domain_list_id,
                active=False,
                status="skipped",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                lastError="user-defined domain list",
            )
            return
        if not dlist.url:
            log.info("Skipping domain list with no URL", extra={"domainListsId": domain_list_id})
            _update_domain_fetch_status(
                domain_list_id,
                active=False,
                status="failed",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                lastError="domain list URL is empty",
            )
            return

        raw_path = Path(RAWIPLISTS_DIR) / f"domain_{domain_list_id}.list"
        _update_domain_fetch_status(domain_list_id, status="fetching")

        last_error: str | None = None
        downloaded = False
        for attempt in range(1, FETCH_RETRIES + 1):
            try:
                with httpx.Client(timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=True) as client:
                    resp = client.get(dlist.url)
                    resp.raise_for_status()
                raw_path.parent.mkdir(parents=True, exist_ok=True)
                raw_path.write_bytes(resp.content)
                downloaded = True
                break
            except Exception as exc:
                last_error = str(exc)
                log.warning(
                    "Domain fetch attempt failed",
                    extra={"domainListsId": domain_list_id, "attempt": attempt, "error": last_error},
                )
                if attempt < FETCH_RETRIES:
                    time.sleep(2 ** attempt)

        if not downloaded:
            log.error(
                "Domain fetch failed",
                extra={"domainListsId": domain_list_id, "error": last_error},
            )
            _update_domain_fetch_status(
                domain_list_id,
                active=False,
                status="failed",
                finishedAt=datetime.now(timezone.utc).isoformat(),
                lastError=last_error,
            )
            return

        lines = raw_path.read_text(errors="replace").splitlines()
        domains, parsed_count = _parse_domain_lines(lines)
        domains = list(dict.fromkeys(domains))
        _update_domain_fetch_status(
            domain_list_id,
            status="resolving",
            parsedDomains=parsed_count,
            totalDomains=len(domains),
            processedDomains=0,
            resolvedRows=0,
            lastError=None,
        )

        log.info(
            "Domain fetch started",
            extra={
                "domainListsId": domain_list_id,
                "url": dlist.url,
                "domainsParsed": parsed_count,
                "uniqueDomains": len(domains),
            },
        )

        resolved_rows: list[dict[str, object]] = []
        processed_domains = 0
        with ThreadPoolExecutor(max_workers=DOMAIN_RESOLVE_WORKERS) as executor:
            futures = {executor.submit(_resolve_domain_ipv4, domain): domain for domain in domains}
            for future in as_completed(futures):
                domain = futures[future]
                ips = future.result()
                processed_domains += 1
                for ip in ips:
                    resolved_rows.append(
                        {
                            "domainName": domain,
                            "ipAddress": ip,
                            "domainListsId": domain_list_id,
                        }
                    )
                if processed_domains == len(domains) or processed_domains % 250 == 0:
                    _update_domain_fetch_status(
                        domain_list_id,
                        processedDomains=processed_domains,
                        resolvedRows=len(resolved_rows),
                    )

        db.query(Domain).filter(Domain.domainListsId == domain_list_id).delete()
        if resolved_rows:
            db.bulk_insert_mappings(Domain, resolved_rows)
        dlist.lastSync = datetime.now(timezone.utc)
        db.commit()
        _update_domain_fetch_status(
            domain_list_id,
            active=False,
            status="complete",
            finishedAt=datetime.now(timezone.utc).isoformat(),
            processedDomains=len(domains),
            resolvedRows=len(resolved_rows),
            lastError=None,
        )
        log.info(
            "Domain fetch complete",
            extra={
                "domainListsId": domain_list_id,
                "url": dlist.url,
                "domainsParsed": parsed_count,
                "resolvedRows": len(resolved_rows),
            },
        )
    except Exception as exc:
        _update_domain_fetch_status(
            domain_list_id,
            active=False,
            status="failed",
            finishedAt=datetime.now(timezone.utc).isoformat(),
            lastError=str(exc),
        )
        raise
    finally:
        db.close()


def fetch_all_domain_lists() -> None:
    """Trigger an immediate fetch of all active downloaded domain lists."""
    db = SessionLocal()
    try:
        ids = [
            row.id
            for row in db.query(DomainList.id)
            .filter(DomainList.flagInactive == 0, DomainList.flagUserDefined == 0)
            .all()
        ]
    finally:
        db.close()
    for domain_list_id in ids:
        fetch_domain_list(domain_list_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _update_job(db, job_id: int, **kwargs) -> None:
    db.query(FetchJob).filter(FetchJob.id == job_id).update(kwargs)
    db.commit()


def _fail_job(db, job_id: int, iplist_id: int, error: str) -> None:
    log.error("Fetch failed", extra={"iplistsId": iplist_id, "error": error})
    _update_job(
        db,
        job_id,
        status="failed",
        completedAt=datetime.now(timezone.utc),
        errorMessage=error,
    )


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


_scheduler = BackgroundScheduler()
_scheduled_ids: dict[int, str] = {}  # iplist_id -> APScheduler job id
_domain_scheduled_ids: dict[int, str] = {}  # domain_list_id -> APScheduler job id


def _sync_schedule() -> None:
    """Re-read DB and adjust scheduled jobs to match current iplists config."""
    db = SessionLocal()
    try:
        rows = (
            db.query(IpList.id, IpList.fetchFrequencyHours)
            .filter(
                IpList.flagInactive == 0,
                IpList.flagUserDefined == 0,
                IpList.fetchFrequencyHours > 0,
            )
            .all()
        )
    finally:
        db.close()

    desired: dict[int, int] = {r.id: r.fetchFrequencyHours for r in rows}
    current_ids = set(_scheduled_ids.keys())
    desired_ids = set(desired.keys())

    for remove_id in current_ids - desired_ids:
        _scheduler.remove_job(_scheduled_ids.pop(remove_id))
        log.info("Removed fetch schedule", extra={"iplistsId": remove_id})

    for add_id in desired_ids - current_ids:
        hours = desired[add_id]
        job = _scheduler.add_job(
            fetch_list,
            "interval",
            hours=hours,
            args=[add_id],
            id=f"fetch_{add_id}",
            replace_existing=True,
        )
        _scheduled_ids[add_id] = job.id
        log.info("Added fetch schedule", extra={"iplistsId": add_id, "hours": hours})

    # Update frequency if changed
    for update_id in current_ids & desired_ids:
        job = _scheduler.get_job(_scheduled_ids[update_id])
        if job and job.trigger.interval.total_seconds() != desired[update_id] * 3600:
            _scheduler.reschedule_job(
                _scheduled_ids[update_id], trigger="interval", hours=desired[update_id]
            )
            log.info(
                "Rescheduled fetch",
                extra={"iplistsId": update_id, "hours": desired[update_id]},
            )


def _sync_domain_schedule() -> None:
    """Re-read DB and adjust scheduled jobs for domain lists."""
    db = SessionLocal()
    try:
        rows = (
            db.query(DomainList.id, DomainList.fetchFrequencyHours)
            .filter(
                DomainList.flagInactive == 0,
                DomainList.flagUserDefined == 0,
                DomainList.fetchFrequencyHours > 0,
            )
            .all()
        )
    finally:
        db.close()

    desired: dict[int, int] = {r.id: r.fetchFrequencyHours for r in rows}
    current_ids = set(_domain_scheduled_ids.keys())
    desired_ids = set(desired.keys())

    for remove_id in current_ids - desired_ids:
        _scheduler.remove_job(_domain_scheduled_ids.pop(remove_id))
        log.info("Removed domain fetch schedule", extra={"domainListsId": remove_id})

    for add_id in desired_ids - current_ids:
        hours = desired[add_id]
        job = _scheduler.add_job(
            fetch_domain_list,
            "interval",
            hours=hours,
            args=[add_id],
            id=f"domain_fetch_{add_id}",
            replace_existing=True,
        )
        _domain_scheduled_ids[add_id] = job.id
        log.info("Added domain fetch schedule", extra={"domainListsId": add_id, "hours": hours})

    for update_id in current_ids & desired_ids:
        job = _scheduler.get_job(_domain_scheduled_ids[update_id])
        if job and job.trigger.interval.total_seconds() != desired[update_id] * 3600:
            _scheduler.reschedule_job(
                _domain_scheduled_ids[update_id], trigger="interval", hours=desired[update_id]
            )
            log.info(
                "Rescheduled domain fetch",
                extra={"domainListsId": update_id, "hours": desired[update_id]},
            )


def _is_fetcher_enabled() -> bool:
    db = SessionLocal()
    try:
        from app.models import Configuration
        row = (
            db.query(Configuration)
            .filter(Configuration.configurationItem == "fetcherEnabled")
            .first()
        )
        return (row.configurationItemValue or "0") == "1"
    finally:
        db.close()


def _run_catchup_fetches() -> None:
    """Run one-off catch-up fetches for overdue lists.

    This protects against missed interval executions (container restarts, scheduler
    hiccups, clock drift). If a list is overdue and not currently in an active
    fetch state, trigger a fetch immediately.
    """
    now = datetime.now(timezone.utc)
    db = SessionLocal()
    try:
        rows = (
            db.query(IpList.id, IpList.fetchFrequencyHours, IpList.lastSync)
            .filter(
                IpList.flagInactive == 0,
                IpList.flagUserDefined == 0,
                IpList.fetchFrequencyHours > 0,
            )
            .all()
        )

        for row in rows:
            latest_job = (
                db.query(FetchJob.status)
                .filter(FetchJob.iplistsId == row.id)
                .order_by(FetchJob.startedAt.desc())
                .first()
            )
            if latest_job and latest_job.status in {"pending", "fetching", "parsing", "loading"}:
                continue

            overdue = (
                row.lastSync is None
                or (now - row.lastSync).total_seconds() >= row.fetchFrequencyHours * 3600
            )
            if overdue:
                log.info(
                    "Running catch-up fetch for overdue list",
                    extra={"iplistsId": row.id, "hours": row.fetchFrequencyHours},
                )
                fetch_list(row.id)
    finally:
        db.close()


def _run_domain_catchup_fetches() -> None:
    """Run one-off catch-up fetches for overdue domain lists."""
    now = datetime.now(timezone.utc)
    db = SessionLocal()
    try:
        rows = (
            db.query(DomainList.id, DomainList.fetchFrequencyHours, DomainList.lastSync)
            .filter(
                DomainList.flagInactive == 0,
                DomainList.flagUserDefined == 0,
                DomainList.fetchFrequencyHours > 0,
            )
            .all()
        )
        for row in rows:
            overdue = (
                row.lastSync is None
                or (now - row.lastSync).total_seconds() >= row.fetchFrequencyHours * 3600
            )
            if overdue:
                log.info(
                    "Running catch-up fetch for overdue domain list",
                    extra={"domainListsId": row.id, "hours": row.fetchFrequencyHours},
                )
                fetch_domain_list(row.id)
    finally:
        db.close()


def _schedule_check() -> None:
    if _is_fetcher_enabled():
        _sync_schedule()
        _sync_domain_schedule()
        _run_catchup_fetches()
        _run_domain_catchup_fetches()
    else:
        # Pause all jobs when fetcher is disabled
        for iplist_id, job_id in list(_scheduled_ids.items()):
            _scheduler.remove_job(job_id)
            del _scheduled_ids[iplist_id]
        for domain_list_id, job_id in list(_domain_scheduled_ids.items()):
            _scheduler.remove_job(job_id)
            del _domain_scheduled_ids[domain_list_id]


def run() -> None:
    """Entry point for the fetcher container."""
    configure_logging()
    log.info("Fetcher service starting")
    Path(RAWIPLISTS_DIR).mkdir(parents=True, exist_ok=True)

    # Apply current schedule immediately at startup, without waiting 60s.
    _schedule_check()

    # Check schedule every 60 seconds
    _scheduler.add_job(_schedule_check, "interval", seconds=60, id="schedule_check")
    _scheduler.start()

    log.info("Fetcher scheduler running")
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        _scheduler.shutdown()
        log.info("Fetcher service stopped")


if __name__ == "__main__":
    run()
