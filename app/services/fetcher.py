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
import time
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
from app.models import FetchError, FetchJob, IpAddress, IpList

log = logging.getLogger(__name__)


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


def _schedule_check() -> None:
    if _is_fetcher_enabled():
        _sync_schedule()
    else:
        # Pause all jobs when fetcher is disabled
        for iplist_id, job_id in list(_scheduled_ids.items()):
            _scheduler.remove_job(job_id)
            del _scheduled_ids[iplist_id]


def run() -> None:
    """Entry point for the fetcher container."""
    configure_logging()
    log.info("Fetcher service starting")
    Path(RAWIPLISTS_DIR).mkdir(parents=True, exist_ok=True)

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
