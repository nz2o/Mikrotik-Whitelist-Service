"""Internal API endpoints — called by the UI to trigger fetches and applies."""

import threading

from fastapi import APIRouter, HTTPException, Query

from app.services import applicator as applicator_svc
from app.services import fetcher as fetcher_svc

router = APIRouter(tags=["internal"])


def _run_bg(fn, *args):
    """Run a blocking service function in a background thread."""
    t = threading.Thread(target=fn, args=args, daemon=True)
    t.start()


@router.post("/fetch/all")
def trigger_fetch_all():
    """Trigger an immediate fetch of all active iplists."""
    _run_bg(fetcher_svc.fetch_all)
    return {"status": "triggered", "target": "all"}


@router.post("/fetch/{iplist_id}")
def trigger_fetch_one(iplist_id: int):
    """Trigger an immediate fetch of a specific iplist."""
    _run_bg(fetcher_svc.fetch_list, iplist_id)
    return {"status": "triggered", "iplistsId": iplist_id}


@router.post("/fetch-domains/all")
def trigger_domain_fetch_all():
    """Trigger an immediate fetch of all active domain lists."""
    _run_bg(fetcher_svc.fetch_all_domain_lists)
    return {"status": "triggered", "target": "all-domain-lists"}


@router.post("/fetch-domains/{domain_list_id}")
def trigger_domain_fetch_one(domain_list_id: int):
    """Trigger an immediate fetch of a specific domain list."""
    started = fetcher_svc.trigger_domain_fetch_async(domain_list_id)
    return {
        "status": "triggered" if started else "already-running",
        "domainListsId": domain_list_id,
    }


@router.get("/fetch-domains/{domain_list_id}/status")
def get_domain_fetch_status(domain_list_id: int):
    """Return the in-process status for a manually triggered domain fetch."""
    status = fetcher_svc.get_domain_fetch_status(domain_list_id)
    if not status:
        return {
            "domainListsId": domain_list_id,
            "active": False,
            "status": "idle",
        }
    return status


@router.post("/apply/all")
def trigger_apply_all():
    """Trigger an immediate apply to all active firewalls (bypasses idempotency)."""
    _run_bg(applicator_svc.apply_all, True)
    return {"status": "triggered", "target": "all"}


@router.post("/apply/{firewall_id}")
def trigger_apply_one(
    firewall_id: int,
    override_in_progress: bool = Query(False, alias="overrideInProgress"),
):
    """Trigger an immediate apply to a specific firewall (bypasses idempotency)."""
    started = applicator_svc.trigger_apply_async(
        firewall_id,
        True,
        override_in_progress=override_in_progress,
    )
    return {
        "status": "triggered" if started else "already-running",
        "firewallsId": firewall_id,
        "overrideInProgress": override_in_progress,
    }


@router.get("/apply/active")
def get_active_applies():
    """Return status dicts for all firewalls currently being applied."""
    return {"active": applicator_svc.get_all_active_applies()}


@router.get("/apply/{firewall_id}/status")
def get_apply_status(firewall_id: int):
    """Return the in-process status for a manual firewall apply."""
    status = applicator_svc.get_apply_status(firewall_id)
    if not status:
        return {
            "firewallsId": firewall_id,
            "active": False,
            "status": "idle",
        }
    return status
