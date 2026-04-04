"""Internal API endpoints — called by the UI to trigger fetches and applies."""

import threading

from fastapi import APIRouter, HTTPException

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


@router.post("/apply/all")
def trigger_apply_all():
    """Trigger an immediate apply to all active firewalls (bypasses idempotency)."""
    _run_bg(applicator_svc.apply_all, True)
    return {"status": "triggered", "target": "all"}


@router.post("/apply/{firewall_id}")
def trigger_apply_one(firewall_id: int):
    """Trigger an immediate apply to a specific firewall (bypasses idempotency)."""
    _run_bg(applicator_svc.apply_firewall, firewall_id, True)
    return {"status": "triggered", "firewallsId": firewall_id}
