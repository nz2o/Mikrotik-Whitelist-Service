"""UI router — serves all HTML pages."""

import ipaddress

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.crypto import encrypt_secret
from app.database import get_db
from app.models import (
    ApplyHistory,
    Configuration,
    FetchError,
    FetchJob,
    Firewall,
    FirewallType,
    IpAddress,
    IpList,
)

router = APIRouter(tags=["ui"])
templates = Jinja2Templates(directory="app/templates")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _get_config(db: Session, key: str) -> str:
    row = db.query(Configuration).filter(Configuration.configurationItem == key).first()
    return (row.configurationItemValue or "") if row else ""


def _set_config(db: Session, key: str, value: str) -> None:
    row = db.query(Configuration).filter(Configuration.configurationItem == key).first()
    if row:
        row.configurationItemValue = value
        db.commit()


def _normalize_ipv4_cidr(value: str) -> str:
    network = ipaddress.IPv4Network(value.strip(), strict=False)
    return str(network)


def _get_manual_list_or_404(db: Session, iplist_id: int) -> IpList:
    row = db.query(IpList).filter(IpList.id == iplist_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="IP list not found")
    if row.flagUserDefined != 1:
        raise HTTPException(status_code=400, detail="Only user-defined lists can be edited manually")
    return row


# ---------------------------------------------------------------------------
# Configuration page
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
@router.get("/configuration", response_class=HTMLResponse)
def page_configuration(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        request,
        "configuration.html",
        {
            "fetcherEnabled": _get_config(db, "fetcherEnabled"),
            "applicatorEnabled": _get_config(db, "applicatorEnabled"),
            "applicatorTTLDays": _get_config(db, "applicatorTTLDays"),
        },
    )


@router.post("/configuration", response_class=HTMLResponse)
def save_configuration(
    request: Request,
    fetcherEnabled: str = Form("0"),
    applicatorEnabled: str = Form("0"),
    applicatorTTLDays: str = Form("7"),
    db: Session = Depends(get_db),
):
    _set_config(db, "fetcherEnabled", fetcherEnabled)
    _set_config(db, "applicatorEnabled", applicatorEnabled)
    _set_config(db, "applicatorTTLDays", applicatorTTLDays)
    return RedirectResponse("/configuration?saved=1", status_code=303)


# ---------------------------------------------------------------------------
# IP Lists page
# ---------------------------------------------------------------------------


@router.get("/iplists", response_class=HTMLResponse)
def page_iplists(request: Request, db: Session = Depends(get_db)):
    iplists = db.query(IpList).order_by(IpList.id).all()

    # Attach last fetch job status to each row
    last_jobs: dict[int, FetchJob] = {}
    for iplist in iplists:
        job = (
            db.query(FetchJob)
            .filter(FetchJob.iplistsId == iplist.id)
            .order_by(FetchJob.startedAt.desc())
            .first()
        )
        last_jobs[iplist.id] = job

    return templates.TemplateResponse(
        request,
        "iplists.html",
        {"iplists": iplists, "last_jobs": last_jobs},
    )


@router.post("/iplists/new")
def create_iplist(
    url: str = Form(""),
    flagUserDefined: int = Form(0),
    flagBlacklist: int = Form(0),
    description: str = Form(""),
    comment: str = Form(""),
    fetchFrequencyHours: int = Form(0),
    flagInactive: int = Form(0),
    db: Session = Depends(get_db),
):
    normalized_url = (url or "").strip() or None
    if flagUserDefined != 1 and not normalized_url:
        raise HTTPException(status_code=400, detail="URL is required for downloaded lists")
    row = IpList(
        url=normalized_url,
        flagUserDefined=flagUserDefined,
        flagBlacklist=flagBlacklist,
        description=description or None,
        comment=comment or None,
        fetchFrequencyHours=0 if flagUserDefined == 1 else fetchFrequencyHours,
        flagInactive=flagInactive,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    if row.flagUserDefined != 1:
        # Trigger initial fetch in background for downloaded lists only
        import threading
        from app.services import fetcher as fetcher_svc

        threading.Thread(target=fetcher_svc.fetch_list, args=[row.id], daemon=True).start()
    return RedirectResponse("/iplists", status_code=303)


@router.post("/iplists/{iplist_id}/save")
def save_iplist(
    iplist_id: int,
    url: str = Form(""),
    flagUserDefined: int = Form(0),
    flagBlacklist: int = Form(0),
    description: str = Form(""),
    comment: str = Form(""),
    fetchFrequencyHours: int = Form(0),
    flagInactive: int = Form(0),
    db: Session = Depends(get_db),
):
    row = db.query(IpList).filter(IpList.id == iplist_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    normalized_url = (url or "").strip() or None
    if flagUserDefined != 1 and not normalized_url:
        raise HTTPException(status_code=400, detail="URL is required for downloaded lists")
    row.url = normalized_url
    row.flagUserDefined = flagUserDefined
    row.flagBlacklist = flagBlacklist
    row.description = description or None
    row.comment = comment or None
    row.fetchFrequencyHours = 0 if flagUserDefined == 1 else fetchFrequencyHours
    row.flagInactive = flagInactive
    db.commit()
    return RedirectResponse("/iplists", status_code=303)


@router.post("/iplists/{iplist_id}/delete")
def delete_iplist(iplist_id: int, db: Session = Depends(get_db)):
    row = db.query(IpList).filter(IpList.id == iplist_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(row)
    db.commit()
    return RedirectResponse("/iplists", status_code=303)


@router.get("/iplists/{iplist_id}/addresses", response_class=HTMLResponse)
def page_ipaddresses(iplist_id: int, request: Request, db: Session = Depends(get_db)):
    iplist = _get_manual_list_or_404(db, iplist_id)
    addresses = (
        db.query(IpAddress)
        .filter(IpAddress.iplistsId == iplist_id)
        .order_by(IpAddress.id)
        .all()
    )
    return templates.TemplateResponse(
        request,
        "ipaddresses.html",
        {"iplist": iplist, "addresses": addresses},
    )


@router.post("/iplists/{iplist_id}/addresses/new")
def create_ipaddress(
    iplist_id: int,
    ipAddress: str = Form(...),
    comment: str = Form(""),
    flagInactive: int = Form(0),
    db: Session = Depends(get_db),
):
    _get_manual_list_or_404(db, iplist_id)
    normalized = _normalize_ipv4_cidr(ipAddress)
    row = IpAddress(
        ipAddress=normalized,
        iplistsId=iplist_id,
        flagInactive=flagInactive,
    )
    db.add(row)
    db.commit()
    return RedirectResponse(f"/iplists/{iplist_id}/addresses", status_code=303)


@router.post("/iplists/{iplist_id}/addresses/{address_id}/save")
def save_ipaddress(
    iplist_id: int,
    address_id: int,
    ipAddress: str = Form(...),
    flagInactive: int = Form(0),
    db: Session = Depends(get_db),
):
    _get_manual_list_or_404(db, iplist_id)
    row = (
        db.query(IpAddress)
        .filter(IpAddress.id == address_id, IpAddress.iplistsId == iplist_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="IP address entry not found")
    row.ipAddress = _normalize_ipv4_cidr(ipAddress)
    row.flagInactive = flagInactive
    db.commit()
    return RedirectResponse(f"/iplists/{iplist_id}/addresses", status_code=303)


@router.post("/iplists/{iplist_id}/addresses/{address_id}/delete")
def delete_ipaddress(iplist_id: int, address_id: int, db: Session = Depends(get_db)):
    _get_manual_list_or_404(db, iplist_id)
    row = (
        db.query(IpAddress)
        .filter(IpAddress.id == address_id, IpAddress.iplistsId == iplist_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="IP address entry not found")
    db.delete(row)
    db.commit()
    return RedirectResponse(f"/iplists/{iplist_id}/addresses", status_code=303)


# ---------------------------------------------------------------------------
# Firewalls page
# ---------------------------------------------------------------------------


@router.get("/firewalls", response_class=HTMLResponse)
def page_firewalls(request: Request, db: Session = Depends(get_db)):
    firewalls = db.query(Firewall).order_by(Firewall.id).all()
    fw_types = db.query(FirewallType).filter(FirewallType.flagInactive == 0).all()

    last_applies: dict[int, ApplyHistory] = {}
    for fw in firewalls:
        apply = (
            db.query(ApplyHistory)
            .filter(ApplyHistory.firewallsId == fw.id)
            .order_by(ApplyHistory.startedAt.desc())
            .first()
        )
        last_applies[fw.id] = apply

    return templates.TemplateResponse(
        request,
        "firewalls.html",
        {
            "firewalls": firewalls,
            "fw_types": fw_types,
            "last_applies": last_applies,
        },
    )


@router.post("/firewalls/new")
def create_firewall(
    firewallAddress: str = Form(...),
    firewallPort: int = Form(22),
    firewallUser: str = Form(...),
    firewallSecret: str = Form(...),
    firewallTypeId: int = Form(...),
    applyFrequencyHours: int = Form(0),
    flagInactive: int = Form(0),
    db: Session = Depends(get_db),
):
    encrypted = encrypt_secret(firewallSecret)
    row = Firewall(
        firewallAddress=firewallAddress,
        firewallPort=firewallPort,
        firewallUser=firewallUser,
        firewallSecret=encrypted,
        firewallTypeId=firewallTypeId,
        applyFrequencyHours=applyFrequencyHours,
        flagInactive=flagInactive,
    )
    db.add(row)
    db.commit()
    return RedirectResponse("/firewalls", status_code=303)


@router.post("/firewalls/{fw_id}/save")
def save_firewall(
    fw_id: int,
    firewallAddress: str = Form(...),
    firewallPort: int = Form(22),
    firewallUser: str = Form(...),
    firewallSecret: str = Form(""),
    firewallTypeId: int = Form(...),
    applyFrequencyHours: int = Form(0),
    flagInactive: int = Form(0),
    db: Session = Depends(get_db),
):
    row = db.query(Firewall).filter(Firewall.id == fw_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    row.firewallAddress = firewallAddress
    row.firewallPort = firewallPort
    row.firewallUser = firewallUser
    row.firewallTypeId = firewallTypeId
    row.applyFrequencyHours = applyFrequencyHours
    row.flagInactive = flagInactive
    # Only re-encrypt if a new secret was provided
    if firewallSecret.strip():
        row.firewallSecret = encrypt_secret(firewallSecret)
    db.commit()
    return RedirectResponse("/firewalls", status_code=303)


@router.post("/firewalls/{fw_id}/delete")
def delete_firewall(fw_id: int, db: Session = Depends(get_db)):
    row = db.query(Firewall).filter(Firewall.id == fw_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(row)
    db.commit()
    return RedirectResponse("/firewalls", status_code=303)


# ---------------------------------------------------------------------------
# Status & Logs page
# ---------------------------------------------------------------------------


@router.get("/status", response_class=HTMLResponse)
def page_status(
    request: Request,
    iplist_filter: int = None,
    fw_filter: int = None,
    fetch_status_filter: str = None,
    apply_status_filter: str = None,
    db: Session = Depends(get_db),
):
    fetch_q = db.query(FetchJob).order_by(FetchJob.startedAt.desc())
    if iplist_filter:
        fetch_q = fetch_q.filter(FetchJob.iplistsId == iplist_filter)
    if fetch_status_filter:
        fetch_q = fetch_q.filter(FetchJob.status == fetch_status_filter)
    fetch_jobs = fetch_q.limit(100).all()

    apply_q = db.query(ApplyHistory).order_by(ApplyHistory.startedAt.desc())
    if fw_filter:
        apply_q = apply_q.filter(ApplyHistory.firewallsId == fw_filter)
    if apply_status_filter:
        apply_q = apply_q.filter(ApplyHistory.status == apply_status_filter)
    apply_history = apply_q.limit(100).all()

    iplists = db.query(IpList.id, IpList.description).order_by(IpList.id).all()
    firewalls = db.query(Firewall.id, Firewall.firewallAddress).order_by(Firewall.id).all()

    return templates.TemplateResponse(
        request,
        "status.html",
        {
            "fetch_jobs": fetch_jobs,
            "apply_history": apply_history,
            "iplists": iplists,
            "firewalls": firewalls,
            "iplist_filter": iplist_filter,
            "fw_filter": fw_filter,
            "fetch_status_filter": fetch_status_filter,
            "apply_status_filter": apply_status_filter,
        },
    )
