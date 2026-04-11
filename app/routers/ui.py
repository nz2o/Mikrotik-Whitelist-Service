"""UI router — serves all HTML pages."""

import ipaddress
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.crypto import encrypt_secret
from app.database import get_db
from app.services import applicator as applicator_svc
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

LIST_TYPE_OPTIONS = IpList.TYPE_OPTIONS
LIST_TYPE_LABELS = {code: label for code, label in LIST_TYPE_OPTIONS}
LIST_TYPE_KIND_MAP = {
    IpList.TYPE_ALLOW: "allow",
    IpList.TYPE_DENY: "deny",
    IpList.TYPE_LOG: "log",
    IpList.TYPE_OUTBOUND_DENY: "outbound-deny",
    IpList.TYPE_ALL_DENY: "all-deny",
}
KIND_TO_TYPE = {v: k for k, v in LIST_TYPE_KIND_MAP.items()}
KIND_TO_TYPE.update({"whitelist": IpList.TYPE_ALLOW, "blacklist": IpList.TYPE_DENY})


def _normalize_list_type(value: int) -> int:
    return value if value in LIST_TYPE_LABELS else IpList.TYPE_ALLOW


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


def _text_export_response(content: str, filename: str, download: int) -> PlainTextResponse:
    response = PlainTextResponse(content)
    if download == 1:
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def _normalize_ipv4_cidr(value: str) -> str:
    network = ipaddress.IPv4Network(value.strip(), strict=False)
    return str(network)


def _parse_bulk_ipv4_lines(raw_text: str) -> tuple[list[str], int]:
    parsed: list[str] = []
    invalid_count = 0
    for line in raw_text.splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#") or candidate.startswith(";"):
            continue
        candidate = candidate.split("#", 1)[0].split(";", 1)[0].strip()
        if not candidate:
            continue
        try:
            parsed.append(_normalize_ipv4_cidr(candidate))
        except ValueError:
            invalid_count += 1
    return parsed, invalid_count


def _get_manual_list_or_404(db: Session, iplist_id: int) -> IpList:
    row = db.query(IpList).filter(IpList.id == iplist_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="IP list not found")
    if row.flagUserDefined != 1:
        raise HTTPException(status_code=400, detail="Only user-defined lists can be edited manually")
    return row


def _get_iplist_or_404(db: Session, iplist_id: int) -> IpList:
    row = db.query(IpList).filter(IpList.id == iplist_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="IP list not found")
    return row


def _parse_search_target(raw_value: str) -> tuple[str, str]:
    value = (raw_value or "").strip()
    if not value:
        raise ValueError("Enter an IPv4 address or CIDR to search")
    try:
        if "/" in value:
            return "cidr", str(ipaddress.IPv4Network(value, strict=False))
        return "ip", str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise ValueError("Enter a valid IPv4 address or CIDR") from exc
    except ipaddress.NetmaskValueError as exc:
        raise ValueError("Enter a valid IPv4 address or CIDR") from exc


def _search_iplists(db: Session, raw_value: str) -> tuple[str, str, list[dict[str, object]]]:
    search_kind, normalized_value = _parse_search_target(raw_value)

    if search_kind == "ip":
        rows = db.execute(
            text(
                """
                SELECT
                    il.id AS iplist_id,
                    il."flagUserDefined" AS iplist_flag_user_defined,
                    il."flagBlacklist" AS iplist_list_type,
                    il."flagInactive" AS iplist_flag_inactive,
                    il.description AS iplist_description,
                    il.comment AS iplist_comment,
                    il.url AS iplist_url,
                    ia.id AS address_id,
                    ia."ipAddress" AS matched_address,
                    ia.description AS address_description,
                    ia.comment AS address_comment,
                    ia."flagInactive" AS address_flag_inactive,
                    CASE
                        WHEN CAST(ia."ipAddress" AS cidr) = CAST(:exact_network AS cidr) THEN 'exact'
                        ELSE 'contains-ip'
                    END AS match_type,
                    masklen(CAST(ia."ipAddress" AS cidr)) AS prefix_length
                FROM iplist."ipAddresses" ia
                JOIN iplist.iplists il ON il.id = ia."iplistsId"
                WHERE CAST(ia."ipAddress" AS cidr) >>= CAST(:query_ip AS inet)
                ORDER BY
                    CASE
                        WHEN CAST(ia."ipAddress" AS cidr) = CAST(:exact_network AS cidr) THEN 0
                        ELSE 1
                    END,
                    masklen(CAST(ia."ipAddress" AS cidr)) DESC,
                    il.id,
                    ia.id
                """
            ),
            {
                "query_ip": normalized_value,
                "exact_network": f"{normalized_value}/32",
            },
        ).mappings()
    else:
        rows = db.execute(
            text(
                """
                SELECT
                    il.id AS iplist_id,
                    il."flagUserDefined" AS iplist_flag_user_defined,
                    il."flagBlacklist" AS iplist_list_type,
                    il."flagInactive" AS iplist_flag_inactive,
                    il.description AS iplist_description,
                    il.comment AS iplist_comment,
                    il.url AS iplist_url,
                    ia.id AS address_id,
                    ia."ipAddress" AS matched_address,
                    ia.description AS address_description,
                    ia.comment AS address_comment,
                    ia."flagInactive" AS address_flag_inactive,
                    CASE
                        WHEN CAST(ia."ipAddress" AS cidr) = CAST(:query_cidr AS cidr) THEN 'exact'
                        ELSE 'contains-cidr'
                    END AS match_type,
                    masklen(CAST(ia."ipAddress" AS cidr)) AS prefix_length
                FROM iplist."ipAddresses" ia
                JOIN iplist.iplists il ON il.id = ia."iplistsId"
                WHERE CAST(ia."ipAddress" AS cidr) >>= CAST(:query_cidr AS cidr)
                ORDER BY
                    CASE
                        WHEN CAST(ia."ipAddress" AS cidr) = CAST(:query_cidr AS cidr) THEN 0
                        ELSE 1
                    END,
                    masklen(CAST(ia."ipAddress" AS cidr)) DESC,
                    il.id,
                    ia.id
                """
            ),
            {"query_cidr": normalized_value},
        ).mappings()

    return search_kind, normalized_value, [dict(row) for row in rows]


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
        },
    )


@router.post("/configuration", response_class=HTMLResponse)
def save_configuration(
    request: Request,
    fetcherEnabled: str = Form("0"),
    applicatorEnabled: str = Form("0"),
    db: Session = Depends(get_db),
):
    _set_config(db, "fetcherEnabled", fetcherEnabled)
    _set_config(db, "applicatorEnabled", applicatorEnabled)
    return RedirectResponse("/configuration?saved=1", status_code=303)


# ---------------------------------------------------------------------------
# IP Lists page
# ---------------------------------------------------------------------------


@router.get("/exports", response_class=HTMLResponse)
def page_exports(request: Request):
    export_types = [
        {
            "code": code,
            "label": label,
            "kind": LIST_TYPE_KIND_MAP[code],
        }
        for code, label in LIST_TYPE_OPTIONS
    ]
    return templates.TemplateResponse(
        request,
        "exports.html",
        {"export_types": export_types},
    )


@router.get("/export/combined/{kind}/{fmt}", response_class=PlainTextResponse)
def export_combined(kind: str, fmt: str, download: int = 0):
    if kind not in KIND_TO_TYPE:
        raise HTTPException(status_code=400, detail="unsupported kind")
    if fmt not in {"rsc", "plain"}:
        raise HTTPException(status_code=400, detail="fmt must be rsc or plain")

    if fmt == "rsc":
        payload = applicator_svc.build_combined_rsc(kind)
        filename = f"combined-{kind}.rsc"
    else:
        payload = applicator_svc.build_combined_plain(kind)
        filename = f"combined-{kind}.txt"

    return _text_export_response(payload, filename, download)


@router.get("/export/iplist/{iplist_id}/{fmt}", response_class=PlainTextResponse)
def export_iplist(iplist_id: int, fmt: str, download: int = 0, db: Session = Depends(get_db)):
    if fmt not in {"rsc", "plain"}:
        raise HTTPException(status_code=400, detail="fmt must be rsc or plain")
    iplist = db.query(IpList).filter(IpList.id == iplist_id).first()
    if not iplist:
        raise HTTPException(status_code=404, detail="IP list not found")

    if fmt == "rsc":
        payload = applicator_svc.build_iplist_rsc(iplist_id)
        filename = f"iplist-{iplist_id}.rsc"
    else:
        payload = applicator_svc.build_iplist_plain(iplist_id)
        filename = f"iplist-{iplist_id}.txt"

    return _text_export_response(payload, filename, download)


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

    search_query = (request.query_params.get("search") or "").strip()
    search_kind = None
    search_error = None
    search_results: list[dict[str, object]] = []
    normalized_search = ""

    if search_query:
        try:
            search_kind, normalized_search, search_results = _search_iplists(db, search_query)
        except ValueError as exc:
            search_error = str(exc)

    return templates.TemplateResponse(
        request,
        "iplists.html",
        {
            "iplists": iplists,
            "last_jobs": last_jobs,
            "list_type_options": LIST_TYPE_OPTIONS,
            "list_type_labels": LIST_TYPE_LABELS,
            "list_type_kind_map": LIST_TYPE_KIND_MAP,
            "search_query": search_query,
            "search_kind": search_kind,
            "search_error": search_error,
            "search_results": search_results,
            "normalized_search": normalized_search,
        },
    )


@router.post("/iplists/new")
def create_iplist(
    url: str = Form(""),
    flagUserDefined: int = Form(0),
    listType: int = Form(IpList.TYPE_ALLOW),
    description: str = Form(""),
    comment: str = Form(""),
    fetchFrequencyHours: int = Form(0),
    flagInactive: int = Form(0),
    ttlDays: Optional[int] = Form(None),
    db: Session = Depends(get_db),
):
    normalized_url = (url or "").strip() or None
    if flagUserDefined != 1 and not normalized_url:
        raise HTTPException(status_code=400, detail="URL is required for downloaded lists")
    row = IpList(
        url=normalized_url,
        flagUserDefined=flagUserDefined,
        flagBlacklist=_normalize_list_type(listType),
        description=description or None,
        comment=comment or None,
        fetchFrequencyHours=0 if flagUserDefined == 1 else fetchFrequencyHours,
        flagInactive=flagInactive,
        ttlDays=ttlDays if ttlDays and ttlDays >= 1 else None,
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
    listType: int = Form(IpList.TYPE_ALLOW),
    description: str = Form(""),
    comment: str = Form(""),
    fetchFrequencyHours: int = Form(0),
    flagInactive: int = Form(0),
    ttlDays: Optional[int] = Form(None),
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
    row.flagBlacklist = _normalize_list_type(listType)
    row.description = description or None
    row.comment = comment or None
    row.fetchFrequencyHours = 0 if flagUserDefined == 1 else fetchFrequencyHours
    row.flagInactive = flagInactive
    row.ttlDays = ttlDays if ttlDays and ttlDays >= 1 else None
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


@router.post("/iplists/{iplist_id}/addresses/{address_id}/quick-edit")
def quick_edit_search_entry(
    iplist_id: int,
    address_id: int,
    list_type: int = Form(IpList.TYPE_ALLOW),
    iplist_flag_inactive: int = Form(0),
    address_flag_inactive: int = Form(0),
    redirect_to: str = Form("/iplists"),
    db: Session = Depends(get_db),
):
    """Quick-edit the list type + inactive flags from the search results page."""
    iplist = db.query(IpList).filter(IpList.id == iplist_id).first()
    if not iplist:
        raise HTTPException(status_code=404, detail="IP list not found")
    address = (
        db.query(IpAddress)
        .filter(IpAddress.id == address_id, IpAddress.iplistsId == iplist_id)
        .first()
    )
    if not address:
        raise HTTPException(status_code=404, detail="IP address entry not found")

    iplist.flagBlacklist = _normalize_list_type(list_type)
    iplist.flagInactive = iplist_flag_inactive
    address.flagInactive = address_flag_inactive
    db.commit()
    return RedirectResponse(redirect_to, status_code=303)


@router.get("/iplists/{iplist_id}/addresses", response_class=HTMLResponse)
def page_ipaddresses(iplist_id: int, request: Request, db: Session = Depends(get_db)):
    iplist = _get_iplist_or_404(db, iplist_id)
    addresses = (
        db.query(IpAddress)
        .filter(IpAddress.iplistsId == iplist_id)
        .order_by(IpAddress.id)
        .all()
    )
    return templates.TemplateResponse(
        request,
        "ipaddresses.html",
        {
            "iplist": iplist,
            "addresses": addresses,
            "manual_mode": iplist.flagUserDefined == 1,
        },
    )


@router.post("/iplists/{iplist_id}/addresses/new")
def create_ipaddress(
    iplist_id: int,
    ipAddress: str = Form(...),
    description: str = Form(""),
    comment: str = Form(""),
    flagInactive: int = Form(0),
    db: Session = Depends(get_db),
):
    _get_manual_list_or_404(db, iplist_id)
    normalized = _normalize_ipv4_cidr(ipAddress)
    row = IpAddress(
        ipAddress=normalized,
        description=description or None,
        comment=comment or None,
        iplistsId=iplist_id,
        flagInactive=flagInactive,
    )
    db.add(row)
    db.commit()
    return RedirectResponse(f"/iplists/{iplist_id}/addresses", status_code=303)


@router.post("/iplists/{iplist_id}/addresses/bulk")
async def bulk_import_ipaddresses(
    iplist_id: int,
    bulkText: str = Form(""),
    uploadFile: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
):
    _get_manual_list_or_404(db, iplist_id)

    chunks: list[str] = []
    if bulkText.strip():
        chunks.append(bulkText)

    if uploadFile and uploadFile.filename:
        uploaded = await uploadFile.read()
        decoded = uploaded.decode("utf-8", errors="replace")
        if decoded.strip():
            chunks.append(decoded)

    if not chunks:
        return RedirectResponse(
            f"/iplists/{iplist_id}/addresses?bulk_error=1",
            status_code=303,
        )

    normalized_entries: list[str] = []
    invalid_count = 0
    for chunk in chunks:
        parsed, invalid = _parse_bulk_ipv4_lines(chunk)
        normalized_entries.extend(parsed)
        invalid_count += invalid

    unique_entries: list[str] = []
    seen: set[str] = set()
    for entry in normalized_entries:
        if entry not in seen:
            seen.add(entry)
            unique_entries.append(entry)

    existing = {
        row.ipAddress
        for row in db.query(IpAddress.ipAddress)
        .filter(IpAddress.iplistsId == iplist_id)
        .all()
    }

    to_insert = [entry for entry in unique_entries if entry not in existing]
    duplicate_count = len(unique_entries) - len(to_insert)

    if to_insert:
        db.bulk_insert_mappings(
            IpAddress,
            [{"ipAddress": entry, "iplistsId": iplist_id} for entry in to_insert],
        )
        db.commit()

    return RedirectResponse(
        f"/iplists/{iplist_id}/addresses?bulk_added={len(to_insert)}&bulk_invalid={invalid_count}&bulk_duplicate={duplicate_count}",
        status_code=303,
    )


@router.post("/iplists/{iplist_id}/addresses/{address_id}/save")
def save_ipaddress(
    iplist_id: int,
    address_id: int,
    ipAddress: str = Form(...),
    description: str = Form(""),
    comment: str = Form(""),
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
    row.description = description or None
    row.comment = comment or None
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
