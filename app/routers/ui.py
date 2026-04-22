"""UI router — serves all HTML pages."""

import ipaddress
import re
import socket
from urllib.parse import urlencode
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
    ApplyError,
    ApplyHistory,
    Configuration,
    Domain,
    DomainList,
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
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)


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


def _coerce_optional_int(value: str | None) -> int | None:
    candidate = (value or "").strip()
    if not candidate:
        return None
    try:
        return int(candidate)
    except ValueError:
        return None


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


def _normalize_domain_name(value: str) -> str:
    candidate = (value or "").strip().split("#", 1)[0].split(";", 1)[0].strip().lower().rstrip(".")
    if not candidate or not _DOMAIN_RE.match(candidate):
        raise ValueError("Enter a valid exact domain name")
    return candidate


def _parse_bulk_domain_lines(raw_text: str) -> tuple[list[str], int]:
    parsed: list[str] = []
    invalid_count = 0
    for line in raw_text.splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#") or candidate.startswith(";"):
            continue
        try:
            parsed.append(_normalize_domain_name(candidate))
        except ValueError:
            invalid_count += 1
    return parsed, invalid_count


def _resolve_domain_ipv4(domain: str) -> list[str]:
    results: set[str] = set()
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        for info in infos:
            results.add(str(ipaddress.IPv4Address(info[4][0])))
    except Exception:
        return []
    return sorted(results)


def _manual_domain_redirect(domain_list_id: int, **params: object) -> RedirectResponse:
    query = urlencode({k: v for k, v in params.items() if v is not None})
    target = f"/domainlists/{domain_list_id}/domains"
    if query:
        target = f"{target}?{query}"
    return RedirectResponse(target, status_code=303)


def _get_manual_domain_list_or_404(db: Session, domain_list_id: int) -> DomainList:
    row = db.query(DomainList).filter(DomainList.id == domain_list_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Domain list not found")
    if row.flagUserDefined != 1:
        raise HTTPException(status_code=400, detail="Only user-defined domain lists can be edited manually")
    return row


def _get_domain_list_or_404(db: Session, domain_list_id: int) -> DomainList:
    row = db.query(DomainList).filter(DomainList.id == domain_list_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Domain list not found")
    return row


def _build_manual_domain_entries(rows: list[Domain]) -> list[dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {}
    for row in rows:
        entry = grouped.get(row.domainName)
        if entry is None:
            entry = {
                "id": row.id,
                "domainName": row.domainName,
                "ipAddresses": [],
                "flagInactive": row.flagInactive,
                "createDate": row.createDate,
                "updateDate": row.updateDate,
            }
            grouped[row.domainName] = entry
        entry["ipAddresses"].append(row.ipAddress)
        entry["flagInactive"] = max(int(entry["flagInactive"]), row.flagInactive)
        if row.createDate < entry["createDate"]:
            entry["createDate"] = row.createDate
        if row.updateDate > entry["updateDate"]:
            entry["updateDate"] = row.updateDate

    entries = list(grouped.values())
    for entry in entries:
        entry["ipAddresses"] = sorted(set(entry["ipAddresses"]))
    entries.sort(key=lambda item: str(item["domainName"]))
    return entries


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


@router.get("/domainlists", response_class=HTMLResponse)
def page_domainlists(request: Request, db: Session = Depends(get_db)):
    domain_lists = db.query(DomainList).order_by(DomainList.id).all()
    resolved_counts: dict[int, int] = {}
    for row in domain_lists:
        resolved_counts[row.id] = (
            db.query(Domain.id)
            .filter(Domain.domainListsId == row.id, Domain.flagInactive == 0)
            .count()
        )

    return templates.TemplateResponse(
        request,
        "domainlists.html",
        {
            "domain_lists": domain_lists,
            "resolved_counts": resolved_counts,
            "list_type_options": LIST_TYPE_OPTIONS,
            "list_type_labels": LIST_TYPE_LABELS,
            "list_type_kind_map": LIST_TYPE_KIND_MAP,
        },
    )


@router.post("/domainlists/new")
def create_domain_list(
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

    row = DomainList(
        url=normalized_url,
        flagUserDefined=flagUserDefined,
        listType=_normalize_list_type(listType),
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
        from app.services import fetcher as fetcher_svc

        fetcher_svc.trigger_domain_fetch_async(row.id)
        return RedirectResponse(f"/domainlists?fetchStarted={row.id}", status_code=303)
    return RedirectResponse("/domainlists", status_code=303)


@router.post("/domainlists/{domain_list_id}/save")
def save_domain_list(
    domain_list_id: int,
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
    row = db.query(DomainList).filter(DomainList.id == domain_list_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Domain list not found")

    normalized_url = (url or "").strip() or None
    if flagUserDefined != 1 and not normalized_url:
        raise HTTPException(status_code=400, detail="URL is required for downloaded lists")

    row.url = normalized_url
    row.flagUserDefined = flagUserDefined
    row.listType = _normalize_list_type(listType)
    row.description = description or None
    row.comment = comment or None
    row.fetchFrequencyHours = 0 if flagUserDefined == 1 else fetchFrequencyHours
    row.flagInactive = flagInactive
    row.ttlDays = ttlDays if ttlDays and ttlDays >= 1 else None
    db.commit()
    if row.flagUserDefined != 1:
        from app.services import fetcher as fetcher_svc

        fetcher_svc.trigger_domain_fetch_async(row.id)
        return RedirectResponse(f"/domainlists?fetchStarted={row.id}", status_code=303)
    return RedirectResponse("/domainlists", status_code=303)


@router.post("/domainlists/{domain_list_id}/delete")
def delete_domain_list(domain_list_id: int, db: Session = Depends(get_db)):
    row = db.query(DomainList).filter(DomainList.id == domain_list_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Domain list not found")
    db.delete(row)
    db.commit()
    return RedirectResponse("/domainlists", status_code=303)


@router.get("/domainlists/{domain_list_id}/domains", response_class=HTMLResponse)
def page_domains(domain_list_id: int, request: Request, db: Session = Depends(get_db)):
    domain_list = _get_domain_list_or_404(db, domain_list_id)
    domain_rows = (
        db.query(Domain)
        .filter(Domain.domainListsId == domain_list_id)
        .order_by(Domain.domainName, Domain.ipAddress, Domain.id)
        .all()
    )

    return templates.TemplateResponse(
        request,
        "domains.html",
        {
            "domain_list": domain_list,
            "domain_rows": domain_rows,
            "manual_entries": _build_manual_domain_entries(domain_rows)
            if domain_list.flagUserDefined == 1
            else [],
            "manual_mode": domain_list.flagUserDefined == 1,
        },
    )


@router.post("/domainlists/{domain_list_id}/domains/new")
def create_manual_domain(
    domain_list_id: int,
    domainName: str = Form(...),
    flagInactive: int = Form(0),
    db: Session = Depends(get_db),
):
    _get_manual_domain_list_or_404(db, domain_list_id)
    try:
        normalized = _normalize_domain_name(domainName)
    except ValueError as exc:
        return _manual_domain_redirect(domain_list_id, error=str(exc))

    existing = (
        db.query(Domain.id)
        .filter(Domain.domainListsId == domain_list_id, Domain.domainName == normalized)
        .first()
    )
    if existing:
        return _manual_domain_redirect(domain_list_id, error="Domain already exists in this list")

    resolved_ips = _resolve_domain_ipv4(normalized)
    if not resolved_ips:
        return _manual_domain_redirect(
            domain_list_id,
            error="Domain did not resolve to any IPv4 A records",
        )

    db.bulk_insert_mappings(
        Domain,
        [
            {
                "domainName": normalized,
                "ipAddress": ip_address,
                "domainListsId": domain_list_id,
                "flagInactive": flagInactive,
            }
            for ip_address in resolved_ips
        ],
    )
    db.commit()
    return _manual_domain_redirect(domain_list_id, added=1)


@router.post("/domainlists/{domain_list_id}/domains/bulk")
async def bulk_import_manual_domains(
    domain_list_id: int,
    bulkText: str = Form(""),
    uploadFile: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
):
    _get_manual_domain_list_or_404(db, domain_list_id)

    chunks: list[str] = []
    if bulkText.strip():
        chunks.append(bulkText)

    if uploadFile and uploadFile.filename:
        uploaded = await uploadFile.read()
        decoded = uploaded.decode("utf-8", errors="replace")
        if decoded.strip():
            chunks.append(decoded)

    if not chunks:
        return _manual_domain_redirect(domain_list_id, bulk_error=1)

    normalized_entries: list[str] = []
    invalid_count = 0
    for chunk in chunks:
        parsed, invalid = _parse_bulk_domain_lines(chunk)
        normalized_entries.extend(parsed)
        invalid_count += invalid

    unique_entries: list[str] = []
    seen: set[str] = set()
    for entry in normalized_entries:
        if entry not in seen:
            seen.add(entry)
            unique_entries.append(entry)

    existing_domains = {
        row[0]
        for row in db.query(Domain.domainName)
        .filter(Domain.domainListsId == domain_list_id)
        .distinct()
        .all()
    }

    to_insert: list[dict[str, object]] = []
    added_count = 0
    unresolved_count = 0
    duplicate_count = 0
    for domain_name in unique_entries:
        if domain_name in existing_domains:
            duplicate_count += 1
            continue
        resolved_ips = _resolve_domain_ipv4(domain_name)
        if not resolved_ips:
            unresolved_count += 1
            continue
        to_insert.extend(
            {
                "domainName": domain_name,
                "ipAddress": ip_address,
                "domainListsId": domain_list_id,
            }
            for ip_address in resolved_ips
        )
        added_count += 1
        existing_domains.add(domain_name)

    if to_insert:
        db.bulk_insert_mappings(Domain, to_insert)
        db.commit()

    return _manual_domain_redirect(
        domain_list_id,
        bulk_added=added_count,
        bulk_invalid=invalid_count,
        bulk_duplicate=duplicate_count,
        bulk_unresolved=unresolved_count,
    )


@router.post("/domainlists/{domain_list_id}/domains/{entry_id}/save")
def save_manual_domain(
    domain_list_id: int,
    entry_id: int,
    currentDomainName: str = Form(...),
    domainName: str = Form(...),
    flagInactive: int = Form(0),
    db: Session = Depends(get_db),
):
    _get_manual_domain_list_or_404(db, domain_list_id)
    existing_rows = (
        db.query(Domain)
        .filter(Domain.domainListsId == domain_list_id, Domain.domainName == currentDomainName)
        .all()
    )
    if not existing_rows or not any(row.id == entry_id for row in existing_rows):
        raise HTTPException(status_code=404, detail="Manual domain entry not found")

    try:
        normalized = _normalize_domain_name(domainName)
    except ValueError as exc:
        return _manual_domain_redirect(domain_list_id, error=str(exc))

    if normalized != currentDomainName:
        collision = (
            db.query(Domain.id)
            .filter(Domain.domainListsId == domain_list_id, Domain.domainName == normalized)
            .first()
        )
        if collision:
            return _manual_domain_redirect(domain_list_id, error="Domain already exists in this list")

    resolved_ips = _resolve_domain_ipv4(normalized)
    if not resolved_ips:
        return _manual_domain_redirect(
            domain_list_id,
            error="Domain did not resolve to any IPv4 A records",
        )

    db.query(Domain).filter(
        Domain.domainListsId == domain_list_id,
        Domain.domainName == currentDomainName,
    ).delete()
    db.bulk_insert_mappings(
        Domain,
        [
            {
                "domainName": normalized,
                "ipAddress": ip_address,
                "domainListsId": domain_list_id,
                "flagInactive": flagInactive,
            }
            for ip_address in resolved_ips
        ],
    )
    db.commit()
    return _manual_domain_redirect(domain_list_id, saved=1)


@router.post("/domainlists/{domain_list_id}/domains/{entry_id}/delete")
def delete_manual_domain(
    domain_list_id: int,
    entry_id: int,
    currentDomainName: str = Form(...),
    db: Session = Depends(get_db),
):
    _get_manual_domain_list_or_404(db, domain_list_id)
    rows = (
        db.query(Domain)
        .filter(Domain.domainListsId == domain_list_id, Domain.domainName == currentDomainName)
        .all()
    )
    if not rows or not any(row.id == entry_id for row in rows):
        raise HTTPException(status_code=404, detail="Manual domain entry not found")
    for row in rows:
        db.delete(row)
    db.commit()
    return _manual_domain_redirect(domain_list_id, deleted=1)


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


@router.get("/apply-errors", response_class=HTMLResponse)
def page_apply_errors(
    request: Request,
    fw_filter: int = None,
    apply_filter: int = None,
    only_timeouts: int = 0,
    limit: int = 200,
    db: Session = Depends(get_db),
):
    safe_limit = max(50, min(limit, 1000))
    q = db.query(ApplyError).order_by(ApplyError.occurredAt.desc())
    if fw_filter:
        q = q.filter(ApplyError.firewallsId == fw_filter)
    if apply_filter:
        q = q.filter(ApplyError.applyHistoryId == apply_filter)
    if only_timeouts == 1:
        q = q.filter(ApplyError.errorMessage.ilike("%timed out%"))

    apply_errors = q.limit(safe_limit).all()
    firewalls = db.query(Firewall.id, Firewall.firewallAddress).order_by(Firewall.id).all()
    applies = (
        db.query(ApplyHistory.id, ApplyHistory.firewallsId, ApplyHistory.startedAt, ApplyHistory.status)
        .order_by(ApplyHistory.startedAt.desc())
        .limit(500)
        .all()
    )

    return templates.TemplateResponse(
        request,
        "apply_errors.html",
        {
            "apply_errors": apply_errors,
            "firewalls": firewalls,
            "applies": applies,
            "fw_filter": fw_filter,
            "apply_filter": apply_filter,
            "only_timeouts": only_timeouts,
            "limit": safe_limit,
            "purged": request.query_params.get("purged"),
            "message": request.query_params.get("message"),
        },
    )


@router.post("/apply-errors/purge-selected")
def purge_apply_errors_selected(
    error_ids: list[int] = Form(default=[]),
    fw_filter: str = Form(""),
    apply_filter: str = Form(""),
    only_timeouts: str = Form("0"),
    limit: str = Form("200"),
    db: Session = Depends(get_db),
):
    params: dict[str, str] = {}
    if fw_filter.strip():
        params["fw_filter"] = fw_filter.strip()
    if apply_filter.strip():
        params["apply_filter"] = apply_filter.strip()
    if only_timeouts.strip() == "1":
        params["only_timeouts"] = "1"
    if limit.strip():
        params["limit"] = limit.strip()

    if not error_ids:
        params["message"] = "No rows selected"
        target = "/apply-errors"
        if params:
            target = f"{target}?{urlencode(params)}"
        return RedirectResponse(target, status_code=303)

    deleted = (
        db.query(ApplyError)
        .filter(ApplyError.id.in_(error_ids))
        .delete(synchronize_session=False)
    )
    db.commit()

    params["purged"] = str(deleted)
    target = f"/apply-errors?{urlencode(params)}"
    return RedirectResponse(target, status_code=303)


@router.post("/apply-errors/purge-all")
def purge_apply_errors_all(
    fw_filter: str = Form(""),
    apply_filter: str = Form(""),
    only_timeouts: str = Form("0"),
    limit: str = Form("200"),
    filtered_only: str = Form("1"),
    db: Session = Depends(get_db),
):
    fw_id = _coerce_optional_int(fw_filter)
    apply_id = _coerce_optional_int(apply_filter)
    timeout_only = only_timeouts.strip() == "1"

    q = db.query(ApplyError)
    if filtered_only == "1":
        if fw_id:
            q = q.filter(ApplyError.firewallsId == fw_id)
        if apply_id:
            q = q.filter(ApplyError.applyHistoryId == apply_id)
        if timeout_only:
            q = q.filter(ApplyError.errorMessage.ilike("%timed out%"))

    deleted = q.delete(synchronize_session=False)
    db.commit()

    params: dict[str, str] = {
        "purged": str(deleted),
    }
    if filtered_only == "1":
        if fw_id:
            params["fw_filter"] = str(fw_id)
        if apply_id:
            params["apply_filter"] = str(apply_id)
        if timeout_only:
            params["only_timeouts"] = "1"
        if limit.strip():
            params["limit"] = limit.strip()

    return RedirectResponse(f"/apply-errors?{urlencode(params)}", status_code=303)


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
