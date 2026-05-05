"""Application CRUD and analysis result routes."""

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.db_models import (
    Application, Domain, TLSResult, Vulnerability, MLPrediction, SecurityWarranty,
)
from ..schemas.pydantic_schemas import (
    AppSubmitRequest, AppOut, DomainOut, TLSResultOut,
    VulnerabilityOut, MLPredictionOut, WarrantyOut, AppReportOut,
    VisibilityUpdateRequest,
)
from .auth import get_current_user, require_role
from ..models.db_models import User

router = APIRouter(prefix="/apps", tags=["apps"])

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


@router.post("/submit", response_model=AppOut, status_code=201)
async def submit_app(
    body: AppSubmitRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("app_owner", "admin")),
):
    app = Application(
        package_name=body.package_name,
        app_name=body.app_name,
        category=body.category,
        apk_path=body.apk_path,
        owner_id=user.id,
        scan_status="pending",
    )
    db.add(app)
    await db.commit()
    await db.refresh(app)

    from ..services.tls_scanner import run_scan_pipeline
    background_tasks.add_task(run_scan_pipeline, app.id)
    return app


@router.post("/upload-apk", response_model=AppOut, status_code=201)
async def upload_apk(
    file: UploadFile = File(...),
    app_name: str = Form(""),
    category: str = Form(""),
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("app_owner", "admin")),
):
    """Accept an .apk file upload, store it, then queue scanning."""
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "File must be an .apk")

    safe_name = f"{uuid.uuid4().hex}_{file.filename}"
    dest = UPLOAD_DIR / safe_name
    dest.write_bytes(await file.read())

    # Infer package name from filename (strip .apk extension)
    pkg = file.filename[:-4].replace("-", ".").replace("_", ".")

    app = Application(
        package_name=pkg,
        app_name=app_name.strip() or pkg,
        category=category.strip() or None,
        apk_path=str(dest),
        owner_id=user.id,
        scan_status="pending",
    )
    db.add(app)
    await db.commit()
    await db.refresh(app)

    from ..services.tls_scanner import run_scan_pipeline
    if background_tasks:
        background_tasks.add_task(run_scan_pipeline, app.id)
    return app


class UrlAnalysisRequest(BaseModel):
    url: str


# ── Known Play Store / app-store URL patterns ────────────────────────────────
_PLAY_STORE_RE = re.compile(
    r"play\.google\.com/store/apps/details.*[?&]id=([A-Za-z0-9_.]+)"
)
_APPLE_STORE_RE = re.compile(
    r"apps\.apple\.com/.+/app/.+/id(\d+)"
)

# Simple hostname validation (bare domain or with optional port)
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d+)?$"
)


def _parse_analysis_target(raw: str) -> tuple[str, str]:
    """
    Given a raw string from the user, return (mode, value) where:
      mode = "package"   → value is an Android package name
      mode = "hostname"  → value is a hostname to TLS-scan directly

    Handles:
      - Play Store URLs  → extract package id
      - Full HTTPS/HTTP URLs  → extract hostname
      - Bare hostnames / domains
    """
    raw = raw.strip()

    # Play Store URL
    m = _PLAY_STORE_RE.search(raw)
    if m:
        return "package", m.group(1)

    # Generic URL — extract hostname
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        if host:
            return "hostname", host
        raise ValueError(f"Cannot extract hostname from URL: {raw!r}")

    # Bare domain (e.g. "example.com", "api.company.io")
    if _HOSTNAME_RE.match(raw):
        # Strip optional port
        host = raw.split(":")[0]
        return "hostname", host

    # Last resort: treat as package name if it looks like one
    if re.match(r"^[a-zA-Z][a-zA-Z0-9_.]+$", raw) and raw.count(".") >= 1:
        return "package", raw

    raise ValueError(
        f"Cannot interpret {raw!r} as a URL, domain, or package name. "
        "Please enter a full URL (https://…), a domain (example.com), or a package name (com.example.app)."
    )


@router.post("/analyze-url", response_model=AppOut, status_code=201)
async def analyze_url(
    body: UrlAnalysisRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Analyze a URL, domain, or Play Store link.

    Accepts:
      - Full URLs:          https://api.example.com/v1/
      - Bare domains:       example.com
      - Play Store URLs:    https://play.google.com/store/apps/details?id=com.example.app

    For Play Store / package names the full app scan pipeline runs (same as /submit).
    For raw hostnames a direct TLS scan is performed on that single domain.
    """
    try:
        mode, value = _parse_analysis_target(body.url)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    if mode == "package":
        # Same as /submit
        app = Application(
            package_name=value,
            app_name=value,
            owner_id=user.id,
            scan_status="pending",
        )
        db.add(app)
        await db.commit()
        await db.refresh(app)

        from ..services.tls_scanner import run_scan_pipeline
        background_tasks.add_task(run_scan_pipeline, app.id)

    else:  # hostname
        # Derive a synthetic package name so the rest of the system is happy
        safe_pkg = "url." + value.replace("-", "_").replace(":", "_")
        app = Application(
            package_name=safe_pkg,
            app_name=value,
            owner_id=user.id,
            scan_status="pending",
        )
        db.add(app)
        await db.commit()
        await db.refresh(app)

        from ..services.tls_scanner import run_url_scan_pipeline
        background_tasks.add_task(run_url_scan_pipeline, app.id, value)

    return app


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Dashboard stats: totals, averages, risk & TLS distributions.

    Scoping rules:
    - end_user → global stats across all public apps in the dataset.
    - app_owner / admin → stats scoped to apps they own (so the dashboard
      reflects their portfolio, including TLS distribution for their domains).
    """
    # Only app_owner gets a portfolio-scoped view (their own apps).
    # admin and end_user both see global stats across all apps.
    is_scoped = user.role == "app_owner"

    # ── App count ────────────────────────────────────────────────────────────
    app_count_q = select(func.count(Application.id))
    if is_scoped:
        app_count_q = app_count_q.where(Application.owner_id == user.id)
    total_apps = (await db.execute(app_count_q)).scalar() or 0

    # ── Latest ML prediction per app ─────────────────────────────────────────
    latest_sq = (
        select(MLPrediction.app_id, func.max(MLPrediction.predicted_at).label("mpa"))
        .group_by(MLPrediction.app_id)
        .subquery()
    )
    pred_q = (
        select(MLPrediction.security_score, MLPrediction.risk_level, MLPrediction.pqc_readiness_score)
        .join(latest_sq, (MLPrediction.app_id == latest_sq.c.app_id) &
                         (MLPrediction.predicted_at == latest_sq.c.mpa))
    )
    if is_scoped:
        pred_q = pred_q.join(Application, MLPrediction.app_id == Application.id).where(
            Application.owner_id == user.id
        )
    pred_rows = (await db.execute(pred_q)).fetchall()

    avg_score = round(sum(r[0] for r in pred_rows) / len(pred_rows), 1) if pred_rows else 0
    avg_pqc = round(sum(r[2] for r in pred_rows) / len(pred_rows), 1) if pred_rows else 0
    risk_dist: dict[str, int] = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for r in pred_rows:
        risk_dist[r[1]] = risk_dist.get(r[1], 0) + 1

    # ── TLS version distribution ─────────────────────────────────────────────
    tls_q = (
        select(TLSResult.tls_version, func.count(TLSResult.id))
        .group_by(TLSResult.tls_version)
    )
    if is_scoped:
        tls_q = (
            tls_q
            .join(Domain, TLSResult.domain_id == Domain.id)
            .join(Application, Domain.app_id == Application.id)
            .where(Application.owner_id == user.id)
        )
    tls_rows = (await db.execute(tls_q)).fetchall()
    # Drop rows where the scanner returned an error (NULL tls_version) to avoid
    # an "Unknown" bar that dwarfs real TLS data.
    tls_dist = {r[0]: r[1] for r in tls_rows if r[0]}

    return {
        "total_apps": total_apps,
        "avg_security_score": avg_score,
        "avg_pqc_readiness": avg_pqc,
        "risk_distribution": risk_dist,
        "tls_distribution": tls_dist,
    }


@router.get("/domain-classes")
async def get_domain_classes(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Distribution of domain classes across all scanned domains."""
    rows = (await db.execute(
        select(Domain.domain_class, func.count(Domain.id))
        .where(Domain.domain_class.isnot(None))
        .group_by(Domain.domain_class)
        .order_by(func.count(Domain.id).desc())
    )).fetchall()
    return [{"class": r[0], "count": r[1]} for r in rows]


@router.get("/", response_model=list[AppOut])
async def list_apps(
    q: str = "",
    skip: int = 0,
    limit: int = 10000,
    sort: str = "recent",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Subquery: latest prediction per app
    latest_pred = (
        select(
            MLPrediction.app_id,
            MLPrediction.security_score,
            MLPrediction.risk_level,
            MLPrediction.pqc_readiness_score,
        )
        .distinct(MLPrediction.app_id)
        .order_by(MLPrediction.app_id, MLPrediction.predicted_at.desc())
        .subquery()
    )

    base_cols = (
        Application,
        latest_pred.c.security_score,
        latest_pred.c.risk_level,
        latest_pred.c.pqc_readiness_score,
    )

    # Role-based visibility + deduplication
    if user.role == "admin":
        stmt = select(*base_cols).outerjoin(latest_pred, Application.id == latest_pred.c.app_id)
    elif user.role == "app_owner":
        from sqlalchemy import or_
        stmt = (
            select(*base_cols)
            .outerjoin(latest_pred, Application.id == latest_pred.c.app_id)
            .where(or_(Application.is_public == True, Application.owner_id == user.id))
        )
    else:
        # end_user: public apps only, deduplicated by package_name (show newest per package)
        newest_sq = (
            select(
                Application.package_name,
                func.max(Application.submitted_at).label("max_submitted"),
            )
            .where(Application.is_public == True)
            .group_by(Application.package_name)
            .subquery()
        )
        stmt = (
            select(*base_cols)
            .outerjoin(latest_pred, Application.id == latest_pred.c.app_id)
            .join(
                newest_sq,
                (Application.package_name == newest_sq.c.package_name)
                & (Application.submitted_at == newest_sq.c.max_submitted)
                & (Application.is_public == True),
            )
        )

    if q:
        stmt = stmt.where(
            Application.app_name.ilike(f"%{q}%")
            | Application.package_name.ilike(f"%{q}%")
        )

    # Sorting
    if sort == "score":
        stmt = stmt.order_by(latest_pred.c.security_score.desc().nulls_last())
    elif sort == "name":
        stmt = stmt.order_by(Application.app_name.asc().nulls_last())
    elif sort == "rating":
        stmt = stmt.order_by(Application.rating.desc().nulls_last())
    else:  # recent (default)
        stmt = stmt.order_by(Application.submitted_at.desc())

    stmt = stmt.offset(skip).limit(limit)
    rows = (await db.execute(stmt)).all()

    # Merge prediction columns into AppOut
    out = []
    for row in rows:
        app, sec_score, risk, pqc = row
        d = AppOut.model_validate(app)
        d.security_score = sec_score
        d.risk_level = risk
        d.pqc_readiness_score = pqc
        out.append(d)
    return out


def _build_pred_subquery():
    return (
        select(
            MLPrediction.app_id,
            MLPrediction.security_score,
            MLPrediction.risk_level,
            MLPrediction.pqc_readiness_score,
        )
        .distinct(MLPrediction.app_id)
        .order_by(MLPrediction.app_id, MLPrediction.predicted_at.desc())
        .subquery()
    )


def _inject_pred(rows) -> list[AppOut]:
    out = []
    for row in rows:
        app, sec_score, risk, pqc = row
        d = AppOut.model_validate(app)
        d.security_score = sec_score
        d.risk_level = risk
        d.pqc_readiness_score = pqc
        out.append(d)
    return out


@router.get("/recent-completions", response_model=list[AppOut])
async def recent_completions(
    since: str = Query(..., description="ISO-8601 UTC timestamp — return apps scanned after this"),
    owner_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Apps whose scan finished after *since*. For app owners pass owner_id to scope to their apps.
    End users and app owners see only public apps; admins see all."""
    try:
        since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "Invalid 'since' timestamp")

    latest_pred = _build_pred_subquery()
    stmt = (
        select(Application, latest_pred.c.security_score, latest_pred.c.risk_level, latest_pred.c.pqc_readiness_score)
        .outerjoin(latest_pred, Application.id == latest_pred.c.app_id)
        .where(Application.scanned_at >= since_dt)
        .where(Application.scan_status.in_(["completed", "failed"]))
    )
    if owner_id is not None:
        stmt = stmt.where(Application.owner_id == owner_id)
    elif user.role != "admin":
        stmt = stmt.where(Application.is_public == True)
    stmt = stmt.order_by(Application.scanned_at.desc()).limit(50)
    return _inject_pred((await db.execute(stmt)).all())


@router.get("/recent-public", response_model=list[AppOut])
async def recent_public(
    since: str = Query(..., description="ISO-8601 UTC timestamp — return apps made public after this"),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Public apps that were made publicly visible after *since*."""
    try:
        since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "Invalid 'since' timestamp")

    latest_pred = _build_pred_subquery()
    stmt = (
        select(Application, latest_pred.c.security_score, latest_pred.c.risk_level, latest_pred.c.pqc_readiness_score)
        .outerjoin(latest_pred, Application.id == latest_pred.c.app_id)
        .where(Application.made_public_at >= since_dt)
        .where(Application.is_public == True)
        .where(Application.scan_status == "completed")
        .order_by(Application.made_public_at.desc())
        .limit(50)
    )
    return _inject_pred((await db.execute(stmt)).all())


@router.get("/{app_id}", response_model=AppOut)
async def get_app(
    app_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(404, "Application not found")
    pred_row = (await db.execute(
        select(MLPrediction.security_score, MLPrediction.risk_level, MLPrediction.pqc_readiness_score)
        .where(MLPrediction.app_id == app_id)
        .order_by(MLPrediction.predicted_at.desc())
        .limit(1)
    )).first()
    out = AppOut.model_validate(app)
    if pred_row:
        out.security_score, out.risk_level, out.pqc_readiness_score = pred_row
    return out


@router.get("/{app_id}/domains", response_model=list[DomainOut])
async def get_domains(
    app_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(select(Domain).where(Domain.app_id == app_id))
    return result.scalars().all()


@router.get("/{app_id}/tls", response_model=list[TLSResultOut])
async def get_tls(
    app_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(TLSResult)
        .join(Domain, TLSResult.domain_id == Domain.id)
        .where(Domain.app_id == app_id)
    )
    return result.scalars().all()


@router.get("/{app_id}/vulnerabilities", response_model=list[VulnerabilityOut])
async def get_vulnerabilities(
    app_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Vulnerability)
        .join(TLSResult, Vulnerability.tls_result_id == TLSResult.id)
        .join(Domain, TLSResult.domain_id == Domain.id)
        .where(Domain.app_id == app_id)
    )
    return result.scalars().all()


@router.get("/{app_id}/prediction", response_model=MLPredictionOut)
async def get_prediction(
    app_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(MLPrediction)
        .where(MLPrediction.app_id == app_id)
        .order_by(MLPrediction.predicted_at.desc())
    )
    pred = result.scalar_one_or_none()
    if not pred:
        raise HTTPException(404, "No prediction available yet")
    return pred


@router.get("/{app_id}/warranty", response_model=WarrantyOut)
async def get_warranty(
    app_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(SecurityWarranty)
        .where(SecurityWarranty.app_id == app_id)
        .order_by(SecurityWarranty.issued_at.desc())
    )
    w = result.scalar_one_or_none()
    if not w:
        raise HTTPException(404, "No warranty issued yet")
    return w


@router.patch("/{app_id}/visibility", response_model=AppOut)
async def set_visibility(
    app_id: int,
    body: VisibilityUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Allow app owner or admin to toggle is_public on an app."""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(404, "Application not found")
    if user.role != "admin" and app.owner_id != user.id:
        raise HTTPException(403, "Not authorised")
    app.is_public = body.is_public
    if body.is_public:
        from datetime import datetime, timezone
        app.made_public_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(app)
    out = AppOut.model_validate(app)
    return out


@router.get("/{app_id}/report")
async def get_report(
    app_id: int,
    format: str = "json",
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_role("app_owner", "admin")),
):
    """Full security report. ?format=json (default) or ?format=pdf."""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(404, "Application not found")

    domains = (await db.execute(select(Domain).where(Domain.app_id == app_id))).scalars().all()
    tls_results = (await db.execute(
        select(TLSResult).join(Domain).where(Domain.app_id == app_id)
    )).scalars().all()
    vulns = (await db.execute(
        select(Vulnerability).join(TLSResult).join(Domain).where(Domain.app_id == app_id)
    )).scalars().all()
    pred = (await db.execute(
        select(MLPrediction).where(MLPrediction.app_id == app_id).order_by(MLPrediction.predicted_at.desc())
    )).scalar_one_or_none()
    warranty = (await db.execute(
        select(SecurityWarranty).where(SecurityWarranty.app_id == app_id).order_by(SecurityWarranty.issued_at.desc())
    )).scalar_one_or_none()

    report = AppReportOut(
        app=AppOut.model_validate(app),
        domains=[DomainOut.model_validate(d) for d in domains],
        tls_results=[TLSResultOut.model_validate(t) for t in tls_results],
        vulnerabilities=[VulnerabilityOut.model_validate(v) for v in vulns],
        prediction=MLPredictionOut.model_validate(pred) if pred else None,
        warranty=WarrantyOut.model_validate(warranty) if warranty else None,
    )

    if format == "pdf":
        from ..services.report_generator import generate_pdf
        pdf_bytes = generate_pdf(report)
        if pdf_bytes:
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="report_{app_id}.pdf"',
                    "Content-Length": str(len(pdf_bytes)),
                },
            )
        raise HTTPException(503, "PDF generation requires reportlab. Install with: pip install reportlab")

    return report.model_dump()
