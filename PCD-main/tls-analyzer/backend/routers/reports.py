"""Routes for security reports: list and download."""

import io
import json
from datetime import datetime, timezone
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.db_models import Report, User, Application, MLPrediction
from ..schemas.pydantic_schemas import ReportOut
from .auth import get_current_user

router = APIRouter(prefix="/reports", tags=["reports"])


async def _auto_generate_reports(db: AsyncSession) -> list[Report]:
    """
    Build Report rows from the applications already in the database.
    Groups scanned apps by submission month → monthly reports.
    Groups by quarter → quarterly reports.
    A "platform security overview" custom report covers all apps.
    All generated reports are saved so subsequent calls just read the DB.
    """
    now = datetime.now(timezone.utc)

    # Fetch all completed apps with their submission date and ML prediction
    app_rows = (await db.execute(
        select(Application.id, Application.submitted_at, Application.app_name)
        .where(Application.scan_status == "completed")
        .order_by(Application.submitted_at)
    )).fetchall()

    if not app_rows:
        return []

    # Group by (year, month)
    monthly: dict[tuple[int, int], int] = defaultdict(int)
    # Group by (year, quarter)
    quarterly: dict[tuple[int, int], int] = defaultdict(int)

    for _, submitted_at, _ in app_rows:
        if submitted_at is None:
            continue
        y, m = submitted_at.year, submitted_at.month
        monthly[(y, m)] += 1
        q = (m - 1) // 3 + 1
        quarterly[(y, q)] += 1

    reports_to_add: list[Report] = []

    # Monthly reports — one per (year, month) bucket
    for (y, m), count in sorted(monthly.items(), reverse=True):
        month_name = datetime(y, m, 1).strftime("%B %Y")
        r = Report(
            title=f"Monthly Security Report — {month_name}",
            date=datetime(y, m, 1, tzinfo=timezone.utc),
            type="monthly",
            apps_count=count,
            status="ready",
        )
        db.add(r)
        reports_to_add.append(r)

    # Quarterly reports — one per (year, quarter)
    quarter_label = {1: "Q1", 2: "Q2", 3: "Q3", 4: "Q4"}
    for (y, q), count in sorted(quarterly.items(), reverse=True):
        r = Report(
            title=f"Quarterly PQC Assessment — {quarter_label[q]} {y}",
            date=datetime(y, (q - 1) * 3 + 1, 1, tzinfo=timezone.utc),
            type="quarterly",
            apps_count=count,
            status="ready",
        )
        db.add(r)
        reports_to_add.append(r)

    # One overall "Platform Security Overview" custom report
    total = len(app_rows)
    r = Report(
        title="Platform Security Overview — All Time",
        date=now,
        type="custom",
        apps_count=total,
        status="ready",
    )
    db.add(r)
    reports_to_add.append(r)

    await db.commit()
    return reports_to_add


@router.get("/", response_model=list[ReportOut])
async def list_reports(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Report).order_by(Report.date.desc()))
    reports = result.scalars().all()

    # Auto-generate reports from app data if the reports table is empty
    if not reports:
        reports = await _auto_generate_reports(db)
        # Re-fetch in sorted order after commit
        result = await db.execute(select(Report).order_by(Report.date.desc()))
        reports = result.scalars().all()

    if user.role == "end_user":
        reports = [r for r in reports if r.type in ("weekly", "monthly")][:3]
    return reports


@router.post("/regenerate", status_code=200)
async def regenerate_reports(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Admin-only: delete all existing report records and regenerate them
    from the current app dataset. Useful after seeding new apps.
    """
    if user.role != "admin":
        raise HTTPException(403, "Admin only")

    # Delete all existing reports
    result = await db.execute(select(Report))
    for r in result.scalars().all():
        await db.delete(r)
    await db.commit()

    generated = await _auto_generate_reports(db)
    return {"message": f"Regenerated {len(generated)} reports from app data."}


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "ready":
        raise HTTPException(status_code=400, detail="Report is not ready yet")
    if user.role == "end_user" and report.type not in ("weekly", "monthly"):
        raise HTTPException(status_code=403, detail="Access denied")

    # Collect summary stats relevant to this report's time window
    from ..models.db_models import TLSResult, Domain
    from sqlalchemy import and_

    # Get apps in this report's period (same month for monthly, same quarter for quarterly)
    report_date = report.date
    if report.type == "monthly":
        start = datetime(report_date.year, report_date.month, 1, tzinfo=timezone.utc)
        if report_date.month == 12:
            end = datetime(report_date.year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            end = datetime(report_date.year, report_date.month + 1, 1, tzinfo=timezone.utc)
        period_filter = and_(Application.submitted_at >= start, Application.submitted_at < end)
    elif report.type == "quarterly":
        q = (report_date.month - 1) // 3 + 1
        start = datetime(report_date.year, (q - 1) * 3 + 1, 1, tzinfo=timezone.utc)
        if q == 4:
            end = datetime(report_date.year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            end = datetime(report_date.year, q * 3 + 1, 1, tzinfo=timezone.utc)
        period_filter = and_(Application.submitted_at >= start, Application.submitted_at < end)
    else:
        period_filter = None  # custom — all apps

    pred_q = (
        select(MLPrediction.security_score, MLPrediction.risk_level, MLPrediction.pqc_readiness_score)
        .join(Application, MLPrediction.app_id == Application.id)
    )
    if period_filter is not None:
        pred_q = pred_q.where(period_filter)
    preds = (await db.execute(pred_q)).fetchall()

    avg_score = round(sum(p[0] for p in preds) / len(preds), 1) if preds else 0
    avg_pqc = round(sum(p[2] for p in preds) / len(preds), 1) if preds else 0
    risk_dist: dict[str, int] = {}
    for p in preds:
        risk_dist[p[1]] = risk_dist.get(p[1], 0) + 1

    # TLS distribution
    tls_q = (
        select(TLSResult.tls_version, func.count(TLSResult.id))
        .join(Domain, TLSResult.domain_id == Domain.id)
        .join(Application, Domain.app_id == Application.id)
        .where(TLSResult.tls_version.isnot(None))
        .group_by(TLSResult.tls_version)
    )
    if period_filter is not None:
        tls_q = tls_q.where(period_filter)
    tls_dist = {r[0]: r[1] for r in (await db.execute(tls_q)).fetchall()}

    data = {
        "report_id": report.id,
        "title": report.title,
        "date": report.date.isoformat(),
        "type": report.type,
        "apps_analyzed": report.apps_count,
        "status": report.status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "avg_security_score": avg_score,
        "avg_pqc_readiness": avg_pqc,
        "risk_distribution": risk_dist,
        "tls_distribution": tls_dist,
        "summary": (
            f"This {report.type} security report covers {report.apps_count} applications. "
            f"Average security score: {avg_score}/100. "
            f"Average PQC readiness: {avg_pqc}%. "
            "All applications were analyzed for TLS configuration, post-quantum cryptography "
            "readiness, and known vulnerabilities."
        ),
    }
    content = json.dumps(data, indent=2).encode()
    filename = report.title.replace(" ", "_").replace("—", "-") + ".json"
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
