"""Admin routes: user management, system health, manual scans."""

import csv
import re
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.db_models import User, Application, Domain, TLSResult, MLPrediction, SecurityWarranty, UserSession
from ..schemas.pydantic_schemas import UserOut, RoleUpdateRequest, SystemHealthOut, AppOut, SessionOut
from .auth import require_role

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@router.patch("/users/{user_id}/role", response_model=UserOut)
async def update_role(
    user_id: int,
    body: RoleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.role = body.role
    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    await db.delete(user)
    await db.commit()


@router.get("/users/{user_id}/sessions", response_model=list[SessionOut])
async def get_user_sessions(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """Return all login sessions for a given user (login history)."""
    result = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == user_id)
        .order_by(UserSession.last_seen_at.desc())
    )
    return result.scalars().all()


@router.delete("/users/{user_id}/sessions", status_code=204)
async def force_logout_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """Delete all active sessions for the user, forcing them to log in again."""
    await db.execute(delete(UserSession).where(UserSession.user_id == user_id))
    await db.commit()


@router.post("/users/{user_id}/send-email", status_code=200)
async def send_email_to_user(
    user_id: int,
    body: dict,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """Send a custom email from the admin to a specific user via SMTP."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")

    subject = body.get("subject", "").strip()
    content = body.get("body", "").strip()
    if not subject or not content:
        raise HTTPException(422, "Subject and body are required")

    from ..config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    if not SMTP_HOST or not SMTP_USER:
        raise HTTPException(503, "SMTP is not configured on this server. Add SMTP_HOST, SMTP_USER and SMTP_PASSWORD to your .env file.")

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = user.email
        body_html = content.replace("\n", "<br>")
        msg.attach(MIMEText(content, "plain"))
        msg.attach(MIMEText(f"<p>{body_html}</p><hr><p style='font-size:11px;color:#888'>Sent via QuantumShield Admin</p>", "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if SMTP_PASSWORD:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.sendmail(SMTP_USER, user.email, msg.as_string())
    except Exception as exc:
        raise HTTPException(500, f"Failed to send email: {exc}")

    return {"message": f"Email sent to {user.email}"}


@router.delete("/users/{user_id}/2fa", status_code=204)
async def reset_user_2fa(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """Disable TOTP 2FA for a user (useful if they are locked out)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.totp_enabled = False
    user.totp_secret = None
    await db.commit()


@router.get("/system/health", response_model=SystemHealthOut)
async def system_health(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    import os
    total_users = (await db.execute(select(func.count(User.id)))).scalar() or 0
    total_apps = (await db.execute(select(func.count(Application.id)))).scalar() or 0
    total_scans = (await db.execute(select(func.count(TLSResult.id)))).scalar() or 0
    pending_scans = (await db.execute(
        select(func.count(Application.id)).where(Application.scan_status.in_(["pending", "scanning"]))
    )).scalar() or 0

    from ..config import MODEL_PATH
    ml_loaded = os.path.exists(MODEL_PATH)

    return SystemHealthOut(
        db_connected=True,
        total_users=total_users,
        total_apps=total_apps,
        total_scans=total_scans,
        pending_scans=pending_scans,
        ml_model_loaded=ml_loaded,
    )


@router.get("/scan-queue", response_model=list[AppOut])
async def get_scan_queue(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """Apps currently pending or actively scanning."""
    result = await db.execute(
        select(Application)
        .where(Application.scan_status.in_(["pending", "scanning"]))
        .order_by(Application.submitted_at.desc())
        .limit(100)
    )
    return result.scalars().all()


@router.get("/recent-scans", response_model=list[AppOut])
async def get_recent_scans(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """Most recently completed scans."""
    result = await db.execute(
        select(Application)
        .where(Application.scan_status == "completed")
        .order_by(Application.submitted_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/ml-metrics")
async def get_ml_metrics(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """ML model prediction statistics."""
    total = (await db.execute(select(func.count(MLPrediction.id)))).scalar() or 0
    avg_score = (await db.execute(select(func.avg(MLPrediction.security_score)))).scalar()
    avg_pqc = (await db.execute(select(func.avg(MLPrediction.pqc_readiness_score)))).scalar()
    avg_conf = (await db.execute(select(func.avg(MLPrediction.confidence)))).scalar()

    risk_rows = (await db.execute(
        select(MLPrediction.risk_level, func.count(MLPrediction.id))
        .group_by(MLPrediction.risk_level)
    )).fetchall()

    # Apps with predictions vs without
    apps_with_pred = (await db.execute(
        select(func.count(func.distinct(MLPrediction.app_id)))
    )).scalar() or 0
    total_apps = (await db.execute(select(func.count(Application.id)))).scalar() or 0

    return {
        "total_predictions": total,
        "apps_with_predictions": apps_with_pred,
        "total_apps": total_apps,
        "coverage_pct": round(apps_with_pred / total_apps * 100, 1) if total_apps else 0,
        "avg_security_score": round(avg_score, 1) if avg_score else 0,
        "avg_pqc_readiness": round(avg_pqc, 1) if avg_pqc else 0,
        "avg_confidence": round(avg_conf, 3) if avg_conf else None,
        "risk_distribution": {r[0]: r[1] for r in risk_rows},
    }


@router.get("/vuln-db")
async def get_vuln_db(
    _admin: User = Depends(require_role("admin")),
):
    """Read-only view of the active vulnerability/CVE database."""
    from ..services.cve_mapper import VULN_DB
    return [
        {
            "key": key,
            "cves": entry.get("cves", []),
            "cvss": entry.get("cvss"),
            "severity": entry.get("severity"),
            "description": entry.get("description", ""),
            "ref": entry.get("ref"),
        }
        for key, entry in VULN_DB.items()
    ]


@router.post("/ml/train", status_code=202)
async def train_ml_model(
    background_tasks: BackgroundTasks,
    _admin: User = Depends(require_role("admin")),
):
    """Retrain the RandomForest model on all scanned apps (background task)."""
    async def _run():
        from ..services.ml_predictor import retrain_model
        await retrain_model()

    background_tasks.add_task(_run)
    return {"message": "Model training started in background. Check /admin/ml-metrics after ~30s."}


@router.post("/ml/train-sync")
async def train_ml_model_sync(
    _admin: User = Depends(require_role("admin")),
):
    """Retrain the model synchronously and return metrics (may take 10-30s)."""
    from ..services.ml_predictor import retrain_model
    result = await retrain_model()
    return result


@router.post("/ml/repredict-all", status_code=202)
async def repredict_all_apps(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """Re-run ML prediction for all apps using the current model (background task)."""
    async def _run():
        from ..database import async_session
        from ..services.ml_predictor import repredict_all
        async with async_session() as sess:
            count = await repredict_all(sess)
        return count

    background_tasks.add_task(_run)
    return {"message": "Re-prediction queued for all apps."}


@router.post("/scan/{app_id}", status_code=202)
async def trigger_rescan(
    app_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(404, "Application not found")

    app.scan_status = "pending"
    await db.commit()

    from ..services.tls_scanner import run_scan_pipeline
    background_tasks.add_task(run_scan_pipeline, app.id)
    return {"message": f"Re-scan queued for app {app_id}"}


@router.post("/seed-csv", status_code=200)
async def seed_from_csv(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """
    Import apps, domains, and TLS results from the research CSV dataset.

    Reads  pqc-research/data/report_per_domain.csv  (configured via
    PIPELINE_DATA_DIR).  Groups domains by their root brand name into
    logical Application records, creates Domain + TLSResult rows, then
    runs a simple ML-score heuristic so the dashboard charts are populated.

    Idempotent: skips apps/domains that already exist by package_name /
    domain name.  Safe to call multiple times.
    """
    from ..config import PIPELINE_DATA_DIR
    import os

    csv_path = os.path.join(PIPELINE_DATA_DIR, "report_per_domain.csv")
    if not os.path.exists(csv_path):
        raise HTTPException(404, f"CSV not found at {csv_path}")

    # ── helpers ──────────────────────────────────────────────────────────────

    def _root(domain: str) -> str:
        """Extract the brand segment from a domain (e.g. 'appsflyersdk' from sub.x.appsflyersdk.com)."""
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return ""
        parts = domain.rstrip(".").split(".")
        # Handle ccTLDs like .com.au, .co.uk (second-to-last part is 2-3 chars)
        if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
            return parts[-3].lower() if len(parts) >= 4 else parts[-3].lower()
        return parts[-2].lower() if len(parts) >= 2 else domain.lower()

    def _score(row: dict) -> float:
        ver = row.get("scan_tls_ver", "")
        base: float = {"TLSv1.3": 85.0, "TLSv1.2": 65.0, "TLSv1.1": 35.0, "TLSv1.0": 20.0}.get(ver, 45.0)
        if row.get("pqc_capable") == "True": base = min(100.0, base + 10)
        if row.get("scan_flag_legacy_tls") == "True": base -= 15
        if row.get("scan_flag_rc4_3des") == "True": base -= 15
        if row.get("scan_flag_rsa_kx") == "True": base -= 5
        if row.get("scan_flag_cert_small") == "True": base -= 5
        return max(0.0, min(100.0, base))

    def _risk(s: float) -> str:
        return "Low" if s >= 80 else "Medium" if s >= 60 else "High" if s >= 40 else "Critical"

    def _pqc(s: float, pqc_capable: str) -> float:
        if pqc_capable == "True": return min(100.0, s + 5)
        return max(0.0, s - 10)

    def _bool(v: str) -> bool:
        return v.strip().lower() == "true"

    # ── read and group CSV ────────────────────────────────────────────────────
    groups: dict[str, list[dict]] = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            root = _root(row["domain"])
            if not root or root == "ip_address":
                continue
            groups.setdefault(root, []).append(row)

    # Sort by number of domains (most data-rich first), include all brands
    qualified = sorted(
        [(k, v) for k, v in groups.items()],
        key=lambda x: -len(x[1]),
    )

    apps_created = 0
    domains_created = 0
    tls_created = 0
    predictions_created = 0
    warranties_created = 0
    now = datetime.now(timezone.utc)

    for root_name, rows in qualified:
        pkg = f"csv.{root_name}"

        # Compute scores (needed whether creating or repairing)
        scored = [r for r in rows if r.get("scan_tls_ver")]
        scores = [_score(r) for r in scored] if scored else [50.0]
        avg_sec = round(sum(scores) / len(scores), 1)
        pqc_vals = [_pqc(s, r.get("pqc_capable", "False")) for s, r in zip(scores, scored)] if scored else [40.0]
        avg_pqc = round(sum(pqc_vals) / len(pqc_vals), 1)

        existing = (await db.execute(
            select(Application).where(Application.package_name == pkg)
        )).scalar_one_or_none()

        if existing:
            app_id = existing.id
            # Check which child data is missing — repair if incomplete
            has_domains = bool((await db.execute(
                select(func.count(Domain.id)).where(Domain.app_id == app_id)
            )).scalar())
            has_pred = bool((await db.execute(
                select(func.count(MLPrediction.id)).where(MLPrediction.app_id == app_id)
            )).scalar())
            has_warranty = bool((await db.execute(
                select(func.count(SecurityWarranty.id)).where(SecurityWarranty.app_id == app_id)
            )).scalar())
            if has_domains and has_pred and has_warranty:
                continue  # fully seeded — nothing to do
        else:
            app = Application(
                package_name=pkg,
                app_name=root_name.replace("-", " ").replace("_", " ").title(),
                category="Research Dataset",
                description=f"Imported from PQC research scan — {len(rows)} domains analysed.",
                scan_status="completed",
                is_public=True,
                submitted_at=now,
            )
            db.add(app)
            await db.flush()   # populates app.id
            app_id = app.id
            apps_created += 1
            has_domains = False
            has_pred = False
            has_warranty = False

        # Domains + TLS (skip if already exist for this app)
        if not has_domains:
            for row in rows:
                dom = Domain(
                    app_id=app_id,
                    domain=row["domain"],
                    country=row.get("vantage_point") or None,
                    is_third_party=row.get("domain_class", "") not in ("first_party",),
                    domain_class=row.get("domain_class") or None,
                )
                db.add(dom)
                await db.flush()   # populates dom.id
                domains_created += 1

                tls_ver = row.get("scan_tls_ver") or None
                cipher = row.get("scan_cipher") or None
                key_type = row.get("scan_cert_key_type") or None
                key_bits_raw = row.get("scan_cert_key_bits", "")
                key_bits = int(key_bits_raw) if key_bits_raw.isdigit() else None
                cipher_bits_raw = row.get("scan_cipher_bits", "")
                cipher_bits = int(cipher_bits_raw) if cipher_bits_raw.isdigit() else None
                sec_score = _score(row) if tls_ver else None

                db.add(TLSResult(
                    domain_id=dom.id,
                    tls_version=tls_ver,
                    cipher_suite=cipher,
                    cert_key_type=key_type,
                    cert_key_bits=key_bits,
                    cipher_strength_score=float(cipher_bits) if cipher_bits else None,
                    supports_pqc=_bool(row.get("scan_pqc_capable", "False")),
                    pqc_group=row.get("scan_hrr_group") or None,
                    has_rsa_key_exchange=_bool(row.get("scan_flag_rsa_kx", "False")),
                    flag_legacy_tls=_bool(row.get("scan_flag_legacy_tls", "False")),
                    flag_rc4_or_3des=_bool(row.get("scan_flag_rc4_3des", "False")),
                    security_score=sec_score,
                    quantum_risk_score=round(max(0.0, 100.0 - (sec_score or 50.0)) / 100, 4),
                    scan_date=now,
                    scan_error=row.get("scan_error") or None,
                ))
                tls_created += 1

        if not has_pred:
            db.add(MLPrediction(
                app_id=app_id,
                security_score=avg_sec,
                risk_level=_risk(avg_sec),
                pqc_readiness_score=avg_pqc,
                confidence=0.85,
                predicted_at=now,
            ))
            predictions_created += 1

        if not has_warranty:
            warranty_status = "Certified" if avg_sec >= 80 else "Conditional" if avg_sec >= 60 else "Not Certified"
            db.add(SecurityWarranty(
                app_id=app_id,
                status=warranty_status,
                issued_at=now,
                justification=f"Auto-issued from research dataset. Security score: {avg_sec}.",
            ))
            warranties_created += 1

        await db.commit()

    return {
        "message": "Seed complete.",
        "apps_created": apps_created,
        "domains_created": domains_created,
        "tls_results_created": tls_created,
        "predictions_created": predictions_created,
        "warranties_created": warranties_created,
    }


@router.get("/metrics/timeseries")
async def metrics_timeseries(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """Return 8 three-hour buckets (24 h) of scan and prediction activity."""
    now = datetime.now(timezone.utc)
    buckets = []
    for i in range(7, -1, -1):
        bucket_start = now - timedelta(hours=(i + 1) * 3)
        bucket_end   = now - timedelta(hours=i * 3)
        label = bucket_end.strftime("%H:%M")

        scans = (await db.execute(
            select(func.count(Application.id)).where(
                Application.submitted_at >= bucket_start,
                Application.submitted_at < bucket_end,
            )
        )).scalar() or 0

        preds = (await db.execute(
            select(func.count(MLPrediction.id)).where(
                MLPrediction.predicted_at >= bucket_start,
                MLPrediction.predicted_at < bucket_end,
            )
        )).scalar() or 0

        buckets.append({"time": label, "scans": scans, "predictions": preds})

    return buckets
