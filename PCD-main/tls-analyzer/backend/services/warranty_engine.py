"""
Security warranty engine.

Issues a warranty badge based on ML prediction scores:
  - score >= 75 AND pqc_score >= 50 → Certified
  - score >= 50 → Conditional
  - Below that → Not Certified
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.db_models import MLPrediction, SecurityWarranty


async def issue_warranty(app_id: int, db: AsyncSession):
    """Evaluate the latest prediction and issue a warranty."""
    pred = (await db.execute(
        select(MLPrediction)
        .where(MLPrediction.app_id == app_id)
        .order_by(MLPrediction.predicted_at.desc())
    )).scalar_one_or_none()

    if not pred:
        return

    score = pred.security_score
    pqc_score = pred.pqc_readiness_score
    risk = pred.risk_level

    if score >= 75 and pqc_score >= 50:
        status = "Certified"
        justification = (
            f"Security score {score:.1f}/100 exceeds threshold (75). "
            f"PQC readiness {pqc_score:.1f}/100 meets minimum (50). "
            f"Risk level: {risk}. Application demonstrates adequate TLS security "
            f"posture with post-quantum cryptography readiness."
        )
    elif score >= 50:
        status = "Conditional"
        reasons = []
        if pqc_score < 50:
            reasons.append(f"PQC readiness {pqc_score:.1f}/100 below threshold (50)")
        if score < 75:
            reasons.append(f"Security score {score:.1f}/100 below certification threshold (75)")
        justification = (
            f"Conditional certification. {'; '.join(reasons)}. "
            f"Risk level: {risk}. Recommend enabling hybrid PQC key exchange "
            f"(ML-KEM-768 per FIPS 203) and upgrading to TLS 1.3."
        )
    else:
        status = "Not Certified"
        justification = (
            f"Security score {score:.1f}/100 below minimum threshold (50). "
            f"Risk level: {risk}. Critical security improvements needed: "
            f"upgrade TLS versions, enable forward secrecy, deploy AEAD ciphers, "
            f"and implement PQC key exchange per NIST transition guidance."
        )

    warranty = SecurityWarranty(
        app_id=app_id,
        status=status,
        justification=justification,
        expires_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db.add(warranty)
    await db.commit()
