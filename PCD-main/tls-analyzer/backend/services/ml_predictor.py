"""
ML prediction module.

Provides:
- predict_for_app()  — run prediction on a single app's TLS data
- retrain_model()    — train RandomForest on all scanned apps, save to MODEL_PATH
- repredict_all()    — re-run prediction for every app with scan data

Feature engineering uses 14 TLS-derived signals for higher score variance
than the original 9-feature version.
"""

import os
import pickle
import warnings
import numpy as np
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.db_models import Application, Domain, TLSResult, Vulnerability, MLPrediction
from ..config import MODEL_PATH

# ── Feature names (14-dimensional) ─────────────────────────────────────
FEATURE_NAMES = [
    "avg_tls_version",       # 0-4 encoded (0=unknown, 4=TLS 1.3)
    "pct_tls13",             # proportion of domains using TLS 1.3
    "cipher_strength_score", # 0-100 from scanner
    "has_pqc",               # any domain supports PQC key exchange
    "pct_pqc_domains",       # proportion of domains with PQC
    "avg_cert_validity_days",# avg certificate validity window
    "num_vulnerabilities",   # total vuln records
    "high_sev_vuln_count",   # High + Critical vulns specifically
    "avg_vulnerability_severity",  # 0 (none) – 4 (Critical)
    "key_exchange_score",    # 0-100 from kex type
    "has_forward_secrecy",   # ECDHE or DHE in any domain
    "num_domains",           # total domains analysed
    "third_party_ratio",     # fraction of third-party domains
    "quantum_risk_score",    # avg quantum_risk_score from scanner
]

# ── Helpers ─────────────────────────────────────────────────────────────

def _tls_encoded(v: Optional[str]) -> int:
    if not v:
        return 0
    u = v.upper()
    if "1.3" in u: return 4
    if "1.2" in u: return 3
    if "1.1" in u: return 2
    if "1.0" in u: return 1
    return 0


def _kex_score(kex: Optional[str], has_pqc: bool) -> float:
    if has_pqc:
        return 100.0
    if not kex:
        return 10.0
    k = kex.upper()
    if "ECDHE" in k or "X25519" in k or "SECP" in k:
        return 70.0
    if "DHE" in k:
        return 50.0
    if "RSA" in k:
        return 15.0
    return 30.0


def _sev_num(s: str) -> float:
    return {"Low": 1.0, "Medium": 2.0, "High": 3.0, "Critical": 4.0}.get(s, 0.0)


# ── Feature extraction ─────────────────────────────────────────────────

async def _extract_features(app_id: int, db: AsyncSession) -> Optional[np.ndarray]:
    domains = (await db.execute(
        select(Domain).where(Domain.app_id == app_id)
    )).scalars().all()
    if not domains:
        return None

    domain_ids = [d.id for d in domains]
    tls_rows = (await db.execute(
        select(TLSResult).where(TLSResult.domain_id.in_(domain_ids))
    )).scalars().all()
    if not tls_rows:
        return None

    vulns = (await db.execute(
        select(Vulnerability).where(
            Vulnerability.tls_result_id.in_([t.id for t in tls_rows])
        )
    )).scalars().all()

    # TLS version
    tls_enc   = [_tls_encoded(t.tls_version) for t in tls_rows]
    avg_tls   = float(np.mean(tls_enc)) if tls_enc else 0.0
    pct_tls13 = sum(1 for v in tls_enc if v == 4) / len(tls_enc)

    # Cipher
    ciphers    = [t.cipher_strength_score or 0.0 for t in tls_rows]
    avg_cipher = float(np.mean(ciphers))

    # PQC
    pqc_cnt   = sum(1 for t in tls_rows if t.supports_pqc)
    has_pqc   = pqc_cnt > 0
    pct_pqc   = pqc_cnt / len(tls_rows)

    # Certificate
    valid_days  = [t.cert_validity_days for t in tls_rows if t.cert_validity_days is not None]
    avg_validity = float(np.mean(valid_days)) if valid_days else 0.0

    # Vulnerabilities
    n_vulns      = float(len(vulns))
    hi_vulns     = float(sum(1 for v in vulns if v.severity in ("High", "Critical")))
    sev_vals     = [_sev_num(v.severity) for v in vulns]
    avg_sev      = float(np.mean(sev_vals)) if sev_vals else 0.0

    # Key exchange / forward secrecy
    kex_scores = [_kex_score(t.key_exchange, t.supports_pqc) for t in tls_rows]
    avg_kex    = float(np.mean(kex_scores))
    has_fs     = any(
        t.has_ecdh or ("DHE" in (t.key_exchange or "").upper())
        for t in tls_rows
    )

    # Domain composition
    n_dom     = float(len(domains))
    tp_ratio  = sum(1 for d in domains if d.is_third_party) / max(n_dom, 1)

    # Quantum risk
    q_risks   = [t.quantum_risk_score or 0.0 for t in tls_rows]
    avg_qrisk = float(np.mean(q_risks))

    return np.array([
        avg_tls, pct_tls13, avg_cipher,
        float(has_pqc), pct_pqc, avg_validity,
        n_vulns, hi_vulns, avg_sev,
        avg_kex, float(has_fs), n_dom,
        tp_ratio, avg_qrisk,
    ], dtype=float)


# ── Rule-based scoring (calibrated for variance) ────────────────────────

def _rule_based(features: np.ndarray) -> dict:
    """
    Multi-factor scoring designed for clear differentiation between apps.

    Score bands intended by design:
      TLS 1.3 + PQC + few vulns        → 78-95  (Low risk)
      TLS 1.3 + no PQC, some vulns     → 55-77  (Medium)
      TLS 1.2 + ECDHE, moderate vulns  → 35-54  (High)
      Legacy TLS / many high-sev vulns → 0-34   (Critical)
    """
    avg_tls   = features[0]
    pct_tls13 = features[1]
    cipher    = features[2]
    has_pqc   = bool(features[3])
    pct_pqc   = features[4]
    avg_val   = features[5]
    n_vulns   = features[6]
    hi_vulns  = features[7]
    avg_sev   = features[8]
    kex       = features[9]
    has_fs    = bool(features[10])
    n_dom     = features[11]
    _tp_ratio = features[12]
    avg_qrisk = features[13]

    # ── Protocol quality (0–38) ──────────────────────────────
    # Step function: big jump between TLS 1.2 and 1.3
    tls_base  = {4: 28, 3: 16, 2: 6, 1: 2, 0: 0}[min(4, round(avg_tls))]
    tls_score = tls_base + pct_tls13 * 10   # up to +10 for % TLS 1.3 domains

    # ── Cipher quality (0–18) ────────────────────────────────
    cipher_score = cipher * 0.18

    # ── Key exchange + forward secrecy (0–20) ────────────────
    kex_score = kex * 0.13 + (7 if has_fs else 0)

    # ── PQC readiness bonus (0–15) ───────────────────────────
    pqc_bonus = (4 + pct_pqc * 11) if has_pqc else 0

    # ── Certificate health (0–4) ─────────────────────────────
    cert_score = (
        4 if avg_val > 730
        else 2 if avg_val > 365
        else 1 if avg_val > 0
        else 0
    )

    # ── Vulnerability penalty (capped at 50) ─────────────────
    # Weighed more heavily on high/critical severity
    vuln_penalty = min(50.0, n_vulns * 1.8 + hi_vulns * 5.5 + avg_sev * 4.5)

    # ── Quantum risk penalty (0–5) ────────────────────────────
    qrisk_penalty = avg_qrisk * 0.05  # avg_qrisk is 0-100

    score = (tls_score + cipher_score + kex_score + pqc_bonus
             + cert_score - vuln_penalty - qrisk_penalty)
    score = float(np.clip(score, 0.0, 100.0))

    # ── Risk level ────────────────────────────────────────────
    if score >= 78:
        risk = "Low"
    elif score >= 55:
        risk = "Medium"
    elif score >= 35:
        risk = "High"
    else:
        risk = "Critical"

    # ── PQC readiness (0–100) ────────────────────────────────
    pqc_ready = (
        pct_pqc * 65              # coverage of PQC domains
        + pct_tls13 * 20          # TLS 1.3 adoption
        + (kex - 60) / 40 * 10 if kex > 60 else 0  # ECDHE+ bonus
    )
    if not has_pqc:
        pqc_ready = min(pqc_ready, 25.0)  # cap non-PQC apps at 25
    pqc_ready = float(np.clip(pqc_ready, 0.0, 100.0))

    # ── Confidence: higher with more domain data ──────────────
    confidence = float(np.clip(0.50 + min(n_dom, 25) / 25 * 0.42, 0.50, 0.92))

    return {
        "security_score":      round(score, 1),
        "risk_level":          risk,
        "pqc_readiness_score": round(pqc_ready, 1),
        "confidence":          round(confidence, 3),
        "feature_importances": {
            name: round(float(v), 4)
            for name, v in zip(FEATURE_NAMES, features)
        },
    }


# ── Model loading ────────────────────────────────────────────────────────

def _load_model() -> Optional[dict]:
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass
    return None


def _model_compatible(model_data: dict) -> bool:
    """Check stored feature list matches current FEATURE_NAMES."""
    return model_data.get("feature_names") == FEATURE_NAMES


# ── Prediction ───────────────────────────────────────────────────────────

async def predict_for_app(app_id: int, db: AsyncSession) -> Optional[MLPrediction]:
    features = await _extract_features(app_id, db)
    if features is None:
        # No TLS data available — store a zero-score placeholder so the app
        # always has a prediction record and scores aren't returned as null.
        prediction = MLPrediction(
            app_id=app_id,
            security_score=0.0,
            risk_level="Unknown",
            pqc_readiness_score=0.0,
            confidence=0.0,
            feature_importances={},
        )
        db.add(prediction)
        await db.commit()
        return prediction

    model_data = _load_model()
    pred_data: dict

    if model_data and _model_compatible(model_data) and "score_model" in model_data:
        try:
            scaler      = model_data["scaler"]
            score_model = model_data["score_model"]
            risk_model  = model_data["risk_model"]
            pqc_model   = model_data["pqc_model"]

            X = scaler.transform(features.reshape(1, -1))
            sec_score  = float(np.clip(score_model.predict(X)[0], 0, 100))
            risk_level = risk_model.predict(X)[0]
            pqc_score  = float(np.clip(pqc_model.predict(X)[0], 0, 100))

            importances: dict = {}
            if hasattr(score_model, "feature_importances_"):
                importances = {
                    name: round(float(imp), 4)
                    for name, imp in zip(FEATURE_NAMES, score_model.feature_importances_)
                }

            pred_data = {
                "security_score":      round(sec_score, 1),
                "risk_level":          risk_level,
                "pqc_readiness_score": round(pqc_score, 1),
                "confidence":          0.88,
                "feature_importances": importances,
            }
        except Exception:
            pred_data = _rule_based(features)
    else:
        pred_data = _rule_based(features)

    prediction = MLPrediction(
        app_id=app_id,
        **pred_data,
    )
    db.add(prediction)
    await db.commit()
    return prediction


# ── Retraining ────────────────────────────────────────────────────────────

async def retrain_model() -> dict:
    """
    Train a RandomForest on rule-based predictions for all scanned apps.

    Using the rule-based scorer as labels lets the RF learn non-linear
    interactions between features, producing better generalisation on
    unseen submissions than the linear formula alone.
    """
    try:
        from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import mean_absolute_error, accuracy_score
    except ImportError:
        return {"error": "scikit-learn not installed. Run: pip install scikit-learn"}

    warnings.filterwarnings("ignore")

    from ..database import async_session

    async with async_session() as db:
        # Accept both 'complete' and 'completed' for safety
        apps = (await db.execute(
            select(Application).where(
                Application.scan_status.in_(["complete", "completed"])
            )
        )).scalars().all()

        X_list, y_score, y_risk, y_pqc = [], [], [], []
        for app in apps:
            feats = await _extract_features(app.id, db)
            if feats is None:
                continue
            rb = _rule_based(feats)
            X_list.append(feats)
            y_score.append(rb["security_score"])
            y_risk.append(rb["risk_level"])
            y_pqc.append(rb["pqc_readiness_score"])

    n = len(X_list)
    if n < 20:
        return {"error": f"Need ≥20 scanned apps to train (found {n})"}

    rng = np.random.default_rng(42)
    X = np.array(X_list, dtype=float)
    # Tiny noise avoids degenerate splits in RF
    X += rng.normal(0, 0.005, X.shape)

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    # Stratified split if enough classes
    X_tr, X_te, ys_tr, ys_te, yr_tr, yr_te, yp_tr, yp_te = train_test_split(
        Xs, y_score, y_risk, y_pqc,
        test_size=max(0.10, min(0.20, 50 / n)),
        random_state=42,
    )

    score_model = RandomForestRegressor(
        n_estimators=300, max_depth=10,
        min_samples_leaf=2, max_features="sqrt",
        random_state=42, n_jobs=-1,
    )
    score_model.fit(X_tr, ys_tr)

    risk_model = RandomForestClassifier(
        n_estimators=300, max_depth=10,
        min_samples_leaf=2, max_features="sqrt",
        class_weight="balanced", random_state=42, n_jobs=-1,
    )
    risk_model.fit(X_tr, yr_tr)

    pqc_model = RandomForestRegressor(
        n_estimators=300, max_depth=10,
        min_samples_leaf=2, max_features="sqrt",
        random_state=42, n_jobs=-1,
    )
    pqc_model.fit(X_tr, yp_tr)

    score_mae  = mean_absolute_error(ys_te, score_model.predict(X_te))
    risk_acc   = accuracy_score(yr_te, risk_model.predict(X_te))

    model_data = {
        "score_model":  score_model,
        "risk_model":   risk_model,
        "pqc_model":    pqc_model,
        "scaler":       scaler,
        "feature_names": FEATURE_NAMES,
        "trained_at":   datetime.now(timezone.utc).isoformat(),
        "n_samples":    n,
        "metrics":      {
            "score_mae":    round(score_mae, 2),
            "risk_accuracy": round(risk_acc, 3),
        },
    }

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model_data, f)

    return {
        "n_samples":    n,
        "score_mae":    round(score_mae, 2),
        "risk_accuracy": round(risk_acc, 3),
        "feature_importances": {
            name: round(float(imp), 4)
            for name, imp in zip(FEATURE_NAMES, score_model.feature_importances_)
        },
    }


# ── Bulk re-prediction ────────────────────────────────────────────────────

async def repredict_all(db: AsyncSession) -> int:
    """
    Re-run prediction for every app that has scan data.
    Returns number of apps updated.
    """
    apps = (await db.execute(select(Application))).scalars().all()
    count = 0
    for app in apps:
        result = await predict_for_app(app.id, db)
        if result is not None:
            count += 1
    return count
