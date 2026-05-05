"""
Seed the database from research pipeline outputs.

Populates:
- Applications from target_apps.json (ALL apps)
- Domains and TLS results from pqc_scan_results.jsonl + vulnerability_report.csv
- Vulnerabilities via CVE mapping logic
- ML predictions (rule-based) for every seeded app
- Security warranties for every seeded app
"""

import json
import csv
from pathlib import Path
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from .database import async_session
from .models.db_models import (
    Application, Domain, TLSResult, Vulnerability, MLPrediction, SecurityWarranty,
    KnowledgeBase, Report, SyncConfig,
)
from .config import PIPELINE_DATA_DIR

# Research pipeline data paths
RESEARCH_DIR = Path(__file__).resolve().parent.parent / "pqc-research" / "data"

# ── Inline CVE mapping (so seed doesn't depend on service imports) ────────────
VULN_DB = {
    "legacy_tls": {
        "cve_id": "CVE-2011-3389",
        "severity": "High",
        "cvss": 7.4,
        "desc": "Legacy TLS version (< 1.2) vulnerable to BEAST/POODLE attacks",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2011-3389",
    },
    "weak_cipher_rc4": {
        "cve_id": "CVE-2013-2566",
        "severity": "Medium",
        "cvss": 5.9,
        "desc": "RC4 cipher usage — statistical biases enable plaintext recovery",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2013-2566",
    },
    "weak_cipher_3des": {
        "cve_id": "CVE-2016-2183",
        "severity": "Medium",
        "cvss": 5.3,
        "desc": "3DES cipher (Sweet32) — birthday attack on 64-bit block cipher",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2016-2183",
    },
    "rsa_key_exchange": {
        "cve_id": "CVE-2012-5081",
        "severity": "Medium",
        "cvss": 5.9,
        "desc": "Static RSA key exchange — no forward secrecy, vulnerable to Bleichenbacher",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2012-5081",
    },
    "harvest_now_rsa": {
        "cve_id": "PQC-HARVEST-RSA",
        "severity": "High",
        "cvss": 7.5,
        "desc": "RSA key exchange vulnerable to harvest-now, decrypt-later quantum attack (Shor's algorithm)",
        "ref": "https://csrc.nist.gov/projects/post-quantum-cryptography",
    },
    "harvest_now_ecdh": {
        "cve_id": "PQC-HARVEST-ECDH",
        "severity": "Medium",
        "cvss": 6.5,
        "desc": "ECDH key exchange without PQC hybrid — future quantum risk via Shor's algorithm",
        "ref": "https://csrc.nist.gov/pubs/fips/203/final",
    },
    "no_pqc_support": {
        "cve_id": "PQC-NOT-READY",
        "severity": "Low",
        "cvss": 3.7,
        "desc": "Server does not support post-quantum key exchange (ML-KEM / X25519Kyber768)",
        "ref": "https://csrc.nist.gov/pubs/fips/203/final",
    },
    "short_cert_key": {
        "cve_id": "CWE-326",
        "severity": "Medium",
        "cvss": 5.3,
        "desc": "Certificate key size below recommended minimum (RSA < 2048 or EC < 256)",
        "ref": "https://cwe.mitre.org/data/definitions/326.html",
    },
}


def _assess_tls_result(tls: TLSResult) -> list[dict]:
    """Return list of vulnerability dicts for a TLS result."""
    vulns = []
    ver = tls.tls_version or ""
    cipher = (tls.cipher_suite or "").upper()

    # Protocol vulnerabilities
    if tls.flag_legacy_tls or ver in ("TLS 1.0", "TLS 1.1"):
        vulns.append(VULN_DB["legacy_tls"])

    # Cipher vulnerabilities
    if tls.flag_rc4_or_3des or "RC4" in cipher:
        vulns.append(VULN_DB["weak_cipher_rc4"])
    if "3DES" in cipher or "DES-CBC3" in cipher:
        vulns.append(VULN_DB["weak_cipher_3des"])

    # Key exchange
    if tls.has_rsa_key_exchange:
        vulns.append(VULN_DB["rsa_key_exchange"])
        vulns.append(VULN_DB["harvest_now_rsa"])
    elif tls.has_ecdh and not tls.supports_pqc:
        vulns.append(VULN_DB["harvest_now_ecdh"])

    # PQC readiness
    if not tls.supports_pqc:
        vulns.append(VULN_DB["no_pqc_support"])

    # Certificate key size
    if tls.cert_key_bits and (
        (tls.cert_key_type == "RSA" and tls.cert_key_bits < 2048) or
        (tls.cert_key_type == "EC" and tls.cert_key_bits < 256)
    ):
        vulns.append(VULN_DB["short_cert_key"])

    return vulns


async def seed_demo_users():
    """Create three demo accounts (end_user, app_owner, admin) if they don't exist."""
    from passlib.context import CryptContext
    from .models.db_models import User

    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

    DEMO = [
        {"email": "user@qs.io", "password": "User1234!", "name": "Demo User", "role": "end_user"},
        {"email": "owner@qs.io", "password": "Owner123!", "name": "Demo Owner", "role": "app_owner"},
        {"email": "admin@qs.io", "password": "Admin123!", "name": "Demo Admin", "role": "admin"},
    ]

    async with async_session() as db:
        for d in DEMO:
            existing = (await db.execute(select(User).where(User.email == d["email"]))).scalar_one_or_none()
            if not existing:
                db.add(User(
                    email=d["email"],
                    password_hash=pwd_ctx.hash(d["password"]),
                    name=d["name"],
                    role=d["role"],
                ))
        await db.commit()
    print("[SEED] Demo users ready.")


async def seed_from_pipeline():
    """Seed the database if it's empty, using research pipeline data."""
    async with async_session() as db:
        count = (await db.execute(select(func.count(Application.id)))).scalar()
        if count and count > 0:
            return  # Already seeded

        # Try both possible data locations
        data_dir = RESEARCH_DIR if RESEARCH_DIR.exists() else Path(PIPELINE_DATA_DIR)
        if not data_dir.exists():
            print("[SEED] No research data directory found, skipping seed.")
            return

        target_apps_path = data_dir / "target_apps.json"
        scan_jsonl_path = data_dir / "pqc_scan_results.jsonl"
        vuln_csv_path = data_dir / "vulnerability_report.csv"

        if not target_apps_path.exists():
            print("[SEED] target_apps.json not found, skipping seed.")
            return

        print("[SEED] Seeding database from research pipeline data...")

        # Load target apps
        with open(target_apps_path, encoding="utf-8") as f:
            apps_data = json.load(f)

        # Load scan results indexed by domain
        scan_by_domain = {}
        if scan_jsonl_path.exists():
            with open(scan_jsonl_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            r = json.loads(line)
                            scan_by_domain[r.get("domain", "")] = r
                        except json.JSONDecodeError:
                            pass

        # Load vulnerability data indexed by domain
        vuln_by_domain = {}
        if vuln_csv_path.exists():
            with open(vuln_csv_path, encoding="utf-8", newline="") as f:
                for row in csv.DictReader(f):
                    vuln_by_domain[row.get("domain", "")] = row

        # Seed ALL apps (no limit)
        seeded = 0
        now = datetime.now(timezone.utc)
        for app_data in apps_data:
            app = Application(
                package_name=app_data["appId"],
                app_name=app_data.get("title"),
                category=app_data.get("genre"),
                install_count=_parse_installs(app_data.get("installs")),
                rating=app_data.get("score"),
                scan_status="completed",
                is_public=True,
            )
            db.add(app)
            await db.flush()

            app_tls_results = []

            # Add domains
            for dom_name in app_data.get("domains", [])[:30]:
                domain = Domain(
                    app_id=app.id,
                    domain=dom_name,
                    is_third_party=_is_third_party(dom_name, app_data.get("appId", "")),
                )
                db.add(domain)
                await db.flush()

                # Add TLS result if scan data exists
                scan = scan_by_domain.get(dom_name)
                if scan:
                    tls_ver = scan.get("tls_version")
                    if tls_ver:
                        tls_ver = {
                            "TLSv1.3": "TLS 1.3", "TLSv1.2": "TLS 1.2",
                            "TLSv1.1": "TLS 1.1", "TLSv1.0": "TLS 1.0",
                            "TLSv1": "TLS 1.0",
                        }.get(tls_ver, tls_ver)

                    cipher = scan.get("cipher_name")
                    kex = "ECDHE" if cipher and "ECDHE" in cipher.upper() else (
                        "DHE" if cipher and "DHE" in cipher.upper() else (
                        "RSA" if cipher and ("TLS_RSA_" in cipher.upper() or "_RSA_WITH_" in cipher.upper()) else None
                    ))

                    vuln_data = vuln_by_domain.get(dom_name, {})

                    tls_result = TLSResult(
                        domain_id=domain.id,
                        tls_version=tls_ver,
                        cipher_suite=cipher,
                        key_exchange=kex,
                        cert_issuer=scan.get("cert_issuer"),
                        cert_key_type=scan.get("cert_key_type"),
                        cert_key_bits=scan.get("cert_key_bits"),
                        supports_pqc=scan.get("pqc_capable", False),
                        pqc_group=scan.get("hrr_group_name"),
                        has_ecdh="ECDH" in (cipher or "").upper(),
                        has_rsa_key_exchange=scan.get("flag_rsa_key_exchange", False),
                        flag_legacy_tls=scan.get("flag_legacy_tls", False),
                        flag_rc4_or_3des=scan.get("flag_rc4_or_3des", False),
                        cipher_strength_score=_safe_float(vuln_data.get("security_score")),
                        quantum_risk_score=_safe_float(vuln_data.get("quantum_risk_score")),
                        security_score=_safe_float(vuln_data.get("security_score")),
                        scan_error=scan.get("error"),
                    )
                    db.add(tls_result)
                    await db.flush()
                    app_tls_results.append(tls_result)

                    # ── Map CVEs for this TLS result ──
                    for v in _assess_tls_result(tls_result):
                        db.add(Vulnerability(
                            tls_result_id=tls_result.id,
                            cve_id=v["cve_id"],
                            severity=v["severity"],
                            cvss_score=v["cvss"],
                            description=v["desc"],
                            reference_url=v["ref"],
                        ))

            # ── ML prediction (rule-based) for the app ──
            if app_tls_results:
                scores = [t.security_score or 0 for t in app_tls_results]
                avg_score = sum(scores) / len(scores) if scores else 0
                pqc_count = sum(1 for t in app_tls_results if t.supports_pqc)
                pqc_pct = (pqc_count / len(app_tls_results) * 100) if app_tls_results else 0
                risk = (
                    "Low" if avg_score >= 75 else
                    "Medium" if avg_score >= 50 else
                    "High" if avg_score >= 25 else
                    "Critical"
                )
                db.add(MLPrediction(
                    app_id=app.id,
                    security_score=round(avg_score, 1),
                    risk_level=risk,
                    pqc_readiness_score=round(pqc_pct, 1),
                    confidence=0.85,
                    feature_importances={"tls_version": 0.25, "cipher_strength": 0.2, "pqc_support": 0.2, "key_exchange": 0.15, "cert_quality": 0.1, "vuln_count": 0.1},
                ))

                # ── Security warranty ──
                if avg_score >= 75 and pqc_pct >= 50:
                    status = "Certified"
                    justification = f"Security score {avg_score:.0f}/100, PQC readiness {pqc_pct:.0f}%. Meets quantum-safe threshold."
                elif avg_score >= 50:
                    status = "Conditional"
                    justification = f"Security score {avg_score:.0f}/100, PQC readiness {pqc_pct:.0f}%. Partial compliance - improvements recommended."
                else:
                    status = "Not Certified"
                    justification = f"Security score {avg_score:.0f}/100, PQC readiness {pqc_pct:.0f}%. Significant security gaps detected."

                db.add(SecurityWarranty(
                    app_id=app.id,
                    status=status,
                    expires_at=now + timedelta(days=90),
                    justification=justification,
                ))

            seeded += 1
            if seeded % 100 == 0:
                await db.commit()
                print(f"[SEED] ... {seeded} apps seeded so far")

        await db.commit()
        print(f"[SEED] Seeded {seeded} applications with TLS results, vulnerabilities, ML predictions, and warranties.")


THIRD_PARTY_KEYWORDS = {
    "google", "gstatic", "googleapis", "facebook", "fbcdn", "twitter",
    "amazon", "amazonaws", "cloudfront", "akamai", "fastly", "cloudflare",
    "doubleclick", "crashlytics", "firebase", "appsflyer", "adjust",
    "branch", "mixpanel", "segment", "newrelic", "datadog", "sentry",
}


def _is_third_party(domain: str, package_name: str) -> bool:
    d = domain.lower()
    # Check known third-party keywords
    if any(kw in d for kw in THIRD_PARTY_KEYWORDS):
        return True
    # If domain doesn't match the app's reverse-domain, treat as third party
    parts = package_name.lower().split(".")
    if len(parts) >= 2:
        tld_domain = f"{parts[1]}.{parts[0]}"
        if tld_domain not in d and parts[1] not in d:
            return True
    return False


def _parse_installs(val) -> int:
    if not val:
        return 0
    if isinstance(val, int):
        return val
    # Handle "10,000,000+" format
    s = str(val).replace(",", "").replace("+", "").strip()
    try:
        return int(s)
    except ValueError:
        return 0


def _safe_float(val) -> float:
    try:
        return float(val) if val not in ("", None) else 0.0
    except (ValueError, TypeError):
        return 0.0


def _score_from_csv_app(row: dict) -> float:
    any_tls13 = str(row.get("any_tls13", "False")).strip().lower() == "true"
    any_tls12 = str(row.get("any_tls12", "False")).strip().lower() == "true"
    pqc_capable = str(row.get("pqc_capable", "False")).strip().lower() == "true"
    try:
        scanned = int(row.get("scanned_domains", 0) or 0)
    except (ValueError, TypeError):
        scanned = 0
    pqc_raw = str(row.get("pqc_domains", ""))
    pqc_count = len([d for d in pqc_raw.split(";") if d.strip()]) if pqc_raw.strip() else 0

    base = 40.0
    if any_tls13:
        base += 20.0
    elif any_tls12:
        base += 8.0
    if pqc_capable:
        base += 20.0
    if scanned > 0:
        base += (pqc_count / scanned) * 10.0
    return round(min(100.0, base), 1)


def _pqc_score_from_csv_app(row: dict) -> float:
    pqc_capable = str(row.get("pqc_capable", "False")).strip().lower() == "true"
    if not pqc_capable:
        return 20.0
    try:
        scanned = int(row.get("scanned_domains", 0) or 0)
    except (ValueError, TypeError):
        scanned = 0
    pqc_raw = str(row.get("pqc_domains", ""))
    pqc_count = len([d for d in pqc_raw.split(";") if d.strip()]) if pqc_raw.strip() else 0
    if scanned <= 0:
        return 60.0
    return round(min(100.0, (pqc_count / scanned) * 100.0), 1)


async def repair_missing_predictions():
    """Create MLPrediction + SecurityWarranty for apps that are missing them (idempotent repair)."""
    csv_path = RESEARCH_DIR / "report_per_app.csv"
    if not csv_path.exists():
        csv_path = Path(PIPELINE_DATA_DIR) / "report_per_app.csv"

    csv_by_app: dict[str, dict] = {}
    if csv_path.exists():
        with open(csv_path, encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                aid = row.get("appId", "").strip()
                if aid:
                    csv_by_app[aid] = row

    async with async_session() as db:
        # Apps that have no MLPrediction row
        subq = select(MLPrediction.app_id)
        rows = (await db.execute(
            select(Application).where(Application.id.not_in(subq))
        )).scalars().all()

        if not rows:
            print("[SEED] All apps have predictions — repair not needed.")
            return

        print(f"[SEED] Repairing {len(rows)} apps missing predictions…")
        now = datetime.now(timezone.utc)
        repaired = 0

        for app in rows:
            csv_row = csv_by_app.get(app.package_name)
            if csv_row:
                sec_score = _score_from_csv_app(csv_row)
                pqc_score = _pqc_score_from_csv_app(csv_row)
            else:
                sec_score = 50.0
                pqc_score = 30.0

            risk = (
                "Low" if sec_score >= 75 else
                "Medium" if sec_score >= 50 else
                "High" if sec_score >= 25 else
                "Critical"
            )
            db.add(MLPrediction(
                app_id=app.id,
                security_score=sec_score,
                risk_level=risk,
                pqc_readiness_score=pqc_score,
                confidence=0.75,
                feature_importances={"tls_version": 0.25, "cipher_strength": 0.2, "pqc_support": 0.2, "key_exchange": 0.15, "cert_quality": 0.1, "vuln_count": 0.1},
            ))

            # Warranty if also missing
            has_w = bool((await db.execute(
                select(func.count(SecurityWarranty.id)).where(SecurityWarranty.app_id == app.id)
            )).scalar())
            if not has_w:
                if sec_score >= 75 and pqc_score >= 50:
                    status, just = "Certified", f"Score {sec_score:.0f}/100, PQC {pqc_score:.0f}%. Meets quantum-safe threshold."
                elif sec_score >= 50:
                    status, just = "Conditional", f"Score {sec_score:.0f}/100, PQC {pqc_score:.0f}%. Partial compliance — improvements recommended."
                else:
                    status, just = "Not Certified", f"Score {sec_score:.0f}/100, PQC {pqc_score:.0f}%. Significant security gaps detected."
                db.add(SecurityWarranty(
                    app_id=app.id,
                    status=status,
                    expires_at=now + timedelta(days=90),
                    justification=just,
                ))

            repaired += 1
            if repaired % 200 == 0:
                await db.commit()
                print(f"[SEED] … {repaired} repaired so far")

        await db.commit()
        print(f"[SEED] Repair complete — {repaired} apps updated.")


async def seed_static_data():
    """Seed knowledge bases, sync config, and reports if not already present."""
    async with async_session() as db:
        # ── Knowledge Bases ────────────────────────────────────────────────
        kb_count = (await db.execute(select(func.count(KnowledgeBase.id)))).scalar()
        if not kb_count:
            now = datetime.now(timezone.utc)
            knowledge_bases = [
                KnowledgeBase(
                    name="CVE Vulnerability Feed",
                    type="NVD CVE Feed",
                    records=248312,
                    size="1.2 GB",
                    status="synced",
                    source="nvd.nist.gov",
                    last_sync=now - timedelta(hours=4),
                ),
                KnowledgeBase(
                    name="PQC Algorithm Registry",
                    type="Internal Registry",
                    records=142,
                    size="4 MB",
                    status="synced",
                    source="Internal",
                    last_sync=now - timedelta(hours=22),
                ),
                KnowledgeBase(
                    name="TLS Cipher Suites",
                    type="IANA Registry",
                    records=534,
                    size="2 MB",
                    status="synced",
                    source="iana.org",
                    last_sync=now - timedelta(days=2),
                ),
                KnowledgeBase(
                    name="Certificate Authorities",
                    type="CA Bundle",
                    records=1821,
                    size="18 MB",
                    status="synced",
                    source="Mozilla CA Store",
                    last_sync=now - timedelta(minutes=30),
                ),
            ]
            for kb in knowledge_bases:
                db.add(kb)

        # ── Sync Config ────────────────────────────────────────────────────
        cfg = (await db.execute(select(SyncConfig).where(SyncConfig.id == 1))).scalar_one_or_none()
        if not cfg:
            db.add(SyncConfig(id=1, sync_interval="6h", backup_retention="30d"))

        # ── Reports ────────────────────────────────────────────────────────
        report_count = (await db.execute(select(func.count(Report.id)))).scalar()
        if not report_count:
            now = datetime.now(timezone.utc)
            reports = [
                Report(title="Weekly Security Digest — Apr 7", date=now.replace(day=7, month=4), type="weekly", apps_count=14, status="ready"),
                Report(title="Weekly Security Digest — Mar 31", date=now.replace(day=31, month=3), type="weekly", apps_count=11, status="ready"),
                Report(title="Monthly Overview — March 2026", date=now.replace(day=1, month=3), type="monthly", apps_count=47, status="ready"),
                Report(title="Quarterly PQC Readiness — Q1 2026", date=now.replace(day=1, month=1), type="quarterly", apps_count=132, status="ready"),
                Report(title="Custom Audit — Finance Apps", date=now.replace(day=2, month=4), type="custom", apps_count=8, status="ready"),
                Report(title="Monthly Overview — April 2026", date=now.replace(day=1, month=4), type="monthly", apps_count=0, status="generating"),
            ]
            for r in reports:
                db.add(r)

        await db.commit()
    print("[SEED] Static data (knowledge bases, reports) ready.")
