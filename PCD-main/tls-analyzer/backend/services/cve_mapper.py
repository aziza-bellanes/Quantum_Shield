"""
CVE mapping module — built on vulnerability_analysis.py.

Maps TLS scan results to known CVEs using a two-layer approach:
  1. Static VULN_DB — fast, offline, always available (from research pipeline)
  2. Live NVD API v2 — enriches static entries with fresh CVSS scores and
     surfaces additional CVEs that NVD has published since the static DB was written.

The live layer is async and best-effort: if NVD is unreachable the static layer
still works, so scans are never blocked by network issues.
"""

import asyncio
import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.db_models import Domain, TLSResult, Vulnerability

logger = logging.getLogger(__name__)

# ── Static CVE/vulnerability database (from vulnerability_analysis.py) ───────
# Extended with FIPS references for PQC compliance reporting.
# These are our well-known, curated entries. NVD enrichment runs on top of them.

VULN_DB: dict[str, dict] = {
    "tls_1.0": {
        "cves": ["CVE-2011-3389", "CVE-2014-3566"],
        "cvss": 5.9,
        "severity": "Medium",
        "description": "TLS 1.0 vulnerable to BEAST (CBC) and POODLE attacks. "
                       "Deprecated by RFC 8996.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2011-3389",
    },
    "tls_1.1": {
        "cves": ["CVE-2011-3389"],
        "cvss": 5.9,
        "severity": "Medium",
        "description": "TLS 1.1 deprecated by RFC 8996, limited cipher support.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2011-3389",
    },
    "rc4": {
        "cves": ["CVE-2013-2566", "CVE-2015-2808"],
        "cvss": 5.9,
        "severity": "Medium",
        "description": "RC4 stream cipher with known statistical biases (Bar Mitzvah attack).",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2013-2566",
    },
    "3des": {
        "cves": ["CVE-2016-2183"],
        "cvss": 5.3,
        "severity": "Medium",
        "description": "3DES vulnerable to SWEET32 birthday attack (64-bit block).",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2016-2183",
    },
    "cbc_mode": {
        "cves": ["CVE-2013-0169"],
        "cvss": 3.7,
        "severity": "Low",
        "description": "CBC mode susceptible to Lucky13 timing attack.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2013-0169",
    },
    "export_cipher": {
        "cves": ["CVE-2015-0204", "CVE-2015-4000"],
        "cvss": 7.4,
        "severity": "High",
        "description": "Export-grade cipher with ≤512-bit keys (FREAK/LOGJAM).",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-0204",
    },
    "rsa_key_exchange": {
        "cves": ["CVE-2012-4929", "CVE-2018-12404"],
        "cvss": 5.9,
        "severity": "Medium",
        "description": "Static RSA key exchange lacks forward secrecy. Vulnerable to "
                       "harvest-now-decrypt-later with future quantum computers.",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-12404",
    },
    "rsa_1024": {
        "cves": [],
        "cvss": 5.3,
        "severity": "Medium",
        "description": "RSA key ≤1024 bits — factorable with commodity hardware.",
        "ref": "https://www.nist.gov/pqcrypto",
    },
    "harvest_now_rsa": {
        "cves": [],
        "cvss": 6.1,
        "severity": "High",
        "description": "RSA key exchange or certificate — vulnerable to harvest-now-decrypt-later "
                       "attack. A cryptographically relevant quantum computer (CRQC) running "
                       "Shor's algorithm could decrypt captured traffic. "
                       "Ref: FIPS 203 (ML-KEM), NIST PQC transition guidance.",
        "ref": "https://csrc.nist.gov/pubs/fips/203/final",
    },
    "harvest_now_ecdh": {
        "cves": [],
        "cvss": 5.4,
        "severity": "Medium",
        "description": "ECDH key exchange — vulnerable to harvest-now-decrypt-later with CRQC. "
                       "Non-hybrid ECDH does not provide quantum resistance. "
                       "Ref: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA).",
        "ref": "https://csrc.nist.gov/pubs/fips/203/final",
    },
    "no_pqc_support": {
        "cves": [],
        "cvss": 4.0,
        "severity": "Medium",
        "description": "No post-quantum key exchange support detected. Domain is not "
                       "protected against quantum threats. Deploy ML-KEM-768 hybrid "
                       "key exchange per FIPS 203. Ref: FIPS 205 (SLH-DSA).",
        "ref": "https://csrc.nist.gov/pubs/fips/203/final",
    },
}


# ── Public API ───────────────────────────────────────────────────────────────

async def map_cves_for_app(app_id: int, db: AsyncSession) -> None:
    """
    Assess all TLS results for an app and create Vulnerability records.

    Two phases:
      Phase 1 — static VULN_DB mapping (synchronous, always runs)
      Phase 2 — NVD live enrichment (async, best-effort)
    """
    tls_results = (await db.execute(
        select(TLSResult).join(Domain).where(Domain.app_id == app_id)
    )).scalars().all()

    # Track which (tls_result_id, cve_id) pairs we've already inserted so we
    # don't create duplicates when the NVD layer adds CVEs already in VULN_DB.
    inserted: set[tuple[int, Optional[str]]] = set()

    # ── Phase 1: static mapping ──────────────────────────────────────────────
    for tls in tls_results:
        static_vulns = _assess_tls_result(tls)
        for v in static_vulns:
            if v["cves"]:
                for cve in v["cves"]:
                    key = (tls.id, cve)
                    if key not in inserted:
                        db.add(Vulnerability(
                            tls_result_id=tls.id,
                            cve_id=cve,
                            severity=v["severity"],
                            cvss_score=v["cvss"],
                            description=v["description"],
                            reference_url=v["ref"],
                        ))
                        inserted.add(key)
            else:
                # Vulnerability with no CVE ID (quantum-specific entries)
                key = (tls.id, v["description"][:80])  # type: ignore[assignment]
                if key not in inserted:
                    db.add(Vulnerability(
                        tls_result_id=tls.id,
                        cve_id=None,
                        severity=v["severity"],
                        cvss_score=v["cvss"],
                        description=v["description"],
                        reference_url=v["ref"],
                    ))
                    inserted.add(key)  # type: ignore[arg-type]

    await db.commit()

    # ── Phase 2: NVD live enrichment (fire-and-forget per tls result) ────────
    try:
        await _enrich_with_live_nvd(tls_results, db, inserted)
    except Exception as exc:
        # Never fail a scan because of NVD connectivity issues
        logger.warning("NVD enrichment failed for app %d: %s", app_id, exc)


async def _enrich_with_live_nvd(
    tls_results: list[TLSResult],
    db: AsyncSession,
    already_inserted: set,
) -> None:
    """
    For each triggered VULN_DB key, fetch fresh CVE data from NVD and add
    any new CVEs (or update CVSS scores) not already in the static DB.
    """
    from .nvd_client import enrich_vuln_entry, fetch_cves_for_cve_id

    triggered_keys: set[str] = set()
    for tls in tls_results:
        triggered_keys.update(_triggered_vuln_keys(tls))

    if not triggered_keys:
        return

    # Fetch live data for all triggered keys concurrently
    tasks = {key: enrich_vuln_entry(key) for key in triggered_keys}
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    live_by_key: dict[str, list[dict]] = {}
    for key, res in zip(tasks.keys(), results):
        if isinstance(res, list):
            live_by_key[key] = res

    added = 0
    for tls in tls_results:
        keys = _triggered_vuln_keys(tls)
        for key in keys:
            live_cves = live_by_key.get(key, [])
            for cve_data in live_cves:
                cve_id = cve_data.get("cve_id")
                if not cve_id:
                    continue
                pair = (tls.id, cve_id)
                if pair in already_inserted:
                    continue
                # Check whether this CVE ID is already in the static list for this key
                static_cves = VULN_DB.get(key, {}).get("cves", [])
                if cve_id in static_cves:
                    continue
                db.add(Vulnerability(
                    tls_result_id=tls.id,
                    cve_id=cve_id,
                    severity=cve_data.get("severity", "Medium"),
                    cvss_score=cve_data.get("cvss_score"),
                    description=cve_data.get("description", ""),
                    reference_url=cve_data.get("reference_url", ""),
                ))
                already_inserted.add(pair)
                added += 1

    if added:
        await db.commit()
        logger.info("NVD enrichment added %d supplemental CVE records", added)


# ── Static assessment logic ───────────────────────────────────────────────────

def _assess_tls_result(tls: TLSResult) -> list[dict]:
    """Run static vulnerability checks against a single TLS result."""
    vulns = []
    cipher = (tls.cipher_suite or "").upper()
    tls_ver = (tls.tls_version or "").upper()

    # Protocol checks
    if "1.0" in tls_ver:
        vulns.append(VULN_DB["tls_1.0"])
    elif "1.1" in tls_ver:
        vulns.append(VULN_DB["tls_1.1"])

    # Cipher checks
    if "RC4" in cipher:
        vulns.append(VULN_DB["rc4"])
    if "3DES" in cipher or "DES-CBC3" in cipher:
        vulns.append(VULN_DB["3des"])
    if "CBC" in cipher and "RC4" not in cipher and "3DES" not in cipher:
        vulns.append(VULN_DB["cbc_mode"])
    if "EXPORT" in cipher:
        vulns.append(VULN_DB["export_cipher"])

    # Key exchange
    if tls.has_rsa_key_exchange:
        vulns.append(VULN_DB["rsa_key_exchange"])

    # Certificate key size
    if not tls.scan_error:
        if tls.cert_key_type and "RSA" in tls.cert_key_type.upper():
            if tls.cert_key_bits and tls.cert_key_bits <= 1024:
                vulns.append(VULN_DB["rsa_1024"])

    # Quantum-specific (skip if the scan errored — no real TLS data)
    if not tls.scan_error:
        if tls.has_rsa_key_exchange:
            vulns.append(VULN_DB["harvest_now_rsa"])
        elif "ECDHE" in cipher or cipher.startswith("TLS_"):
            vulns.append(VULN_DB["harvest_now_ecdh"])

        if not tls.supports_pqc and tls_ver:
            vulns.append(VULN_DB["no_pqc_support"])

    return vulns


def _triggered_vuln_keys(tls: TLSResult) -> set[str]:
    """Return the VULN_DB keys that apply to this TLS result (for NVD lookup)."""
    keys: set[str] = set()
    cipher = (tls.cipher_suite or "").upper()
    tls_ver = (tls.tls_version or "").upper()

    if "1.0" in tls_ver:
        keys.add("tls_1.0")
    elif "1.1" in tls_ver:
        keys.add("tls_1.1")

    if "RC4" in cipher:
        keys.add("rc4")
    if "3DES" in cipher or "DES-CBC3" in cipher:
        keys.add("3des")
    if "CBC" in cipher:
        keys.add("cbc_mode")
    if "EXPORT" in cipher:
        keys.add("export_cipher")

    if tls.has_rsa_key_exchange:
        keys.add("rsa_key_exchange")
        keys.add("harvest_now_rsa")
    elif "ECDHE" in cipher or cipher.startswith("TLS_"):
        keys.add("harvest_now_ecdh")

    if not tls.supports_pqc and tls_ver:
        keys.add("no_pqc_support")

    return keys
