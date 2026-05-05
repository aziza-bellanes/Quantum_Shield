"""
NVD (National Vulnerability Database) API v2 client.

Fetches live CVE data from https://services.nvd.nist.gov/rest/json/cves/2.0
and provides an in-memory cache with a 24-hour TTL so we don't hammer the API.

Usage
-----
from .nvd_client import get_cves_for_keyword, enrich_vuln_entry

cves = await get_cves_for_keyword("TLS 1.0 BEAST")
"""

import asyncio
import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── NVD API v2 base URL ──────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Optional: set NVD_API_KEY env var to get higher rate limits (50 req/30s vs 5/30s)
import os
_API_KEY = os.getenv("NVD_API_KEY", "")

# ── In-memory cache: keyword → {"ts": float, "cves": list[dict]} ─────────────
_cache: dict[str, dict] = {}
_CACHE_TTL = 86_400  # 24 hours


# ── Keyword map: our internal vuln keys → NVD keyword queries ────────────────
KEYWORD_MAP: dict[str, str] = {
    "tls_1.0":         "TLS 1.0 BEAST POODLE",
    "tls_1.1":         "TLS 1.1 deprecated RFC 8996",
    "rc4":             "RC4 cipher Bar Mitzvah",
    "3des":            "3DES SWEET32 birthday attack",
    "cbc_mode":        "Lucky13 CBC TLS",
    "export_cipher":   "FREAK LOGJAM export cipher",
    "rsa_key_exchange":"RSA key exchange forward secrecy",
    "rsa_1024":        "RSA 1024 weak key",
    "harvest_now_rsa": "quantum RSA Shor harvest decrypt",
    "harvest_now_ecdh":"quantum ECDH harvest decrypt",
    "no_pqc_support":  "post-quantum TLS ML-KEM FIPS 203",
}


async def get_cves_for_keyword(keyword: str, max_results: int = 5) -> list[dict]:
    """
    Fetch CVEs from NVD matching *keyword*.  Returns a list of enriched dicts:
    {
        "cve_id": str,
        "description": str,
        "cvss_score": float | None,
        "severity": str,           # LOW / MEDIUM / HIGH / CRITICAL
        "reference_url": str,
    }
    Results are cached for 24 hours.
    """
    cache_key = f"{keyword}:{max_results}"
    cached = _cache.get(cache_key)
    if cached and (time.time() - cached["ts"]) < _CACHE_TTL:
        return cached["cves"]

    try:
        result = await _fetch_nvd(keyword, max_results)
        _cache[cache_key] = {"ts": time.time(), "cves": result}
        return result
    except Exception as exc:
        logger.warning("NVD API call failed for %r: %s", keyword, exc)
        return []


async def enrich_vuln_entry(vuln_key: str) -> list[dict]:
    """
    For a known VULN_DB key (e.g. "tls_1.0"), return fresh CVE data from NVD.
    Falls back to an empty list if NVD is unreachable.
    """
    keyword = KEYWORD_MAP.get(vuln_key)
    if not keyword:
        return []
    return await get_cves_for_keyword(keyword)


async def fetch_cves_for_cve_id(cve_id: str) -> Optional[dict]:
    """
    Fetch full details for a specific CVE ID (e.g. "CVE-2014-3566").
    Returns enriched dict or None if not found.
    """
    cache_key = f"id:{cve_id}"
    cached = _cache.get(cache_key)
    if cached and (time.time() - cached["ts"]) < _CACHE_TTL:
        return cached["cves"][0] if cached["cves"] else None

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            headers = {"apiKey": _API_KEY} if _API_KEY else {}
            resp = await client.get(
                NVD_API_BASE,
                params={"cveId": cve_id},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                parsed = [_parse_cve_item(v) for v in vulns]
                _cache[cache_key] = {"ts": time.time(), "cves": parsed}
                return parsed[0]
    except Exception as exc:
        logger.warning("NVD lookup for %s failed: %s", cve_id, exc)

    return None


async def prefetch_all_vuln_keys() -> None:
    """
    Pre-warm the cache for all VULN_DB keys.
    Call this at startup (fire-and-forget) so first scans don't wait.
    """
    tasks = [enrich_vuln_entry(key) for key in KEYWORD_MAP]
    await asyncio.gather(*tasks, return_exceptions=True)
    logger.info("NVD cache pre-warmed for %d vulnerability keys", len(KEYWORD_MAP))


# ── Internal helpers ─────────────────────────────────────────────────────────

async def _fetch_nvd(keyword: str, max_results: int) -> list[dict]:
    """Hit NVD API v2 and parse the response."""
    params: dict = {"keywordSearch": keyword, "resultsPerPage": max_results}
    headers: dict = {}
    if _API_KEY:
        headers["apiKey"] = _API_KEY

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(NVD_API_BASE, params=params, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    vulns = data.get("vulnerabilities", [])
    return [_parse_cve_item(v) for v in vulns]


def _parse_cve_item(item: dict) -> dict:
    """
    Parse a single NVD vulnerability item into our standard dict.
    NVD v2 structure: item["cve"] contains all the data.
    """
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # Description: prefer English
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if not desc:
        descs = cve.get("descriptions", [])
        desc = descs[0].get("value", "") if descs else ""

    # CVSS score: prefer v3.1 > v3.0 > v2
    cvss_score: Optional[float] = None
    severity = "Medium"
    metrics = cve.get("metrics", {})

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is not None:
                cvss_score = float(score)
                sev = cvss_data.get("baseSeverity") or metric_list[0].get("baseSeverity", "")
                severity = _normalise_severity(sev, cvss_score)
            break

    # Reference URL
    refs = cve.get("references", [])
    ref_url = refs[0].get("url", f"https://nvd.nist.gov/vuln/detail/{cve_id}") if refs else \
              f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return {
        "cve_id": cve_id,
        "description": desc[:500] if desc else f"See {ref_url}",
        "cvss_score": cvss_score,
        "severity": severity,
        "reference_url": ref_url,
    }


def _normalise_severity(raw: str, score: Optional[float]) -> str:
    """Map NVD severity string or CVSS score to our four-level scale."""
    r = raw.upper()
    if r in ("CRITICAL",):
        return "Critical"
    if r in ("HIGH",):
        return "High"
    if r in ("MEDIUM",):
        return "Medium"
    if r in ("LOW",):
        return "Low"
    # Fall back to numeric
    if score is not None:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"
    return "Medium"
