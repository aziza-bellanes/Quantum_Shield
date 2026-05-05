"""
TLS analysis pipeline service — built on pqc_tls_scanner.py.

Wraps the research pipeline's scan_domain(), assess_weak_configs(), and
PQC probe logic into an async background task that stores results in
PostgreSQL.
"""

import asyncio
import socket
import ssl
import struct
import os
import json
import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import async_session
from ..models.db_models import Application, Domain, TLSResult
from ..config import SCAN_TIMEOUT, SCAN_CONCURRENCY

# ── Import core logic from research pipeline ────────────────────────────
# We re-use the exact same functions from the research pipeline, adapted
# for service use. The key functions are inlined here to avoid import-path
# issues with the research folder structure.

# PQC group IDs (from pqc_tls_scanner.py)
PQC_GROUPS: dict[int, str] = {
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
    0x11EC: "X25519MLKEM768",
    0x11EB: "SecP256r1MLKEM768",
    0x11ED: "X25519MLKEM1024",
}

CLASSIC_GROUPS: dict[int, str] = {
    0x001D: "x25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
}

ALL_GROUPS = {**PQC_GROUPS, **CLASSIC_GROUPS}


# ── ClientHello builder (from pqc_tls_scanner.py) ──────────────────────

def _pack_extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data

def _sni_ext(hostname: str) -> bytes:
    name = hostname.encode()
    sni_data = struct.pack("!H", len(name) + 3) + struct.pack("!BH", 0, len(name)) + name
    return _pack_extension(0x0000, sni_data)

def _supported_versions_ext() -> bytes:
    data = struct.pack("!B", 4) + b"\x03\x04\x03\x03"
    return _pack_extension(0x002B, data)

def _supported_groups_ext() -> bytes:
    groups = list(PQC_GROUPS.keys()) + [0x001D, 0x0017, 0x0018]
    data = struct.pack("!H", len(groups) * 2)
    for g in groups:
        data += struct.pack("!H", g)
    return _pack_extension(0x000A, data)

def _sig_algs_ext() -> bytes:
    algs = [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809,
            0x0401, 0x0501, 0x0601, 0x0201]
    data = struct.pack("!H", len(algs) * 2)
    for a in algs:
        data += struct.pack("!H", a)
    return _pack_extension(0x000D, data)

def _key_share_ext() -> bytes:
    pub = os.urandom(32)
    entry = struct.pack("!HH", 0x001D, len(pub)) + pub
    data = struct.pack("!H", len(entry)) + entry
    return _pack_extension(0x0033, data)

def _build_client_hello(hostname: str) -> bytes:
    random_bytes = os.urandom(32)
    session_id = b""
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F]
    cipher_bytes = struct.pack("!H", len(ciphers) * 2)
    for c in ciphers:
        cipher_bytes += struct.pack("!H", c)
    compression = b"\x01\x00"
    extensions = (
        _sni_ext(hostname) + _supported_versions_ext() + _supported_groups_ext() +
        _sig_algs_ext() + _key_share_ext() +
        _pack_extension(0x0010, b"\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31")
    )
    body = (b"\x03\x03" + random_bytes + struct.pack("!B", len(session_id)) + session_id +
            cipher_bytes + compression + struct.pack("!H", len(extensions)) + extensions)
    hs = struct.pack("!B", 0x01) + struct.pack("!I", len(body))[1:] + body
    return struct.pack("!BHH", 0x16, 0x0301, len(hs)) + hs


def _read_tls_record(sock: socket.socket) -> tuple[int, bytes]:
    hdr = b""
    while len(hdr) < 5:
        chunk = sock.recv(5 - len(hdr))
        if not chunk:
            raise ConnectionError("Connection closed")
        hdr += chunk
    content_type, _, length = struct.unpack("!BHH", hdr)
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Truncated TLS record")
        data += chunk
    return content_type, data


def _parse_server_hello(data: bytes) -> dict:
    result = {"type": "unknown", "selected_group": None, "pqc_group": False,
              "selected_group_name": None}
    if len(data) < 4 or data[0] != 2:
        return result
    pos = 4
    if pos + 2 > len(data):
        return result
    pos += 2  # legacy_ver

    HRR_MAGIC = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
    if pos + 32 > len(data):
        return result
    rand = data[pos:pos+32]
    pos += 32
    is_hrr = (rand == HRR_MAGIC)
    result["type"] = "HelloRetryRequest" if is_hrr else "ServerHello"

    if pos >= len(data):
        return result
    sid_len = data[pos]; pos += 1 + sid_len

    if pos + 2 > len(data):
        return result
    pos += 3  # cipher (2) + compression (1)

    if pos + 2 > len(data):
        return result
    ext_len = struct.unpack("!H", data[pos:pos+2])[0]
    pos += 2
    end = pos + ext_len
    while pos + 4 <= end:
        ext_type, ext_len2 = struct.unpack("!HH", data[pos:pos+4])
        pos += 4
        ext_data = data[pos:pos+ext_len2]
        pos += ext_len2
        if ext_type == 0x0033:
            if len(ext_data) >= 2:
                grp = struct.unpack("!H", ext_data[:2])[0]
                result["selected_group"] = grp
                result["selected_group_name"] = ALL_GROUPS.get(grp, f"unknown(0x{grp:04X})")
                result["pqc_group"] = grp in PQC_GROUPS
    return result


def _infer_key_from_der(der: bytes) -> tuple[Optional[str], Optional[int]]:
    if b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" in der:
        return "RSA", None
    if b"\x2a\x86\x48\xce\x3d\x02\x01" in der:
        if b"\x2a\x86\x48\xce\x3d\x03\x01\x07" in der:
            return "EC-secp256r1", 256
        if b"\x2b\x81\x04\x00\x22" in der:
            return "EC-secp384r1", 384
        if b"\x2b\x81\x04\x00\x23" in der:
            return "EC-secp521r1", 521
        return "EC", None
    if b"\x2b\x65\x70" in der:
        return "Ed25519", 256
    return None, None


def _is_rsa_key_exchange(cipher_name: Optional[str]) -> bool:
    if not cipher_name:
        return False
    c = cipher_name.upper()
    if "TLS_RSA_" in c or "_RSA_WITH_" in c:
        return True
    if any(x in c for x in ("ECDHE", "DHE", "ECDH", "TLS_AES", "TLS_CHACHA20", "PSK")):
        return False
    if c.startswith(("AES", "CAMELLIA", "SEED", "ARIA")):
        return True
    return False


# ── Scan functions (from pqc_tls_scanner.py) ────────────────────────────

def standard_scan(host: str, port: int = 443, timeout: float = None) -> dict:
    if timeout is None:
        timeout = float(SCAN_TIMEOUT)
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    result = {
        "tls_version": None, "cipher_name": None, "cipher_bits": None,
        "cert_issuer": None, "cert_key_type": None, "cert_key_bits": None,
        "cert_expiry": None, "cert_validity_days": None, "alpn": None, "error": None,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                result["tls_version"] = s.version()
                c = s.cipher()
                result["cipher_name"] = c[0] if c else None
                result["cipher_bits"] = c[2] if c else None
                result["alpn"] = s.selected_alpn_protocol()
                cert = s.getpeercert()
                if cert:
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["cert_issuer"] = issuer.get("organizationName")
                    # Parse cert expiry
                    not_after = cert.get("notAfter")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            result["cert_expiry"] = expiry
                            result["cert_validity_days"] = (expiry - datetime.now(timezone.utc)).days
                        except ValueError:
                            pass
                der = s.getpeercert(binary_form=True)
                if der:
                    kt, kb = _infer_key_from_der(der)
                    result["cert_key_type"] = kt
                    result["cert_key_bits"] = kb
    except ssl.CertificateError:
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx2.wrap_socket(raw, server_hostname=host) as s:
                    result["tls_version"] = s.version()
                    c = s.cipher()
                    result["cipher_name"] = c[0] if c else None
                    result["cipher_bits"] = c[2] if c else None
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)
    return result


def pqc_probe(host: str, port: int = 443, timeout: float = None) -> dict:
    if timeout is None:
        timeout = float(SCAN_TIMEOUT)
    result = {
        "probe_result": None, "hrr_group_name": None,
        "pqc_capable": False, "pqc_group": None,
    }
    try:
        hello = _build_client_hello(host)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(hello)
            sock.settimeout(timeout)
            content_type, data = _read_tls_record(sock)
        if content_type == 0x15:
            result["probe_result"] = "alert"
            return result
        if content_type != 0x16:
            result["probe_result"] = "unexpected_record"
            return result
        parsed = _parse_server_hello(data)
        result["hrr_group_name"] = parsed.get("selected_group_name")
        result["pqc_capable"] = parsed.get("pqc_group", False)
        result["pqc_group"] = parsed.get("selected_group_name") if parsed.get("pqc_group") else None
        if parsed["type"] == "HelloRetryRequest":
            result["probe_result"] = "hrr_pqc" if result["pqc_capable"] else "hrr_classic"
        elif parsed["type"] == "ServerHello":
            result["probe_result"] = "server_hello"
        else:
            result["probe_result"] = "parse_failed"
    except Exception as e:
        result["probe_result"] = "error"
    return result


def scan_domain(host: str, port: int = 443) -> dict:
    """Full scan of a single domain: standard TLS + PQC probe."""
    record = {"domain": host}
    std = standard_scan(host, port)
    pqc = pqc_probe(host, port)
    record.update(std)
    record.update(pqc)

    # Assess weak configs (from pqc_tls_scanner.py)
    cipher = (record.get("cipher_name") or "").upper()
    tls_v = (record.get("tls_version") or "").upper()
    cert_bits = record.get("cert_key_bits")

    record["flag_legacy_tls"] = tls_v in {"TLSV1", "TLSV1.0", "TLSV1.1"}
    record["flag_rsa_key_exchange"] = _is_rsa_key_exchange(record.get("cipher_name"))
    record["flag_rc4_or_3des"] = ("RC4" in cipher) or ("3DES" in cipher) or ("DES-CBC3" in cipher)
    record["flag_cert_key_too_small"] = isinstance(cert_bits, int) and cert_bits < 2048
    record["has_ecdh"] = "ECDHE" in cipher or "ECDH" in cipher
    record["has_rsa_key_exchange"] = record["flag_rsa_key_exchange"]

    # Key exchange classification
    if "ECDHE" in cipher:
        record["key_exchange"] = "ECDHE"
    elif "DHE" in cipher:
        record["key_exchange"] = "DHE"
    elif _is_rsa_key_exchange(record.get("cipher_name")):
        record["key_exchange"] = "RSA"
    elif cipher.startswith("TLS_"):
        record["key_exchange"] = "ECDHE"  # TLS 1.3 mandatory
    else:
        record["key_exchange"] = None

    return record


# ── Cipher strength score (ported from vulnerability_analysis.py) ───────

def _cipher_strength_score(cipher_name: Optional[str]) -> float:
    if not cipher_name:
        return 0.0
    c = cipher_name.upper()
    score = 50.0
    # Mode bonus
    if "GCM" in c or "CHACHA20" in c or "CCM" in c:
        score += 30.0
    elif "CBC" in c:
        score += 10.0
    # Bit strength
    if "256" in c:
        score += 20.0
    elif "128" in c:
        score += 10.0
    # Penalty for deprecated
    if "RC4" in c or "3DES" in c:
        score = 10.0
    if "EXPORT" in c:
        score = 0.0
    return min(100.0, score)


# ── Quantum Risk Score (ported from vulnerability_analysis.py) ──────────

def _quantum_risk_score(record: dict) -> float:
    score = 0.0
    cipher = (record.get("cipher_name") or "").upper()
    tls_ver = (record.get("tls_version") or "").upper()
    cert_type = (record.get("cert_key_type") or "").upper()
    pqc = record.get("pqc_capable", False)

    if "TLS_RSA_" in cipher or "_RSA_WITH_" in cipher:
        score += 3.0
    elif "ECDHE" in cipher or "TLS_AES" in cipher or "TLS_CHACHA" in cipher:
        score += 1.5
    elif "DHE" in cipher:
        score += 2.0
    else:
        score += 1.5

    if "RSA" in cert_type:
        score += 2.5
    elif "EC" in cert_type or "ED25519" in cert_type:
        score += 1.5
    else:
        score += 1.0

    if "1.0" in tls_ver or "1.1" in tls_ver:
        score += 2.0
    elif "1.2" in tls_ver:
        score += 1.0
    elif "1.3" in tls_ver:
        score += 0.5
    else:
        score += 1.5

    if pqc:
        score -= 2.5
    else:
        score += 2.0

    return max(0.0, min(10.0, round(score, 1)))


# ── Security score (ported from vulnerability_analysis.py) ──────────────

def _security_score(record: dict) -> float:
    score = 100.0
    cipher = (record.get("cipher_name") or "").upper()
    tls_ver = (record.get("tls_version") or "").upper()
    pqc = record.get("pqc_capable", False)

    if "1.0" in tls_ver:
        score -= 11.8
    elif "1.1" in tls_ver:
        score -= 11.8
    if "1.3" not in tls_ver and tls_ver:
        score -= 7.4
    if "RC4" in cipher:
        score -= 11.8
    if "3DES" in cipher or "DES-CBC3" in cipher:
        score -= 10.6
    if "CBC" in cipher:
        score -= 7.4
    if "TLS_RSA_" in cipher or "_RSA_WITH_" in cipher:
        score -= 11.8
    if not pqc and tls_ver:
        score -= 8.0

    return max(0.0, min(100.0, round(score, 1)))


# ── Background scan pipeline ────────────────────────────────────────────

async def run_scan_pipeline(app_id: int):
    """
    Background task that scans all domains for an application.
    Steps:
      1. Look up domains for the app (from DB or resolve from package name)
      2. Scan each domain (TLS + PQC)
      3. Map CVEs
      4. Run ML prediction
      5. Issue warranty
      6. Store everything in DB
    """
    async with async_session() as db:
        try:
            # Mark as scanning
            result = await db.execute(select(Application).where(Application.id == app_id))
            app = result.scalar_one_or_none()
            if not app:
                return
            app.scan_status = "scanning"
            await db.commit()

            # Get or resolve domains
            domain_rows = (await db.execute(
                select(Domain).where(Domain.app_id == app_id)
            )).scalars().all()

            if not domain_rows:
                # 1. If an APK was uploaded, extract domains from it first
                if app.apk_path:
                    from .apk_extractor import extract_domains_from_apk
                    extracted = extract_domains_from_apk(app.apk_path)
                    if extracted:
                        for dom_name in extracted:
                            cls = _classify_domain(dom_name, app.package_name)
                            domain = Domain(
                                app_id=app_id,
                                domain=dom_name,
                                is_third_party=(cls != "first_party"),
                                domain_class=cls,
                            )
                            db.add(domain)
                        await db.flush()
                        domain_rows = (await db.execute(
                            select(Domain).where(Domain.app_id == app_id)
                        )).scalars().all()
                        await db.commit()

                # 2. Fall back to research pipeline data / heuristic derivation
                if not domain_rows:
                    domains = await _resolve_domains(app.package_name, db, app_id)
                else:
                    domains = list(domain_rows)
            else:
                # Backfill domain_class for rows that were saved without it
                for d in domain_rows:
                    if not d.domain_class:
                        d.domain_class = _classify_domain(d.domain, app.package_name)
                await db.commit()
                domains = domain_rows

            if not domains:
                app.scan_status = "completed"
                await db.commit()
                from .ml_predictor import predict_for_app
                await predict_for_app(app_id, db)
                return

            # Scan each domain concurrently without blocking the event loop.
            # concurrent.futures.as_completed() is a blocking iterator — using it
            # directly inside an async function freezes the event loop for the
            # entire scan duration, stalling all other requests.
            # asyncio.gather + run_in_executor is the correct non-blocking pattern.
            loop = asyncio.get_running_loop()
            domain_names = [d.domain for d in domains]

            with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_CONCURRENCY) as pool:
                scan_results = await asyncio.gather(
                    *[loop.run_in_executor(pool, scan_domain, name) for name in domain_names],
                    return_exceptions=True,
                )

            for dom_obj, scan_result in zip(domains, scan_results):
                if isinstance(scan_result, Exception):
                    scan_result = {"error": str(scan_result)}
                tls_ver = _normalize_tls_version(scan_result.get("tls_version"))
                tls_record = TLSResult(
                    domain_id=dom_obj.id,
                    tls_version=tls_ver,
                    cipher_suite=scan_result.get("cipher_name"),
                    key_exchange=scan_result.get("key_exchange"),
                    cert_expiry=scan_result.get("cert_expiry"),
                    cert_issuer=scan_result.get("cert_issuer"),
                    cert_validity_days=scan_result.get("cert_validity_days"),
                    cert_key_type=scan_result.get("cert_key_type"),
                    cert_key_bits=scan_result.get("cert_key_bits"),
                    supports_pqc=scan_result.get("pqc_capable", False),
                    pqc_group=scan_result.get("pqc_group"),
                    has_ecdh=scan_result.get("has_ecdh", False),
                    has_rsa_key_exchange=scan_result.get("has_rsa_key_exchange", False),
                    flag_legacy_tls=scan_result.get("flag_legacy_tls", False),
                    flag_rc4_or_3des=scan_result.get("flag_rc4_or_3des", False),
                    cipher_strength_score=_cipher_strength_score(scan_result.get("cipher_name")),
                    quantum_risk_score=_quantum_risk_score(scan_result),
                    security_score=_security_score(scan_result),
                    scan_error=scan_result.get("error"),
                )
                db.add(tls_record)

            await db.commit()

            # Map CVEs for all TLS results
            from .cve_mapper import map_cves_for_app
            await map_cves_for_app(app_id, db)

            # Run ML prediction
            from .ml_predictor import predict_for_app
            await predict_for_app(app_id, db)

            # Issue warranty
            from .warranty_engine import issue_warranty
            await issue_warranty(app_id, db)

            app.scan_status = "completed"
            app.scanned_at = datetime.now(timezone.utc)
            await db.commit()

        except Exception as e:
            app.scan_status = "failed"
            app.scanned_at = datetime.now(timezone.utc)
            await db.commit()
            raise


def _normalize_tls_version(raw: Optional[str]) -> Optional[str]:
    """Normalize to RFC 8446 naming: 'TLS 1.3' instead of 'TLSv1.3'."""
    if not raw:
        return None
    mapping = {
        "TLSV1.3": "TLS 1.3", "TLSV1.2": "TLS 1.2",
        "TLSV1.1": "TLS 1.1", "TLSV1.0": "TLS 1.0", "TLSV1": "TLS 1.0",
    }
    return mapping.get(raw.upper().replace(" ", ""), raw)


def _classify_domain(domain: str, package_name: str = "") -> str:
    """Return a domain class label based on simple keyword matching."""
    d = domain.lower()
    if any(k in d for k in ("google", "gstatic", "googleapis", "googleadservices")):
        return "google"
    if any(k in d for k in ("facebook", "fbcdn", "instagram", "whatsapp")):
        return "facebook"
    if any(k in d for k in ("cloudfront", "akamai", "fastly", ".cdn.", "cdnjs", "jsdelivr")):
        return "cdn"
    if any(k in d for k in ("ads", "adservice", "doubleclick", "admob", "adcolony", "adtech")):
        return "ads"
    if "firebase" in d or "firebaseio" in d:
        return "firebase"
    if "amazon" in d or "amazonaws" in d:
        return "aws"
    if "microsoft" in d or "azure" in d or "msftauth" in d:
        return "microsoft"
    if "twitter" in d or "twimg" in d or "t.co" in d:
        return "twitter"
    # Match package name's base domain to decide first_party vs third_party
    if package_name:
        parts = package_name.split(".")
        if len(parts) >= 2:
            pkg_base = parts[1].lower()
            if pkg_base and pkg_base in d:
                return "first_party"
    return "third_party"


async def _resolve_domains(package_name: str, db: AsyncSession, app_id: int) -> list[Domain]:
    """
    Resolve domains for a package name using the research pipeline data.
    Falls back to looking up in target_apps.json.
    """
    from ..config import PIPELINE_DATA_DIR
    target_apps_path = Path(PIPELINE_DATA_DIR) / "target_apps.json"

    domains_to_create = []

    if target_apps_path.exists():
        with open(target_apps_path, encoding="utf-8") as f:
            apps_data = json.load(f)
        for app_data in apps_data:
            if app_data.get("appId") == package_name:
                for dom in app_data.get("domains", []):
                    domains_to_create.append(dom)
                break

    if not domains_to_create:
        # Try to extract domains from package name heuristic
        parts = package_name.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(reversed(parts[:3])) if len(parts) >= 3 else ".".join(reversed(parts[:2]))
            domains_to_create.append(base_domain)

    created = []
    for dom_name in domains_to_create:
        cls = _classify_domain(dom_name, package_name)
        domain = Domain(
            app_id=app_id,
            domain=dom_name,
            is_third_party=(cls not in ("first_party",)),
            domain_class=cls,
        )
        db.add(domain)
        await db.flush()
        created.append(domain)

    await db.commit()
    return created


async def run_url_scan_pipeline(app_id: int, hostname: str) -> None:
    """
    Scan a single hostname/domain directly (used by the URL/domain analysis flow).
    Creates a Domain record for *hostname*, then runs the full pipeline.
    """
    async with async_session() as db:
        try:
            result = await db.execute(select(Application).where(Application.id == app_id))
            app = result.scalar_one_or_none()
            if not app:
                return
            app.scan_status = "scanning"
            await db.commit()

            # Create domain record for the target hostname
            cls = _classify_domain(hostname, app.package_name or hostname)
            domain = Domain(
                app_id=app_id,
                domain=hostname,
                is_third_party=(cls != "first_party"),
                domain_class=cls,
            )
            db.add(domain)
            await db.flush()

            # Scan the domain
            loop = asyncio.get_running_loop()
            scan_result = await loop.run_in_executor(None, scan_domain, hostname)

            tls_ver = _normalize_tls_version(scan_result.get("tls_version"))
            tls_record = TLSResult(
                domain_id=domain.id,
                tls_version=tls_ver,
                cipher_suite=scan_result.get("cipher_name"),
                key_exchange=scan_result.get("key_exchange"),
                cert_expiry=scan_result.get("cert_expiry"),
                cert_issuer=scan_result.get("cert_issuer"),
                cert_validity_days=scan_result.get("cert_validity_days"),
                cert_key_type=scan_result.get("cert_key_type"),
                cert_key_bits=scan_result.get("cert_key_bits"),
                supports_pqc=scan_result.get("pqc_capable", False),
                pqc_group=scan_result.get("pqc_group"),
                has_ecdh=scan_result.get("has_ecdh", False),
                has_rsa_key_exchange=scan_result.get("has_rsa_key_exchange", False),
                flag_legacy_tls=scan_result.get("flag_legacy_tls", False),
                flag_rc4_or_3des=scan_result.get("flag_rc4_or_3des", False),
                cipher_strength_score=_cipher_strength_score(scan_result.get("cipher_name")),
                quantum_risk_score=_quantum_risk_score(scan_result),
                security_score=_security_score(scan_result),
                scan_error=scan_result.get("error"),
            )
            db.add(tls_record)
            await db.commit()

            from .cve_mapper import map_cves_for_app
            await map_cves_for_app(app_id, db)

            from .ml_predictor import predict_for_app
            await predict_for_app(app_id, db)

            from .warranty_engine import issue_warranty
            await issue_warranty(app_id, db)

            app.scan_status = "completed"
            from datetime import datetime, timezone
            app.scanned_at = datetime.now(timezone.utc)
            await db.commit()

        except Exception:
            app.scan_status = "failed"
            from datetime import datetime, timezone
            app.scanned_at = datetime.now(timezone.utc)
            await db.commit()
            raise
