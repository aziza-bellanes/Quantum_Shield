"""
pqc_tls_scanner.py
==================
Two-layer TLS scanner for each domain:

Layer 1 – Standard scan (Python ssl)
  Records TLS version, cipher suite, certificate key type/size,
  ALPN protocol, and certificate SANs.

Layer 2 – PQC probe (raw socket / hand-crafted ClientHello)
  Sends a TLS 1.3 ClientHello that:
    • lists PQC key-exchange groups FIRST in supported_groups
    • provides only a classical x25519 key share
  Then observes the server's first record:
    • ServerHello  → server accepted x25519  (no PQC negotiated)
    • HelloRetryRequest → server wants a different group; reads which one
      – if that group is a known PQC ID → PQC_CAPABLE = True
  This is the "injection" mechanism – we force the server to reveal its
  preferred group without needing to generate PQC key material ourselves.

PQC group IDs probed
  25497 (0x6399) X25519Kyber768Draft00   – Google/Cloudflare deployed
  25498 (0x639A) SecP256r1Kyber768Draft00
   4588 (0x11EC) X25519MLKEM768          – IANA NIST post-quantum
   4587 (0x11EB) SecP256r1MLKEM768
   4589 (0x11ED) X25519MLKEM1024

Outputs
  pqc_scan_results.jsonl  – one JSON object per domain
  pqc_scan_summary.csv    – human-readable summary
"""

import socket
import ssl
import struct
import os
import json
import csv
import time
import concurrent.futures
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# ─── paths ───────────────────────────────────────────────────────────────────
BASE     = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUT_JSONL = DATA_DIR / "pqc_scan_results.jsonl"
OUT_CSV   = DATA_DIR / "pqc_scan_summary.csv"

# ─── PQC group IDs ───────────────────────────────────────────────────────────
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

# ─── Weak config / CVE mapping ───────────────────────────────────────────────
# References are included for reporting and triage. Some are CVEs and some are
# standards deprecations to cover TLS policy risk classes.
WEAK_CONFIG_MAP = {
    "legacy_tls": {
        "label": "Legacy TLS version (1.0/1.1)",
        "refs": ["RFC8996", "CVE-2011-3389"],
    },
    "rsa_key_exchange": {
        "label": "RSA key exchange (no forward secrecy)",
        "refs": ["HNDL-risk", "NIST-PQC-transition"],
    },
    "rc4_or_3des": {
        "label": "RC4/3DES weak cipher",
        "refs": ["CVE-2013-2566", "CVE-2016-2183"],
    },
    "cert_key_too_small": {
        "label": "Certificate key size < 2048 bits",
        "refs": ["NIST-SP-800-131A"],
    },
}


def _is_rsa_key_exchange(cipher_name: Optional[str]) -> bool:
    if not cipher_name:
        return False
    c = cipher_name.upper()
    # Explicit RSA key exchange naming.
    if "TLS_RSA_" in c or "_RSA_WITH_" in c:
        return True
    # Exclude modern key exchange patterns.
    if any(x in c for x in ("ECDHE", "DHE", "ECDH", "TLS_AES", "TLS_CHACHA20", "PSK")):
        return False
    # OpenSSL-style legacy names often imply RSA key exchange (e.g., AES128-SHA).
    if c.startswith(("AES", "CAMELLIA", "SEED", "ARIA")):
        return True
    return False


def assess_weak_configs(scan_record: dict) -> dict:
    tls_v = (scan_record.get("tls_version") or "").upper()
    cipher = (scan_record.get("cipher_name") or "").upper()
    cert_bits = scan_record.get("cert_key_bits")

    legacy_tls = tls_v in {"TLSV1", "TLSV1.0", "TLSV1.1"}
    rsa_kx = _is_rsa_key_exchange(scan_record.get("cipher_name"))
    rc4_or_3des = ("RC4" in cipher) or ("3DES" in cipher) or ("DES-CBC3" in cipher)
    cert_small = isinstance(cert_bits, int) and cert_bits < 2048

    flags = {
        "flag_legacy_tls": legacy_tls,
        "flag_rsa_key_exchange": rsa_kx,
        "flag_rc4_or_3des": rc4_or_3des,
        "flag_cert_key_too_small": cert_small,
    }

    active = []
    refs = []
    for key, active_flag in flags.items():
        if not active_flag:
            continue
        wk = key.replace("flag_", "")
        if wk in WEAK_CONFIG_MAP:
            active.append(WEAK_CONFIG_MAP[wk]["label"])
            refs.extend(WEAK_CONFIG_MAP[wk]["refs"])

    return {
        **flags,
        "weak_config_count": sum(1 for v in flags.values() if v),
        "weak_config_labels": "|".join(active),
        "weak_config_refs": "|".join(sorted(set(refs))),
    }

# ─── ClientHello builder ─────────────────────────────────────────────────────

def _pack_extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data

def _sni_ext(hostname: str) -> bytes:
    name = hostname.encode()
    sni_data = struct.pack("!H", len(name) + 3) + struct.pack("!BH", 0, len(name)) + name
    return _pack_extension(0x0000, sni_data)

def _supported_versions_ext() -> bytes:
    # Offer TLS 1.3 and 1.2
    data = struct.pack("!B", 4) + b"\x03\x04\x03\x03"
    return _pack_extension(0x002B, data)

def _supported_groups_ext() -> bytes:
    # PQC groups first, then classical
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
    """
    Provide an x25519 key share (32 random bytes as public key).
    PQC groups are listed in supported_groups but NOT in key_share,
    so a PQC-supporting server will respond with HelloRetryRequest
    selecting a PQC group.
    """
    pub = os.urandom(32)
    entry = struct.pack("!HH", 0x001D, len(pub)) + pub
    data  = struct.pack("!H", len(entry)) + entry
    return _pack_extension(0x0033, data)

def _build_client_hello(hostname: str) -> bytes:
    random_bytes = os.urandom(32)
    session_id   = b""

    # TLS 1.3 cipher suites (+ some TLS1.2 fallbacks)
    ciphers = [
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x1302,  # TLS_AES_256_GCM_SHA384
        0x1303,  # TLS_CHACHA20_POLY1305_SHA256
        0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ]
    cipher_bytes = struct.pack("!H", len(ciphers) * 2)
    for c in ciphers:
        cipher_bytes += struct.pack("!H", c)

    compression = b"\x01\x00"

    extensions = (
        _sni_ext(hostname) +
        _supported_versions_ext() +
        _supported_groups_ext() +
        _sig_algs_ext() +
        _key_share_ext() +
        # ALPN: h2, http/1.1
        _pack_extension(0x0010, b"\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31")
    )

    body = (
        b"\x03\x03" +                          # client_version (TLS 1.2 legacy)
        random_bytes +
        struct.pack("!B", len(session_id)) + session_id +
        cipher_bytes +
        compression +
        struct.pack("!H", len(extensions)) + extensions
    )

    hs  = struct.pack("!B", 0x01) + struct.pack("!I", len(body))[1:] + body
    rec = struct.pack("!BHH", 0x16, 0x0301, len(hs)) + hs
    return rec


# ─── Server response parser ──────────────────────────────────────────────────

def _read_tls_record(sock: socket.socket) -> tuple[int, bytes]:
    """Read one TLS record. Returns (content_type, data)."""
    hdr = b""
    while len(hdr) < 5:
        chunk = sock.recv(5 - len(hdr))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
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
    """Parse ServerHello or HelloRetryRequest handshake message."""
    result = {"type": "unknown", "version": None, "cipher": None,
              "selected_group": None, "pqc_group": False}
    if len(data) < 4:
        return result

    msg_type = data[0]
    # 2 = ServerHello
    if msg_type != 2:
        return result

    # skip msg_type (1) + length (3)
    pos = 4
    if pos + 2 > len(data):
        return result
    legacy_ver = struct.unpack("!H", data[pos:pos+2])[0]
    pos += 2

    # random (32 bytes) – if == HelloRetryRequest magic, it's HRR
    HRR_MAGIC = bytes.fromhex(
        "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
    if pos + 32 > len(data):
        return result
    rand = data[pos:pos+32]
    pos += 32
    is_hrr = (rand == HRR_MAGIC)
    result["type"] = "HelloRetryRequest" if is_hrr else "ServerHello"

    # skip session_id
    if pos >= len(data):
        return result
    sid_len = data[pos]; pos += 1 + sid_len

    # cipher suite
    if pos + 2 > len(data):
        return result
    cipher_id = struct.unpack("!H", data[pos:pos+2])[0]
    result["cipher"] = f"0x{cipher_id:04X}"
    pos += 3  # cipher (2) + compression_method (1)

    # extensions
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

        # supported_versions (0x002B) – actual TLS version in HRR
        if ext_type == 0x002B and len(ext_data) >= 2:
            result["version"] = f"0x{struct.unpack('!H', ext_data[:2])[0]:04X}"

        # key_share (0x0033)
        if ext_type == 0x0033:
            if is_hrr:
                # HRR key_share contains only the selected group (2 bytes)
                if len(ext_data) >= 2:
                    grp = struct.unpack("!H", ext_data[:2])[0]
                    result["selected_group"] = grp
                    result["selected_group_name"] = ALL_GROUPS.get(grp, f"unknown(0x{grp:04X})")
                    result["pqc_group"] = grp in PQC_GROUPS
            else:
                # ServerHello key_share contains group + public key
                if len(ext_data) >= 2:
                    grp = struct.unpack("!H", ext_data[:2])[0]
                    result["selected_group"] = grp
                    result["selected_group_name"] = ALL_GROUPS.get(grp, f"unknown(0x{grp:04X})")
                    result["pqc_group"] = grp in PQC_GROUPS

    return result


# ─── Layer 1: standard ssl scan ──────────────────────────────────────────────

def standard_scan(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED
    result = {
        "tls_version": None, "cipher_name": None, "cipher_bits": None,
        "cert_subject": None, "cert_issuer": None, "cert_key_type": None,
        "cert_key_bits": None, "alpn": None, "sni": host,
        "error": None,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                result["tls_version"]  = s.version()
                c = s.cipher()
                result["cipher_name"]  = c[0] if c else None
                result["cipher_bits"]  = c[2] if c else None
                result["alpn"]         = s.selected_alpn_protocol()
                cert = s.getpeercert()
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["cert_subject"] = subj.get("commonName")
                    result["cert_issuer"]  = issuer.get("organizationName")
                # Key type from DER
                der = s.getpeercert(binary_form=True)
                if der:
                    kt, kb = _infer_key_from_der(der)
                    result["cert_key_type"] = kt
                    result["cert_key_bits"] = kb
    except ssl.CertificateError as e:
        # retry with unverified to still get TLS info
        result["error"] = f"cert_error: {e}"
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode    = ssl.CERT_NONE
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


def _infer_key_from_der(der: bytes) -> tuple[Optional[str], Optional[int]]:
    """Heuristic: detect RSA vs EC key type from DER cert bytes."""
    # RSA OID: 1.2.840.113549.1.1.1  → hex 2a 86 48 86 f7 0d 01 01 01
    if b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" in der:
        # Find modulus length – look for bit-string after RSA OID
        idx = der.find(b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")
        # rough bit-length from certificate total size heuristic
        bits = None
        return "RSA", bits
    # EC OID: 1.2.840.10045.2.1  → hex 2a 86 48 ce 3d 02 01
    if b"\x2a\x86\x48\xce\x3d\x02\x01" in der:
        # secp256r1 OID: 2a 86 48 ce 3d 03 01 07
        if b"\x2a\x86\x48\xce\x3d\x03\x01\x07" in der:
            return "EC-secp256r1", 256
        if b"\x2b\x81\x04\x00\x22" in der:
            return "EC-secp384r1", 384
        if b"\x2b\x81\x04\x00\x23" in der:
            return "EC-secp521r1", 521
        return "EC", None
    # Ed25519 OID: 1.3.101.112  → hex 2b 65 70
    if b"\x2b\x65\x70" in der:
        return "Ed25519", 256
    return None, None


# ─── Layer 2: PQC probe ───────────────────────────────────────────────────────

def pqc_probe(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """
    Send a crafted ClientHello with PQC groups first.
    Parse the first server response to detect PQC capability.
    """
    result = {
        "probe_result": None,   # "hrr_pqc" | "hrr_classic" | "server_hello" | "error"
        "hrr_group": None,
        "hrr_group_name": None,
        "pqc_capable": False,
        "probe_error": None,
    }
    try:
        hello = _build_client_hello(host)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(hello)
            # Allow the server time to respond
            sock.settimeout(timeout)
            content_type, data = _read_tls_record(sock)

        if content_type == 0x15:  # Alert
            desc = data[1] if len(data) > 1 else 0
            result["probe_result"] = "alert"
            result["probe_error"]  = f"TLS Alert code {desc}"
            return result

        if content_type != 0x16:  # Not a handshake record
            result["probe_result"] = "unexpected_record"
            return result

        parsed = _parse_server_hello(data)
        result["hrr_group"]      = parsed.get("selected_group")
        result["hrr_group_name"] = parsed.get("selected_group_name")
        result["pqc_capable"]    = parsed.get("pqc_group", False)

        if parsed["type"] == "HelloRetryRequest":
            result["probe_result"] = "hrr_pqc" if result["pqc_capable"] else "hrr_classic"
        elif parsed["type"] == "ServerHello":
            result["probe_result"] = "server_hello"
            # Server accepted x25519 directly – no HRR
            result["pqc_capable"] = parsed.get("pqc_group", False)
        else:
            result["probe_result"] = "parse_failed"

    except Exception as e:
        result["probe_result"] = "error"
        result["probe_error"]  = str(e)

    return result


# ─── Combined scan ────────────────────────────────────────────────────────────

def scan_domain(host: str, port: int = 443) -> dict:
    record = {
        "domain": host,
        "port":   port,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
    record.update(standard_scan(host, port))
    record.update(pqc_probe(host, port))
    record.update(assess_weak_configs(record))
    return record


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(description="PQC TLS Scanner")
    ap.add_argument("--domains", default=str(DATA_DIR / "target_domains.csv"),
                    help="CSV with domain column (default: data/target_domains.csv)")
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--limit",   type=int, default=0, help="0 = no limit")
    ap.add_argument("--port",    type=int, default=443)
    args = ap.parse_args()

    # Load domains from CSV or plain text
    domain_path = Path(args.domains)
    if not domain_path.exists():
        # fallback: look for a plain-text file
        plain = DATA_DIR / "domains.txt"
        if plain.exists():
            domains = [l.strip() for l in plain.read_text().splitlines() if l.strip()]
        else:
            print(f"[ERROR] No domain list found at {domain_path}")
            return
    else:
        import csv as _csv
        with open(domain_path, newline="", encoding="utf-8") as f:
            reader = _csv.DictReader(f)
            domains = [row["domain"] for row in reader if row.get("domain", "").strip()]

    if args.limit:
        domains = domains[:args.limit]

    print(f"Scanning {len(domains)} domains with {args.workers} workers …")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(scan_domain, d, args.port): d for d in domains}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            r = fut.result()
            results.append(r)
            marker = "PQC" if r.get("pqc_capable") else ("NO_PQC " + (r.get("tls_version") or r.get("probe_result") or "err"))
            print(f"  [{done:4d}/{len(domains)}] {r['domain']:45s} {marker}")

    # Write JSONL
    with open(OUT_JSONL, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    # Write CSV summary
    csv_fields = ["domain", "tls_version", "cipher_name", "cipher_bits",
                  "cert_key_type", "cert_key_bits", "alpn",
                  "probe_result", "hrr_group_name", "pqc_capable",
                  "cert_subject", "cert_issuer", "error", "probe_error",
                  "flag_legacy_tls", "flag_rsa_key_exchange", "flag_rc4_or_3des",
                  "flag_cert_key_too_small", "weak_config_count",
                  "weak_config_labels", "weak_config_refs"]
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=csv_fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(results)

    # Print summary
    pqc_yes = [r for r in results if r.get("pqc_capable")]
    hrr_cls = [r for r in results if r.get("probe_result") == "hrr_classic"]
    tls13   = [r for r in results if r.get("tls_version") == "TLSv1.3"]
    tls12   = [r for r in results if r.get("tls_version") == "TLSv1.2"]
    errors  = [r for r in results if r.get("error")]
    weak_any = [r for r in results if r.get("weak_config_count", 0) > 0]
    weak_legacy = [r for r in results if r.get("flag_legacy_tls")]
    weak_rsa_kx = [r for r in results if r.get("flag_rsa_key_exchange")]
    weak_rc4_3des = [r for r in results if r.get("flag_rc4_or_3des")]
    weak_cert_small = [r for r in results if r.get("flag_cert_key_too_small")]

    print("\n" + "=" * 60)
    print(f"  Total domains scanned : {len(results)}")
    print(f"  TLS 1.3               : {len(tls13)}")
    print(f"  TLS 1.2               : {len(tls12)}")
    print(f"  PQC capable (HRR/nego): {len(pqc_yes)}")
    print(f"  HRR – classic group   : {len(hrr_cls)}")
    print(f"  Weak config (any)     : {len(weak_any)}")
    print(f"    - Legacy TLS        : {len(weak_legacy)}")
    print(f"    - RSA key exchange  : {len(weak_rsa_kx)}")
    print(f"    - RC4/3DES          : {len(weak_rc4_3des)}")
    print(f"    - Cert < 2048 bits  : {len(weak_cert_small)}")
    print(f"  Errors                : {len(errors)}")
    print("=" * 60)

    if pqc_yes:
        print("\nPQC-capable domains:")
        for r in pqc_yes:
            print(f"  {r['domain']} → {r['hrr_group_name']}")

    print(f"\nResults → {OUT_JSONL}")
    print(f"Summary → {OUT_CSV}")

if __name__ == "__main__":
    main()
