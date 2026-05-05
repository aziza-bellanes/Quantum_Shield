"""
analyze_results.py
==================
Aggregates all scan outputs into a comprehensive PQC readiness report.

Reads:
  data/pqc_scan_results.jsonl   – per-domain TLS + PQC scan
  data/mitm_capture.jsonl       – live traffic capture
  data/target_apps.json         – filtered app metadata

Outputs:
  data/report_per_domain.csv    – domain-level detail
  data/report_per_app.csv       – app-level summary
  data/report_summary.txt       – human-readable executive summary
"""

import json
import csv
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

BASE      = Path(__file__).resolve().parent
DATA_DIR  = BASE / "data"

SCAN_JSONL   = DATA_DIR / "pqc_scan_results.jsonl"
MITM_JSONL   = DATA_DIR / "mitm_capture.jsonl"
APPS_JSON    = DATA_DIR / "target_apps.json"
RUNTIME_JSONL = DATA_DIR / "runtime_pqc_results.jsonl"    # post-capture scan
COVERAGE_CSV  = DATA_DIR / "runtime_vs_static_gap.csv"

OUT_DOMAIN_CSV = DATA_DIR / "report_per_domain.csv"
OUT_APP_CSV    = DATA_DIR / "report_per_app.csv"
OUT_SUMMARY    = DATA_DIR / "report_summary.txt"

# ─── loaders ─────────────────────────────────────────────────────────────────

def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        print(f"  [WARN] {path} not found – skipping")
        return []
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records

def load_json(path: Path) -> list | dict:
    if not path.exists():
        print(f"  [WARN] {path} not found – skipping")
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)

# ─── domain-level aggregation ─────────────────────────────────────────────────

def build_domain_table(scan_records: list[dict], mitm_records: list[dict]) -> list[dict]:
    """
    Merge static TLS scan + live MITM observations for each domain.
    """
    # Index scan records by domain
    scan_by_domain: dict[str, dict] = {}
    for r in scan_records:
        scan_by_domain[r["domain"]] = r

    # Aggregate MITM observations per host
    mitm_by_host: dict[str, list[dict]] = defaultdict(list)
    for r in mitm_records:
        mitm_by_host[r.get("host", "")].append(r)

    # Union of all domains
    all_domains = set(scan_by_domain) | set(mitm_by_host)

    rows = []
    for dom in sorted(all_domains):
        s = scan_by_domain.get(dom, {})
        m_list = mitm_by_host.get(dom, [])

        # From MITM: TLS versions seen
        m_tls_vers = list({x.get("upstream_tls_ver") or x.get("client_tls_ver")
                           for x in m_list if x.get("upstream_tls_ver") or x.get("client_tls_ver")})
        m_ciphers  = list({x.get("upstream_cipher") or x.get("client_cipher")
                           for x in m_list if x.get("upstream_cipher") or x.get("client_cipher")})
        m_pqc      = any(
            (x.get("pqc_capable") or {}).get("pqc_capable", False)
            if isinstance(x.get("pqc_capable"), dict)
            else bool(x.get("pqc_capable"))
            for x in m_list
        )

        rows.append({
            "domain":               dom,
            # TLS Scan results
            "scan_tls_ver":         s.get("tls_version"),
            "scan_cipher":          s.get("cipher_name"),
            "scan_cipher_bits":     s.get("cipher_bits"),
            "scan_cert_key_type":   s.get("cert_key_type"),
            "scan_cert_key_bits":   s.get("cert_key_bits"),
            "scan_alpn":            s.get("alpn"),
            "scan_probe_result":    s.get("probe_result"),
            "scan_hrr_group":       s.get("hrr_group_name"),
            "scan_pqc_capable":     s.get("pqc_capable", False),
            "scan_flag_legacy_tls": s.get("flag_legacy_tls", False),
            "scan_flag_rsa_kx":     s.get("flag_rsa_key_exchange", False),
            "scan_flag_rc4_3des":   s.get("flag_rc4_or_3des", False),
            "scan_flag_cert_small": s.get("flag_cert_key_too_small", False),
            "scan_weak_count":      s.get("weak_config_count", 0),
            "scan_weak_labels":     s.get("weak_config_labels", ""),
            "scan_weak_refs":       s.get("weak_config_refs", ""),
            "scan_error":           s.get("error"),
            # Live MITM
            "mitm_seen":            len(m_list),
            "mitm_tls_vers":        "|".join(filter(None, m_tls_vers)),
            "mitm_ciphers":         "|".join(filter(None, m_ciphers)),
            "mitm_pqc_capable":     m_pqc,
            # Combined verdict
            "pqc_capable":          s.get("pqc_capable", False) or m_pqc,
            # Vantage point
            "vantage_point":        s.get("vantage_point", ""),
        })
    return rows

# ─── app-level aggregation ────────────────────────────────────────────────────

def build_app_table(apps: list[dict], domain_table: list[dict]) -> list[dict]:
    domain_info = {r["domain"]: r for r in domain_table}
    rows = []
    for app in apps:
        doms = app.get("domains", [])
        app_domain_rows = [domain_info[d] for d in doms if d in domain_info]

        any_pqc       = any(r["pqc_capable"] for r in app_domain_rows)
        any_tls13     = any(r.get("scan_tls_ver") == "TLSv1.3" for r in app_domain_rows)
        any_tls12     = any(r.get("scan_tls_ver") == "TLSv1.2" for r in app_domain_rows)
        pqc_domains   = [r["domain"] for r in app_domain_rows if r["pqc_capable"]]
        hrr_groups    = list({r.get("scan_hrr_group") for r in app_domain_rows if r.get("scan_hrr_group")})

        rows.append({
            "appId":           app["appId"],
            "title":           app["title"],
            "genre":           app["genre"],
            "tag":             app["tag"],
            "score":           app.get("score"),
            "installs":        app.get("installs"),
            "total_domains":   len(doms),
            "scanned_domains": len(app_domain_rows),
            "any_tls13":       any_tls13,
            "any_tls12":       any_tls12,
            "pqc_capable":     any_pqc,
            "pqc_domains":     ";".join(pqc_domains),
            "pqc_groups":      ";".join(hrr_groups),
        })
    return rows

# ─── summary text ────────────────────────────────────────────────────────────

def build_summary(domain_rows: list[dict], app_rows: list[dict],
                  runtime_records: list[dict] | None = None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    d_total  = len(domain_rows)
    d_tls13  = sum(1 for r in domain_rows if r.get("scan_tls_ver") == "TLSv1.3")
    d_tls12  = sum(1 for r in domain_rows if r.get("scan_tls_ver") == "TLSv1.2")
    d_pqc    = sum(1 for r in domain_rows if r["pqc_capable"])
    d_hrr    = sum(
        1 for r in domain_rows
        if str(r.get("scan_probe_result") or "").startswith("hrr")
    )
    d_err    = sum(1 for r in domain_rows if r.get("scan_error"))
    d_weak_any = sum(1 for r in domain_rows if (r.get("scan_weak_count") or 0) > 0)
    d_legacy   = sum(1 for r in domain_rows if r.get("scan_flag_legacy_tls"))
    d_rsa_kx   = sum(1 for r in domain_rows if r.get("scan_flag_rsa_kx"))
    d_rc4_3des = sum(1 for r in domain_rows if r.get("scan_flag_rc4_3des"))
    d_cert_sm  = sum(1 for r in domain_rows if r.get("scan_flag_cert_small"))

    a_total  = len(app_rows)
    a_pqc    = sum(1 for r in app_rows if r["pqc_capable"])
    a_tls13  = sum(1 for r in app_rows if r["any_tls13"])

    by_tag: dict[str, dict] = defaultdict(lambda: {"total": 0, "pqc": 0, "tls13": 0})
    for r in app_rows:
        t = r["tag"]
        by_tag[t]["total"] += 1
        if r["pqc_capable"]: by_tag[t]["pqc"]  += 1
        if r["any_tls13"]:   by_tag[t]["tls13"] += 1

    pqc_domains_list = [(r["domain"], r.get("scan_hrr_group","?"))
                        for r in domain_rows if r["pqc_capable"]]

    lines = [
        "=" * 70,
        "  PQC Readiness Report – Mobile Apps TLS Analysis",
        f"  Generated: {now}",
        "=" * 70,
        "",
        "── Domain-Level Results ──────────────────────────────────────────",
        f"  Domains scanned       : {d_total}",
        f"  TLS 1.3               : {d_tls13} ({d_tls13*100//max(d_total,1)}%)",
        f"  TLS 1.2               : {d_tls12} ({d_tls12*100//max(d_total,1)}%)",
        f"  Scan errors           : {d_err}",
        f"  Triggered HRR         : {d_hrr}",
        f"  PQC capable           : {d_pqc} ({d_pqc*100//max(d_total,1)}%)",
        f"  Weak config (any)     : {d_weak_any} ({d_weak_any*100//max(d_total,1)}%)",
        f"    - Legacy TLS 1.0/1.1: {d_legacy}",
        f"    - RSA key exchange  : {d_rsa_kx}",
        f"    - RC4/3DES ciphers  : {d_rc4_3des}",
        f"    - Cert key <2048bit : {d_cert_sm}",
        "",
        "── App-Level Results ─────────────────────────────────────────────",
        f"  Apps in scope         : {a_total}",
        f"  Apps with TLS 1.3     : {a_tls13} ({a_tls13*100//max(a_total,1)}%)",
        f"  Apps with PQC capable : {a_pqc} ({a_pqc*100//max(a_total,1)}%)",
        "",
        "── By Category ───────────────────────────────────────────────────",
    ]

    for tag, counts in sorted(by_tag.items()):
        tot = counts["total"]
        lines.append(
            f"  {tag:30s}  apps={tot:4d}  "
            f"TLS1.3={counts['tls13']:3d} ({counts['tls13']*100//max(tot,1)}%)  "
            f"PQC={counts['pqc']:3d} ({counts['pqc']*100//max(tot,1)}%)"
        )

    if pqc_domains_list:
        lines += [
            "",
            "── PQC-Capable Domains ───────────────────────────────────────────",
        ]
        for dom, grp in sorted(pqc_domains_list):
            lines.append(f"  {dom:45s} {grp}")

    lines += [
        "",
        "── Key Exchange / Cipher Distribution ───────────────────────────",
    ]
    hrr_groups: dict[str, int] = defaultdict(int)
    for r in domain_rows:
        g = r.get("scan_hrr_group")
        if g: hrr_groups[g] += 1
    for g, n in sorted(hrr_groups.items(), key=lambda x: -x[1]):
        lines.append(f"  {g:40s} {n:4d} servers")

    # ── Runtime comparison (if available) ───────────────────────────────
    if runtime_records:
        rt_total = len(runtime_records)
        rt_tls13 = sum(1 for r in runtime_records if r.get("tls_version") == "TLSv1.3")
        rt_tls12 = sum(1 for r in runtime_records if r.get("tls_version") == "TLSv1.2")
        rt_pqc   = sum(1 for r in runtime_records if r.get("pqc_capable"))
        rt_pqc_domains = [(r["domain"], r.get("hrr_group_name","?"))
                          for r in runtime_records if r.get("pqc_capable")]
        # Overlap with static
        static_doms = {r["domain"] for r in domain_rows}
        rt_doms     = {r["domain"] for r in runtime_records}
        overlap     = len(static_doms & rt_doms)
        rt_only     = len(rt_doms - static_doms)
        overlap_pct = overlap * 100 // max(len(rt_doms), 1)

        if overlap == 0:
            note_1 = "  NOTE: No overlap. Runtime endpoints are different from"
            note_2 = "  metadata domains, which suggests static metadata is not"
            note_3 = "  representative of real API backends for this capture."
        elif overlap == len(rt_doms):
            note_1 = "  NOTE: Full overlap in this capture. Runtime endpoints are"
            note_2 = "  already present in the static domain set; metadata captured"
            note_3 = "  these hosts for the observed app traffic." 
        elif overlap_pct < 50:
            note_1 = "  NOTE: Partial but low overlap. Many runtime API hosts are"
            note_2 = "  absent from static metadata, so runtime capture is needed"
            note_3 = "  for representative endpoint discovery."
        else:
            note_1 = "  NOTE: Moderate/high overlap for this capture, but runtime"
            note_2 = "  capture still adds endpoint context and app-level evidence."
            note_3 = "  Continue collecting across more apps for robust coverage."

        lines += [
            "",
            "── Runtime API Endpoints (live mitmproxy capture) ────────────",
            f"  Runtime hosts scanned : {rt_total}",
            f"  TLS 1.3               : {rt_tls13} ({rt_tls13*100//max(rt_total,1)}%)",
            f"  TLS 1.2               : {rt_tls12} ({rt_tls12*100//max(rt_total,1)}%)",
            f"  PQC capable           : {rt_pqc} ({rt_pqc*100//max(rt_total,1)}%)",
            "",
            "── Static vs Runtime Coverage Gap ───────────────────────────",
            f"  Static (metadata) domains  : {len(static_doms)}",
            f"  Runtime (traffic) hosts    : {len(rt_doms)}",
            f"  Overlap (same domain both) : {overlap}",
            f"  Runtime-only (new API hdts): {rt_only}",
            note_1,
            note_2,
            note_3,
        ]
        if rt_pqc_domains:
            lines += ["\n  PQC-capable runtime hosts:"]
            for dom, grp in sorted(rt_pqc_domains):
                lines.append(f"    {dom:43s} {grp}")

    lines += ["", "=" * 70]

    # ── Vantage point comparison (if multiple) ──────────────────────────
    vantages: dict[str, dict] = defaultdict(lambda: {"total": 0, "tls13": 0, "pqc": 0})
    for r in domain_rows:
        vp = r.get("vantage_point") or "Unknown"
        vantages[vp]["total"] += 1
        if r.get("scan_tls_ver") == "TLSv1.3":
            vantages[vp]["tls13"] += 1
        if r.get("pqc_capable"):
            vantages[vp]["pqc"] += 1

    if len(vantages) > 1:
        lines += [
            "",
            "── Multi-Vantage Comparison ──────────────────────────────────",
        ]
        for vp, counts in sorted(vantages.items()):
            tot = counts["total"]
            lines.append(
                f"  {vp:20s}  domains={tot:4d}  "
                f"TLS1.3={counts['tls13']:3d} ({counts['tls13']*100//max(tot,1)}%)  "
                f"PQC={counts['pqc']:3d} ({counts['pqc']*100//max(tot,1)}%)"
            )

    lines += ["", "=" * 70]
    return "\n".join(lines)

# ─── main ────────────────────────────────────────────────────────────────────

def main():
    print("Loading data ...")
    scan_records    = load_jsonl(SCAN_JSONL)
    mitm_records    = load_jsonl(MITM_JSONL)
    runtime_records = load_jsonl(RUNTIME_JSONL)
    apps            = load_json(APPS_JSON)

    if not isinstance(apps, list):
        apps = []

    print(f"  Scan records     : {len(scan_records)}")
    print(f"  MITM records     : {len(mitm_records)}")
    print(f"  Runtime records  : {len(runtime_records)}")
    print(f"  Target apps      : {len(apps)}")

    print("Building tables ...")
    domain_rows = build_domain_table(scan_records, mitm_records)
    app_rows    = build_app_table(apps, domain_rows)

    # ── write domain CSV ──────────────────────────────────────────────────────
    dom_fields = ["domain","vantage_point","scan_tls_ver","scan_cipher","scan_cipher_bits",
                  "scan_cert_key_type","scan_cert_key_bits","scan_alpn",
                  "scan_probe_result","scan_hrr_group","scan_pqc_capable",
                  "scan_flag_legacy_tls","scan_flag_rsa_kx",
                  "scan_flag_rc4_3des","scan_flag_cert_small",
                  "scan_weak_count","scan_weak_labels","scan_weak_refs",
                  "mitm_seen","mitm_tls_vers","mitm_ciphers","mitm_pqc_capable",
                  "pqc_capable","scan_error"]
    with open(OUT_DOMAIN_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=dom_fields, extrasaction="ignore")
        w.writeheader(); w.writerows(domain_rows)
    print(f"Wrote {OUT_DOMAIN_CSV}")

    # ── write app CSV ─────────────────────────────────────────────────────────
    app_fields = ["appId","title","genre","tag","score","installs",
                  "total_domains","scanned_domains","any_tls13","any_tls12",
                  "pqc_capable","pqc_domains","pqc_groups"]
    with open(OUT_APP_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=app_fields, extrasaction="ignore")
        w.writeheader(); w.writerows(app_rows)
    print(f"Wrote {OUT_APP_CSV}")

    # ── write summary ─────────────────────────────────────────────────────────
    summary = build_summary(domain_rows, app_rows,
                            runtime_records if runtime_records else None)
    OUT_SUMMARY.write_text(summary, encoding="utf-8")
    print(f"Wrote {OUT_SUMMARY}")
    print()
    # Print safely on Windows consoles that may not support UTF-8
    sys.stdout.buffer.write((summary + "\n").encode("utf-8", errors="replace"))

if __name__ == "__main__":
    main()
