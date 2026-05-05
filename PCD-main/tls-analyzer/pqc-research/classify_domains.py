"""
classify_domains.py
===================
Classify scanned domains as first-party, ads/analytics, CDN, Google services,
social, or other third-party.  Enriches report_per_domain.csv with a
``domain_class`` column and produces classification statistics.

Input:
  data/report_per_domain.csv
  data/target_apps.json           (for first-party matching)
  data/pcap_runtime_merged.csv    (optional – for app↔host mapping)

Output:
  data/report_per_domain.csv      (updated in-place with domain_class column)
  data/domain_classification.csv  (domain, domain_class, matched_rule)
  data/classification_summary.txt
"""

import csv
import json
import re
from collections import defaultdict
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"

DOMAIN_CSV = DATA_DIR / "report_per_domain.csv"
APPS_JSON = DATA_DIR / "target_apps.json"
RUNTIME_CSV = DATA_DIR / "pcap_runtime_merged.csv"
OUT_CLASS = DATA_DIR / "domain_classification.csv"
OUT_SUMMARY = DATA_DIR / "classification_summary.txt"

# ─── Known third-party domain patterns ──────────────────────────────────────
# Each category maps to a list of (pattern, label) tuples.
# Patterns are matched against the full domain string.

GOOGLE_PATTERNS = [
    "googleapis.com", "google.com", "google.com.au", "gstatic.com",
    "googleusercontent.com", "googlevideo.com", "googleadservices.com",
    "googletagmanager.com", "googletagservices.com", "google-analytics.com",
    "googlesyndication.com", "googleads.g.doubleclick.net", "goog",
    "firebase.google.com", "firebaseio.com", "firebaseinstallations.googleapis.com",
    "fcm.googleapis.com", "crashlytics.com", "crashlyticsreports-pa.googleapis.com",
    "app-measurement.com",
]

FIREBASE_PATTERNS = [
    "firebaseio.com", "firebaseinstallations.googleapis.com",
    "firebase-settings.crashlytics.com", "crashlytics.com",
    "fcm.googleapis.com", "app-measurement.com",
    "firebaseremoteconfig.googleapis.com", "firebasestorage.googleapis.com",
    "firebasedynamiclinks.googleapis.com",
]

ADS_ANALYTICS_PATTERNS = [
    # Ad networks
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "googleads.g.doubleclick.net", "adservice.google.",
    "admob.com", "adsserver.", "adserver.", "ads.yahoo.com",
    "advertising.com", "adnxs.com", "adsrvr.org", "adswizz.com",
    "moatads.com", "serving-sys.com", "smartadserver.com",
    "mopub.com", "applovin.com", "unity3d.com", "unityads.",
    "appsflyer.com", "adjust.com", "branch.io", "kochava.com",
    "singular.net",
    # Analytics
    "google-analytics.com", "googletagmanager.com", "app-measurement.com",
    "amplitude.com", "mixpanel.com", "segment.io", "segment.com",
    "bugsnag.com", "sentry.io", "newrelic.com", "datadoghq.com",
    "analytics.", "braze.com", "braze.eu", "appboy.com",
    "onesignal.com", "pushwoosh.com", "leanplum.com",
    "flurry.com", "localytics.com", "clevertap.com",
    "hotjar.com", "mouseflow.com", "fullstory.com",
    "instabug.com", "uxcam.com",
    # Attribution & tracking
    "facebook.net", "fbcdn.net", "connect.facebook.net",
    "graph.facebook.com",
]

CDN_PATTERNS = [
    "cloudflare.com", "cloudflare-dns.com", "cdnjs.cloudflare.com",
    "cloudfront.net", "akamai.net", "akamaized.net", "akamaitech.net",
    "akamaihd.net", "edgesuite.net", "edgekey.net",
    "fastly.net", "fastlylb.net",
    "azureedge.net", "azure.com", "msedge.net",
    "amazonaws.com", "s3.amazonaws.com", "elasticbeanstalk.com",
    "cdn.", "static.",
    "imgix.net", "imgix.com",
    "maxcdn.com", "stackpathdns.com", "stackpathcdn.com",
    "jsdelivr.net", "unpkg.com",
]

SOCIAL_PATTERNS = [
    "facebook.com", "fb.com", "fbcdn.net", "instagram.com",
    "twitter.com", "t.co", "twimg.com", "x.com",
    "linkedin.com", "pinterest.com", "tiktok.com",
    "snapchat.com", "snap.com", "reddit.com",
    "whatsapp.com", "whatsapp.net", "telegram.org",
]

APPLE_PATTERNS = [
    "apple.com", "icloud.com", "mzstatic.com", "apple-dns.net",
]

MICROSOFT_PATTERNS = [
    "microsoft.com", "windows.net", "msftconnecttest.com",
    "office.com", "live.com", "outlook.com", "bing.com",
    "msn.com", "skype.com",
]


def _domain_ends_with(domain: str, pattern: str) -> bool:
    """Check if domain equals or is a subdomain of pattern."""
    if domain == pattern:
        return True
    if domain.endswith("." + pattern):
        return True
    return False


def _classify_by_known_lists(domain: str) -> tuple[str, str] | None:
    """Classify domain using known pattern lists. Returns (class, rule) or None."""
    d = domain.lower().strip()

    # Firebase (subset of Google, check first)
    for p in FIREBASE_PATTERNS:
        if _domain_ends_with(d, p):
            return ("google_firebase", f"firebase:{p}")

    # Ads & Analytics
    for p in ADS_ANALYTICS_PATTERNS:
        if _domain_ends_with(d, p) or p in d:
            return ("ads_analytics", f"ads:{p}")

    # CDN
    for p in CDN_PATTERNS:
        if _domain_ends_with(d, p) or (p.endswith(".") and d.startswith(p)):
            return ("cdn", f"cdn:{p}")

    # Google services (broader)
    for p in GOOGLE_PATTERNS:
        if _domain_ends_with(d, p):
            return ("google_services", f"google:{p}")

    # Social
    for p in SOCIAL_PATTERNS:
        if _domain_ends_with(d, p):
            return ("social", f"social:{p}")

    # Apple
    for p in APPLE_PATTERNS:
        if _domain_ends_with(d, p):
            return ("apple_services", f"apple:{p}")

    # Microsoft
    for p in MICROSOFT_PATTERNS:
        if _domain_ends_with(d, p):
            return ("microsoft_services", f"microsoft:{p}")

    return None


def _extract_company_tokens(package_name: str) -> list[str]:
    """
    Extract candidate company/brand tokens from an Android package name.
    e.g. 'com.paypal.android.p2pmobile' → ['paypal']
         'com.nordvpn.android' → ['nordvpn']
         'org.iggymedia.periodtracker' → ['iggymedia']
    """
    parts = package_name.lower().split(".")
    # Skip common prefixes/suffixes
    skip = {"com", "org", "net", "io", "co", "app", "android", "mobile",
            "www", "dev", "beta", "release", "lite", "pro", "free",
            "premium", "main", "client", "sdk"}
    tokens = [p for p in parts if p not in skip and len(p) > 2]
    return tokens


def _is_first_party(domain: str, app_domains: set[str],
                    package_tokens: list[str]) -> tuple[bool, str]:
    """
    Check if a domain is first-party for an app.
    Uses direct domain match and fuzzy package-name matching.
    """
    d = domain.lower()

    # Direct match: domain is in the app's declared domains
    if d in app_domains:
        return (True, "declared_domain")

    # Token match: company name from package appears in domain
    for tok in package_tokens:
        if tok in d:
            return (True, f"package_token:{tok}")

    return (False, "")


def load_app_domain_map(apps_json: Path) -> dict[str, dict]:
    """Load apps and build domain→app mapping."""
    if not apps_json.exists():
        return {}
    with open(apps_json, encoding="utf-8") as f:
        apps = json.load(f)

    result = {}
    for app in apps:
        pkg = app.get("appId", "")
        doms = set(d.lower() for d in app.get("domains", []))
        tokens = _extract_company_tokens(pkg)
        result[pkg] = {"domains": doms, "tokens": tokens, "app": app}
    return result


def load_runtime_host_map(runtime_csv: Path) -> dict[str, set[str]]:
    """Load runtime CSV and build host→set-of-apps mapping."""
    if not runtime_csv.exists():
        return {}
    mapping: dict[str, set[str]] = defaultdict(set)
    with open(runtime_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            host = (row.get("host") or "").strip().lower()
            app = (row.get("app") or "").strip()
            if host and app:
                mapping[host].add(app)
    return mapping


def classify_domains(domain_csv: Path, apps_json: Path,
                     runtime_csv: Path | None = None) -> list[dict]:
    """Classify each domain and return classification records."""
    # Load domain list
    domains = []
    with open(domain_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            d = (row.get("domain") or "").strip()
            if d:
                domains.append(d)

    # Load app info
    app_map = load_app_domain_map(apps_json)
    all_app_domains: set[str] = set()
    for info in app_map.values():
        all_app_domains |= info["domains"]

    # Load runtime mapping
    runtime_map = load_runtime_host_map(runtime_csv) if runtime_csv else {}

    # Build reverse index: domain → apps that declared it
    domain_to_apps: dict[str, list[str]] = defaultdict(list)
    for pkg, info in app_map.items():
        for d in info["domains"]:
            domain_to_apps[d].append(pkg)

    # Add runtime mappings
    for host, apps in runtime_map.items():
        for app in apps:
            if app not in domain_to_apps.get(host, []):
                domain_to_apps[host].append(app)

    results = []
    for domain in domains:
        d = domain.lower()

        # 1) Check known third-party lists first
        known = _classify_by_known_lists(d)
        if known:
            cls, rule = known
            results.append({
                "domain": domain,
                "domain_class": cls,
                "matched_rule": rule,
                "associated_apps": "|".join(domain_to_apps.get(d, [])),
            })
            continue

        # 2) Check first-party match against all associated apps
        associated_apps = domain_to_apps.get(d, [])
        is_fp = False
        fp_rule = ""

        for pkg in associated_apps:
            info = app_map.get(pkg)
            if not info:
                continue
            matched, rule = _is_first_party(d, info["domains"], info["tokens"])
            if matched:
                is_fp = True
                fp_rule = f"first_party:{pkg}:{rule}"
                break

        # 3) If not matched to any app, try all app tokens (broader check)
        if not is_fp:
            for pkg, info in app_map.items():
                matched, rule = _is_first_party(d, info["domains"], info["tokens"])
                if matched:
                    is_fp = True
                    fp_rule = f"first_party:{pkg}:{rule}"
                    associated_apps.append(pkg)
                    break

        if is_fp:
            results.append({
                "domain": domain,
                "domain_class": "first_party",
                "matched_rule": fp_rule,
                "associated_apps": "|".join(associated_apps),
            })
        else:
            # 4) Heuristic: blogspot, github.io, notion.site → developer/documentation
            if any(x in d for x in [".blogspot.", ".github.io", ".notion.site",
                                     ".wordpress.com", ".wixsite.com"]):
                results.append({
                    "domain": domain,
                    "domain_class": "developer_site",
                    "matched_rule": "heuristic:hosted_site",
                    "associated_apps": "|".join(associated_apps),
                })
            # 5) Government / institutional
            elif any(d.endswith(x) for x in [".gov", ".gov.au", ".gov.uk",
                                              ".edu", ".edu.au", ".org.au",
                                              ".go.id", ".go.jp", ".gov.za"]):
                results.append({
                    "domain": domain,
                    "domain_class": "government_institutional",
                    "matched_rule": "heuristic:gov_edu_tld",
                    "associated_apps": "|".join(associated_apps),
                })
            else:
                results.append({
                    "domain": domain,
                    "domain_class": "other_third_party",
                    "matched_rule": "unmatched",
                    "associated_apps": "|".join(associated_apps),
                })

    return results


def update_domain_csv(domain_csv: Path, classifications: list[dict]):
    """Add domain_class column to the existing report_per_domain.csv."""
    class_map = {c["domain"]: c["domain_class"] for c in classifications}

    # Read existing
    with open(domain_csv, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = list(reader.fieldnames or [])
        rows = list(reader)

    # Add column
    if "domain_class" not in fields:
        fields.insert(1, "domain_class")

    for row in rows:
        row["domain_class"] = class_map.get(row.get("domain", ""), "unknown")

    with open(domain_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def build_summary(classifications: list[dict], domain_csv: Path) -> str:
    """Build classification summary with PQC readiness breakdown per class."""
    # Load PQC data from domain CSV
    pqc_map = {}
    tls_map = {}
    with open(domain_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            d = row.get("domain", "")
            pqc_map[d] = str(row.get("pqc_capable", "")).lower() in ("true", "1", "yes")
            tls_map[d] = row.get("scan_tls_ver", "")

    by_class: dict[str, list[dict]] = defaultdict(list)
    for c in classifications:
        by_class[c["domain_class"]].append(c)

    lines = [
        "=" * 70,
        "  Domain Classification Report",
        "=" * 70,
        f"  Total domains classified: {len(classifications)}",
        "",
        "── Distribution ──────────────────────────────────────────────────",
        f"  {'Class':<30s} {'Count':>6s} {'TLS1.3':>8s} {'PQC':>6s} {'PQC%':>6s}",
        "  " + "-" * 58,
    ]

    for cls in sorted(by_class, key=lambda x: -len(by_class[x])):
        items = by_class[cls]
        n = len(items)
        n_pqc = sum(1 for c in items if pqc_map.get(c["domain"], False))
        n_tls13 = sum(1 for c in items if tls_map.get(c["domain"], "") == "TLSv1.3")
        pqc_pct = n_pqc * 100 // max(n, 1)
        lines.append(f"  {cls:<30s} {n:>6d} {n_tls13:>8d} {n_pqc:>6d} {pqc_pct:>5d}%")

    # Key insight: PQC by class
    lines += [
        "",
        "── Key Findings ──────────────────────────────────────────────────",
    ]

    fp_items = by_class.get("first_party", [])
    fp_pqc = sum(1 for c in fp_items if pqc_map.get(c["domain"], False))
    cdn_items = by_class.get("cdn", [])
    cdn_pqc = sum(1 for c in cdn_items if pqc_map.get(c["domain"], False))
    google_items = by_class.get("google_services", []) + by_class.get("google_firebase", [])
    google_pqc = sum(1 for c in google_items if pqc_map.get(c["domain"], False))

    if fp_items:
        lines.append(f"  First-party backends: {len(fp_items)} domains, "
                     f"{fp_pqc} PQC-capable ({fp_pqc*100//max(len(fp_items),1)}%)")
    if cdn_items:
        lines.append(f"  CDN endpoints:        {len(cdn_items)} domains, "
                     f"{cdn_pqc} PQC-capable ({cdn_pqc*100//max(len(cdn_items),1)}%)")
    if google_items:
        lines.append(f"  Google/Firebase:      {len(google_items)} domains, "
                     f"{google_pqc} PQC-capable ({google_pqc*100//max(len(google_items),1)}%)")

    lines.append("")
    lines.append("  This reveals whether PQC adoption is driven by app developers")
    lines.append("  (first-party) or by infrastructure providers (CDN/Google).")

    # Sample domains per class
    lines += ["", "── Samples Per Class ─────────────────────────────────────────────"]
    for cls in sorted(by_class, key=lambda x: -len(by_class[x])):
        items = by_class[cls]
        samples = [c["domain"] for c in items[:5]]
        lines.append(f"  {cls}: {', '.join(samples)}")

    lines += ["", "=" * 70]
    return "\n".join(lines)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Classify domains as 1P/3P/ads/CDN")
    ap.add_argument("--domain-csv", default=str(DOMAIN_CSV))
    ap.add_argument("--apps-json", default=str(APPS_JSON))
    ap.add_argument("--runtime-csv", default=str(RUNTIME_CSV))
    args = ap.parse_args()

    domain_csv = Path(args.domain_csv)
    apps_json = Path(args.apps_json)
    runtime_csv = Path(args.runtime_csv)

    if not domain_csv.exists():
        print(f"[ERROR] {domain_csv} not found. Run analyze_results.py first.")
        return

    print("Classifying domains ...")
    classifications = classify_domains(
        domain_csv, apps_json,
        runtime_csv if runtime_csv.exists() else None,
    )

    # Write classification CSV
    OUT_CLASS.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CLASS, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["domain", "domain_class",
                                           "matched_rule", "associated_apps"])
        w.writeheader()
        w.writerows(classifications)
    print(f"Wrote {OUT_CLASS}")

    # Update domain CSV in-place
    update_domain_csv(domain_csv, classifications)
    print(f"Updated {domain_csv} with domain_class column")

    # Write summary
    summary = build_summary(classifications, domain_csv)
    OUT_SUMMARY.write_text(summary, encoding="utf-8")
    print(f"Wrote {OUT_SUMMARY}")
    print()
    import sys
    sys.stdout.buffer.write((summary + "\n").encode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
