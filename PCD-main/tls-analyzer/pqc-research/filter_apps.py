"""
filter_apps.py
==============
Filters Combined_apps_10388.json to extract target apps
(Health & Fitness, Medical, Finance, VPN) and collects the unique
domains that each app's backend might contact.

Outputs:
  target_apps.json  – list of filtered app records (appId, title, genre, domains)
  target_domains.csv – unique domain → app_count mapping for TLS scanning
"""

import json
import re
import csv
import os
from urllib.parse import urlparse
from pathlib import Path

# ── paths ────────────────────────────────────────────────────────────────────
BASE        = Path(__file__).resolve().parent
DATA_DIR    = BASE / "data"
COMBINED    = BASE.parent.parent.parent.parent / "Combined_apps_10388.json"
OUT_APPS    = DATA_DIR / "target_apps.json"
OUT_DOMAINS = DATA_DIR / "target_domains.csv"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── filters ──────────────────────────────────────────────────────────────────
TARGET_GENRES = {
    "Health & Fitness",
    "Medical",
    "Finance",
}
VPN_KEYWORDS = ["vpn", "wireguard", "openvpn", "tunnel", "protonvpn", "nordvpn",
                "expressvpn", "mullvad", "windscribe", "torguard"]

# ── helpers ───────────────────────────────────────────────────────────────────
URL_RE = re.compile(r'https?://[^\s\'"<>)]+', re.IGNORECASE)

def extract_domain(raw: str) -> str | None:
    """Return the netloc of a URL, stripped of www. prefix."""
    try:
        h = urlparse(raw.strip()).netloc
        return h.lstrip("www.").lower() if h else None
    except Exception:
        return None

def domains_from_app(app: dict) -> set[str]:
    """Collect domains from every URL field in an app record."""
    doms: set[str] = set()
    url_fields = ["developerWebsite", "privacyPolicy", "url"]
    for fld in url_fields:
        d = extract_domain(app.get(fld) or "")
        if d:
            doms.add(d)
    # also scan description text for any https:// links
    for txt in [app.get("description") or "", app.get("summary") or ""]:
        for match in URL_RE.findall(txt):
            d = extract_domain(match)
            if d and "." in d and not d.startswith("play.google"):
                doms.add(d)
    # strip tracking / play store noise
    noise = {"play.google.com", "support.google.com", "goo.gl", "bit.ly"}
    return doms - noise

def is_vpn_app(app: dict) -> bool:
    combined = " ".join([
        app.get("title", ""),
        app.get("summary", ""),
        app.get("description", "")[:200],
    ]).lower()
    return any(kw in combined for kw in VPN_KEYWORDS)

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"Loading {COMBINED} …")
    with open(COMBINED, encoding="utf-8") as f:
        all_apps = json.load(f)
    print(f"Total apps in dataset: {len(all_apps)}")

    target: list[dict] = []
    domain_apps: dict[str, set[str]] = {}   # domain → {appId, …}

    for app in all_apps:
        genre   = app.get("genre", "")
        app_id  = app.get("appId", "")
        matched = genre in TARGET_GENRES or is_vpn_app(app)
        if not matched:
            continue

        doms = domains_from_app(app)
        tag  = "vpn" if is_vpn_app(app) else genre.lower().replace(" & ", "_").replace(" ", "_")

        target.append({
            "appId":    app_id,
            "title":    app.get("title", ""),
            "genre":    genre,
            "tag":      tag,
            "score":    app.get("score"),
            "installs": app.get("minInstalls"),
            "domains":  sorted(doms),
        })
        for d in doms:
            domain_apps.setdefault(d, set()).add(app_id)

    # ── stats ─────────────────────────────────────────────────────────────────
    tags = {}
    for a in target:
        tags[a["tag"]] = tags.get(a["tag"], 0) + 1
    print(f"\nFiltered {len(target)} apps:")
    for t, n in sorted(tags.items(), key=lambda x: -x[1]):
        print(f"  {t:30s} {n:4d}")
    print(f"\nUnique domains: {len(domain_apps)}")

    # ── write outputs ─────────────────────────────────────────────────────────
    with open(OUT_APPS, "w", encoding="utf-8") as f:
        json.dump(target, f, indent=2)
    print(f"Wrote {OUT_APPS}")

    with open(OUT_DOMAINS, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "app_count", "apps_sample"])
        for dom, app_set in sorted(domain_apps.items()):
            w.writerow([dom, len(app_set), ";".join(sorted(app_set)[:5])])
    print(f"Wrote {OUT_DOMAINS}")

if __name__ == "__main__":
    main()
