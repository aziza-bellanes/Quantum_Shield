"""
APK domain extractor.

Extracts domains from APK files using:
1. apktool to decompile the APK
2. Parse AndroidManifest.xml for network config
3. Parse network_security_config.xml for domain pins
4. Regex scan for URLs in smali/resource files
"""

import subprocess
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional


URL_PATTERN = re.compile(
    r'https?://([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)',
    re.IGNORECASE,
)

# Domains to exclude (development/test/internal)
EXCLUDE_DOMAINS = {
    "localhost", "127.0.0.1", "example.com", "example.org",
    "schemas.android.com", "schemas.microsoft.com",
    "www.w3.org", "ns.adobe.com", "xmlpull.org",
}


def extract_domains_from_apk(apk_path: str, work_dir: Optional[str] = None) -> list[str]:
    """
    Extract all unique domains from an APK file.
    Returns a sorted list of unique domain names.
    """
    apk = Path(apk_path)
    if not apk.exists():
        return []

    if work_dir:
        output_dir = Path(work_dir) / apk.stem
    else:
        output_dir = apk.parent / f"{apk.stem}_decompiled"

    domains = set()

    # Step 1: Decompile APK with apktool
    try:
        subprocess.run(
            ["apktool", "d", str(apk), "-o", str(output_dir), "-f"],
            capture_output=True, text=True, timeout=120,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # apktool not available — try basic extraction
        return _basic_extract(apk_path)

    # Step 2: Parse AndroidManifest.xml
    manifest = output_dir / "AndroidManifest.xml"
    if manifest.exists():
        domains.update(_parse_manifest(manifest))

    # Step 3: Parse network_security_config.xml
    nsc = output_dir / "res" / "xml" / "network_security_config.xml"
    if nsc.exists():
        domains.update(_parse_network_security_config(nsc))

    # Step 4: Scan all text files for URLs
    for ext in ("*.xml", "*.json", "*.smali", "*.txt", "*.properties"):
        for f in output_dir.rglob(ext):
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
                for match in URL_PATTERN.finditer(text):
                    domain = match.group(1).lower().rstrip(".")
                    if domain not in EXCLUDE_DOMAINS and "." in domain:
                        domains.add(domain)
            except Exception:
                continue

    return sorted(domains)


def _parse_manifest(manifest_path: Path) -> set[str]:
    """Extract domains from AndroidManifest.xml intent filters."""
    domains = set()
    try:
        tree = ET.parse(manifest_path)
        for elem in tree.iter():
            for attr in elem.attrib.values():
                if isinstance(attr, str):
                    for match in URL_PATTERN.finditer(attr):
                        d = match.group(1).lower().rstrip(".")
                        if d not in EXCLUDE_DOMAINS and "." in d:
                            domains.add(d)
    except ET.ParseError:
        pass
    return domains


def _parse_network_security_config(nsc_path: Path) -> set[str]:
    """Extract pinned domains from network_security_config.xml."""
    domains = set()
    try:
        tree = ET.parse(nsc_path)
        for domain_elem in tree.iter("domain"):
            d = (domain_elem.text or "").strip().lower().rstrip(".")
            if d and d not in EXCLUDE_DOMAINS and "." in d:
                domains.add(d)
    except ET.ParseError:
        pass
    return domains


def _basic_extract(apk_path: str) -> list[str]:
    """Fallback: extract URLs from APK as a zip file."""
    import zipfile
    domains = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.endswith((".xml", ".json", ".txt")):
                    try:
                        text = z.read(name).decode("utf-8", errors="ignore")
                        for match in URL_PATTERN.finditer(text):
                            d = match.group(1).lower().rstrip(".")
                            if d not in EXCLUDE_DOMAINS and "." in d:
                                domains.add(d)
                    except Exception:
                        continue
    except Exception:
        pass
    return sorted(domains)
