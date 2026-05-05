"""
ml_clustering.py
================
Multi-algorithm ML analysis of TLS security posture across scanned domains.

Performs:
1. **Feature engineering** — 20+ features from TLS, cipher, cert, PQC, and
   vulnerability data
2. **Optimal k selection** — silhouette analysis across k=2..8
3. **Multi-algorithm clustering** — KMeans, Agglomerative, DBSCAN with
   comparison metrics
4. **Supervised feature importance** — Random Forest classifier trained on
   PQC readiness as target, revealing which TLS config features best predict
   quantum readiness
5. **PQC readiness predictor** — logistic regression model that scores
   likelihood of PQC adoption given current TLS configuration
6. **Cross-tabulation** — cluster × domain_class and cluster × category
   breakdowns for paper-ready tables

Input:
  data/report_per_domain.csv       (domain-level scan results)
  data/vulnerability_report.csv    (vulnerability & quantum risk scores)
  data/domain_classification.csv   (first-party/third-party labels)

Output:
  data/cluster_assignments.csv     — domain, cluster_id, cluster_label, features
  data/cluster_summary.txt         — full ML analysis report
  data/feature_importance.csv      — ranked feature importance for PQC prediction
  data/silhouette_analysis.csv     — silhouette scores per k
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
IN_DOMAIN = DATA_DIR / "report_per_domain.csv"
IN_VULN = DATA_DIR / "vulnerability_report.csv"
IN_CLASS = DATA_DIR / "domain_classification.csv"
OUT_ASSIGN = DATA_DIR / "cluster_assignments.csv"
OUT_SUMMARY = DATA_DIR / "cluster_summary.txt"
OUT_IMPORTANCE = DATA_DIR / "feature_importance.csv"
OUT_SILHOUETTE = DATA_DIR / "silhouette_analysis.csv"


def to_bool(v) -> int:
    if isinstance(v, bool):
        return int(v)
    s = str(v or "").strip().lower()
    return 1 if s in {"1", "true", "yes"} else 0


def safe_float(v, default=0.0) -> float:
    try:
        return float(v) if v not in {"", None} else default
    except (ValueError, TypeError):
        return default


def safe_int(v, default=0) -> int:
    try:
        return int(float(v)) if v not in {"", None} else default
    except (ValueError, TypeError):
        return default


def tls_version_ordinal(ver: str) -> int:
    """Map TLS version to ordinal for ML features."""
    v = (ver or "").upper()
    if "1.0" in v:
        return 1
    if "1.1" in v:
        return 2
    if "1.2" in v:
        return 3
    if "1.3" in v:
        return 4
    return 0  # unknown / scan error


def cipher_mode_ordinal(cipher: str) -> int:
    """Map cipher mode to ordinal (higher = more secure)."""
    c = (cipher or "").upper()
    if "RC4" in c:
        return 1
    if "3DES" in c or "DES-CBC3" in c:
        return 2
    if "CBC" in c:
        return 3
    if "CCM" in c:
        return 4
    if "GCM" in c:
        return 5
    if "CHACHA" in c:
        return 5
    return 0


def key_type_ordinal(kt: str) -> int:
    """Map cert key type to ordinal."""
    k = (kt or "").upper()
    if "RSA" in k:
        return 1
    if "EC" in k or "ECDSA" in k:
        return 2
    if "ED25519" in k:
        return 3
    return 0


def load_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if (r.get("domain") or "").strip():
                rows.append(r)
    return rows


def build_feature_matrix(domain_rows: list[dict], vuln_map: dict,
                          class_map: dict) -> tuple[list[dict], list[str]]:
    """
    Build a rich feature dictionary per domain.
    Returns (list of feature dicts, list of feature names).
    """
    feature_dicts = []

    for r in domain_rows:
        domain = r.get("domain", "")
        vuln = vuln_map.get(domain, {})
        dom_class = class_map.get(domain, "unknown")

        # TLS features
        tls_ord = tls_version_ordinal(r.get("scan_tls_ver", ""))
        is_tls13 = 1 if tls_ord == 4 else 0
        is_tls12 = 1 if tls_ord == 3 else 0
        is_legacy = 1 if tls_ord <= 2 else 0

        # Cipher features
        cipher_ord = cipher_mode_ordinal(r.get("scan_cipher", ""))
        is_aead = 1 if cipher_ord >= 4 else 0
        cipher_bits = safe_int(r.get("scan_cipher_bits"), 0)

        # Certificate features
        kt_ord = key_type_ordinal(r.get("scan_cert_key_type", ""))
        cert_bits = safe_int(r.get("scan_cert_key_bits"), 0)
        is_ec = 1 if kt_ord >= 2 else 0
        is_rsa = 1 if kt_ord == 1 else 0

        # Weakness flags
        flag_legacy = to_bool(r.get("scan_flag_legacy_tls"))
        flag_rsa_kx = to_bool(r.get("scan_flag_rsa_kx"))
        flag_rc4_3des = to_bool(r.get("scan_flag_rc4_3des"))
        flag_cert_small = to_bool(r.get("scan_flag_cert_small"))
        weak_count = safe_int(r.get("scan_weak_count"), 0)

        # PQC
        pqc_capable = to_bool(r.get("pqc_capable"))

        # Vulnerability features
        vuln_count = safe_int(vuln.get("vuln_count"), 0)
        cve_count = safe_int(vuln.get("cve_count"), 0)
        max_cvss = safe_float(vuln.get("max_cvss"), 0)
        security_score = safe_float(vuln.get("security_score"), 50)
        qrs = safe_float(vuln.get("quantum_risk_score"), 5)

        # Domain class features (one-hot)
        is_first_party = 1 if dom_class == "first_party" else 0
        is_cdn = 1 if dom_class == "cdn" else 0
        is_google = 1 if dom_class in ("google_services", "google_firebase") else 0
        is_ads = 1 if dom_class == "ads_analytics" else 0

        fd = {
            "tls_version_ord": tls_ord,
            "is_tls13": is_tls13,
            "is_tls12": is_tls12,
            "is_legacy_tls": is_legacy,
            "cipher_mode_ord": cipher_ord,
            "is_aead": is_aead,
            "cipher_bits": cipher_bits,
            "key_type_ord": kt_ord,
            "cert_bits": cert_bits,
            "is_ec_cert": is_ec,
            "is_rsa_cert": is_rsa,
            "flag_legacy_tls": flag_legacy,
            "flag_rsa_kx": flag_rsa_kx,
            "flag_rc4_3des": flag_rc4_3des,
            "flag_cert_small": flag_cert_small,
            "weak_count": weak_count,
            "vuln_count": vuln_count,
            "cve_count": cve_count,
            "max_cvss": max_cvss,
            "security_score": security_score,
            "quantum_risk_score": qrs,
            "is_first_party": is_first_party,
            "is_cdn": is_cdn,
            "is_google": is_google,
            "is_ads": is_ads,
            "pqc_capable": pqc_capable,
        }
        feature_dicts.append(fd)

    # Get consistent feature names (exclude target)
    feature_names = [k for k in feature_dicts[0] if k != "pqc_capable"]

    # Features for supervised models: exclude vuln-derived fields that encode
    # pqc_capable (data leakage: vulnerability_analysis.py penalises no_pqc_support,
    # so security_score/vuln_count/quantum_risk_score/cve_count/max_cvss contain
    # the label). Only raw TLS/cipher/cert features go into supervised analysis.
    supervised_feature_names = [k for k in feature_names
                                if k not in {"security_score", "vuln_count",
                                             "cve_count", "max_cvss",
                                             "quantum_risk_score"}]
    return feature_dicts, feature_names, supervised_feature_names


def choose_label(stats: dict) -> str:
    """Assign interpretive label to cluster based on aggregate stats."""
    pqc = stats["pqc_rate"]
    tls13 = stats["tls13_rate"]
    avg_sec = stats["avg_security_score"]
    avg_qrs = stats["avg_qrs"]

    if avg_qrs <= 2.5 and pqc > 0.8:
        return "quantum-ready"
    if pqc > 0.3 and tls13 > 0.7:
        return "pqc-transitioning"
    if tls13 > 0.7 and pqc <= 0.3:
        return "modern-classical"
    if avg_sec < 70:
        return "legacy-vulnerable"
    return "modern-classical"


def main():
    ap = argparse.ArgumentParser(description="ML Security Posture Analysis")
    ap.add_argument("--input", default=str(IN_DOMAIN))
    ap.add_argument("--max-clusters", type=int, default=8,
                    help="Max k for silhouette analysis")
    ap.add_argument("--random-state", type=int, default=42)
    args = ap.parse_args()

    try:
        from sklearn.cluster import KMeans, AgglomerativeClustering, DBSCAN
        from sklearn.preprocessing import StandardScaler
        from sklearn.metrics import silhouette_score, calinski_harabasz_score
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import cross_val_score
        import numpy as np
    except ImportError:
        print("[ERROR] scikit-learn and numpy not installed.")
        print("Install: pip install scikit-learn numpy")
        return

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[ERROR] {in_path} not found. Run analyze_results.py first.")
        return

    domain_rows = load_csv(in_path)
    vuln_rows = load_csv(IN_VULN)
    class_rows = load_csv(IN_CLASS)

    if not domain_rows:
        print("[ERROR] No domain rows found.")
        return

    print(f"Loaded {len(domain_rows)} domains, {len(vuln_rows)} vuln records, "
          f"{len(class_rows)} classifications")

    vuln_map = {r["domain"]: r for r in vuln_rows}
    class_map = {r["domain"]: r.get("domain_class", "unknown") for r in class_rows}

    feature_dicts, feature_names, supervised_feature_names = build_feature_matrix(
        domain_rows, vuln_map, class_map)

    # Filter to domains with actual scan data (exclude errors)
    valid_idx = [i for i, r in enumerate(domain_rows)
                 if not r.get("scan_error") and r.get("scan_tls_ver")]
    if len(valid_idx) < 10:
        print(f"[ERROR] Only {len(valid_idx)} valid domains – need at least 10.")
        return

    valid_dicts = [feature_dicts[i] for i in valid_idx]
    valid_rows = [domain_rows[i] for i in valid_idx]

    # Build numpy arrays
    X = np.array([[fd[fn] for fn in feature_names] for fd in valid_dicts], dtype=float)
    y_pqc = np.array([fd["pqc_capable"] for fd in valid_dicts], dtype=int)

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    n_samples = len(valid_idx)
    print(f"Feature matrix: {n_samples} samples × {len(feature_names)} features")

    lines = []
    lines.append("=" * 70)
    lines.append("  ML Security Posture Analysis")
    lines.append("=" * 70)
    lines.append(f"  Samples: {n_samples}  Features: {len(feature_names)}")
    lines.append(f"  PQC-capable: {y_pqc.sum()} ({y_pqc.sum()*100//n_samples}%)")
    lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # 1. Silhouette analysis for optimal k
    # ══════════════════════════════════════════════════════════════════
    lines.append("══ 1. Optimal Cluster Count (Silhouette Analysis) ═══════════════")
    sil_records = []
    best_k, best_sil = 2, -1

    max_k = min(args.max_clusters, n_samples - 1)
    for k in range(2, max_k + 1):
        km = KMeans(n_clusters=k, random_state=args.random_state, n_init=10)
        lab = km.fit_predict(Xs)
        sil = silhouette_score(Xs, lab)
        ch = calinski_harabasz_score(Xs, lab)
        sil_records.append({"k": k, "silhouette": round(sil, 4),
                            "calinski_harabasz": round(ch, 1)})
        lines.append(f"  k={k}: silhouette={sil:.4f}  CH-index={ch:.1f}")
        if sil > best_sil:
            best_sil = sil
            best_k = k

    lines.append(f"  → Best k = {best_k} (silhouette = {best_sil:.4f})")
    lines.append("")

    # Write silhouette CSV
    with open(OUT_SILHOUETTE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["k", "silhouette", "calinski_harabasz"])
        w.writeheader()
        w.writerows(sil_records)

    # ══════════════════════════════════════════════════════════════════
    # 2. Multi-algorithm clustering comparison
    # ══════════════════════════════════════════════════════════════════
    lines.append("══ 2. Clustering Algorithm Comparison ═══════════════════════════")

    # KMeans with optimal k
    km_model = KMeans(n_clusters=best_k, random_state=args.random_state, n_init=10)
    km_labels = km_model.fit_predict(Xs)
    km_sil = silhouette_score(Xs, km_labels)

    # Agglomerative with optimal k
    agg_model = AgglomerativeClustering(n_clusters=best_k)
    agg_labels = agg_model.fit_predict(Xs)
    agg_sil = silhouette_score(Xs, agg_labels)

    # DBSCAN (auto-k)
    dbscan_model = DBSCAN(eps=1.5, min_samples=5)
    db_labels = dbscan_model.fit_predict(Xs)
    n_db_clusters = len(set(db_labels) - {-1})
    n_db_noise = (db_labels == -1).sum()
    db_sil = silhouette_score(Xs, db_labels) if n_db_clusters >= 2 else -1

    lines.append(f"  {'Algorithm':<25s} {'Clusters':>9s} {'Silhouette':>11s}")
    lines.append("  " + "-" * 47)
    lines.append(f"  {'KMeans':<25s} {best_k:>9d} {km_sil:>11.4f}")
    lines.append(f"  {'Agglomerative':<25s} {best_k:>9d} {agg_sil:>11.4f}")
    lines.append(f"  {'DBSCAN':<25s} {n_db_clusters:>9d} {db_sil:>11.4f}"
                 f"  (noise: {n_db_noise})")

    # Select best algorithm
    algo_scores = [("KMeans", km_sil, km_labels),
                   ("Agglomerative", agg_sil, agg_labels)]
    if n_db_clusters >= 2:
        algo_scores.append(("DBSCAN", db_sil, db_labels))
    algo_scores.sort(key=lambda x: -x[1])
    best_algo, _, best_labels = algo_scores[0]
    lines.append(f"  → Best: {best_algo}")
    lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # 3. Cluster profiles
    # ══════════════════════════════════════════════════════════════════
    lines.append("══ 3. Cluster Profiles ═══════════════════════════════════════════")

    cluster_groups: dict[int, list[int]] = defaultdict(list)
    for i, cid in enumerate(best_labels):
        cluster_groups[int(cid)].append(i)

    cluster_stats = {}
    for cid in sorted(cluster_groups):
        indices = cluster_groups[cid]
        n = len(indices)

        pqc_rate = sum(valid_dicts[i]["pqc_capable"] for i in indices) / n
        tls13_rate = sum(valid_dicts[i]["is_tls13"] for i in indices) / n
        aead_rate = sum(valid_dicts[i]["is_aead"] for i in indices) / n
        ec_rate = sum(valid_dicts[i]["is_ec_cert"] for i in indices) / n
        avg_sec = sum(valid_dicts[i]["security_score"] for i in indices) / n
        avg_qrs = sum(valid_dicts[i]["quantum_risk_score"] for i in indices) / n
        avg_vuln = sum(valid_dicts[i]["vuln_count"] for i in indices) / n
        avg_cert_bits = sum(valid_dicts[i]["cert_bits"] for i in indices) / n

        stats = {
            "count": n, "pqc_rate": pqc_rate, "tls13_rate": tls13_rate,
            "aead_rate": aead_rate, "ec_rate": ec_rate,
            "avg_security_score": avg_sec, "avg_qrs": avg_qrs,
            "avg_vuln_count": avg_vuln, "avg_cert_bits": avg_cert_bits,
        }
        stats["label"] = choose_label(stats)
        cluster_stats[cid] = stats

        cid_display = cid if cid >= 0 else "noise"
        lines.append(f"  Cluster {cid_display} → {stats['label']} (n={n})")
        lines.append(f"    PQC capable : {pqc_rate:.0%}")
        lines.append(f"    TLS 1.3     : {tls13_rate:.0%}")
        lines.append(f"    AEAD cipher : {aead_rate:.0%}")
        lines.append(f"    EC cert     : {ec_rate:.0%}")
        lines.append(f"    Avg security: {avg_sec:.1f}/100")
        lines.append(f"    Avg QRS     : {avg_qrs:.1f}/10")
        lines.append(f"    Avg vulns   : {avg_vuln:.1f}")
        lines.append(f"    Avg cert bits: {avg_cert_bits:.0f}")
        samples = [valid_rows[i].get("domain", "") for i in indices[:6]]
        lines.append(f"    Samples     : {', '.join(samples)}")
        lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # 4. Supervised feature importance (Random Forest)
    # ══════════════════════════════════════════════════════════════════
    lines.append("══ 4. Feature Importance for PQC Readiness (Random Forest) ══════")
    lines.append("  NOTE: Only raw TLS/cipher/cert features used (vuln-derived scores")
    lines.append("  excluded to prevent data leakage from pqc_capable label).")
    lines.append("")

    # Build supervised feature matrix (no leaking features)
    X_sup = np.array([[fd[fn] for fn in supervised_feature_names]
                      for fd in valid_dicts], dtype=float)
    Xs_sup = scaler.fit_transform(X_sup)

    if y_pqc.sum() > 5 and (n_samples - y_pqc.sum()) > 5:
        rf = RandomForestClassifier(n_estimators=200, random_state=args.random_state,
                                     class_weight="balanced")
        rf.fit(X_sup, y_pqc)
        importances = rf.feature_importances_

        # Cross-validation accuracy
        n_folds = min(5, min(y_pqc.sum(), n_samples - y_pqc.sum()))
        if n_folds >= 2:
            cv_scores = cross_val_score(rf, X_sup, y_pqc, cv=n_folds, scoring="accuracy")
            lines.append(f"  Cross-validation accuracy: {cv_scores.mean():.3f} "
                        f"(±{cv_scores.std():.3f}, {n_folds}-fold)")
        else:
            lines.append("  (Insufficient class balance for cross-validation)")

        # Rank features
        feat_imp = sorted(zip(supervised_feature_names, importances),
                          key=lambda x: -x[1])
        lines.append(f"  {'Feature':<25s} {'Importance':>12s}")
        lines.append("  " + "-" * 39)
        for fn, imp in feat_imp:
            bar = "\u2588" * int(imp * 40)
            lines.append(f"  {fn:<25s} {imp:>12.4f}  {bar}")

        # Write feature importance CSV
        with open(OUT_IMPORTANCE, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["rank", "feature", "importance"])
            w.writeheader()
            for rank, (fn, imp) in enumerate(feat_imp, 1):
                w.writerow({"rank": rank, "feature": fn,
                            "importance": round(imp, 6)})
        print(f"Wrote {OUT_IMPORTANCE}")
    else:
        lines.append("  [SKIP] Insufficient PQC class balance for supervised analysis")
    lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # 5. PQC readiness predictor (Logistic Regression)
    # ══════════════════════════════════════════════════════════════════
    lines.append("══ 5. PQC Readiness Predictor (Logistic Regression) ═════════════")

    if y_pqc.sum() > 5 and (n_samples - y_pqc.sum()) > 5:
        lr = LogisticRegression(max_iter=1000, random_state=args.random_state,
                                 class_weight="balanced")
        lr.fit(Xs_sup, y_pqc)

        n_folds_lr = min(5, min(y_pqc.sum(), n_samples - y_pqc.sum()))
        if n_folds_lr >= 2:
            lr_cv = cross_val_score(lr, Xs_sup, y_pqc, cv=n_folds_lr,
                                    scoring="accuracy")
            lines.append(f"  Cross-validation accuracy: {lr_cv.mean():.3f} "
                        f"(\u00b1{lr_cv.std():.3f})")

        # Top positive/negative coefficients
        coefs = list(zip(supervised_feature_names, lr.coef_[0]))
        coefs_sorted = sorted(coefs, key=lambda x: -abs(x[1]))
        lines.append(f"  {'Feature':<25s} {'Coefficient':>12s} {'Direction':>10s}")
        lines.append("  " + "-" * 49)
        for fn, coef in coefs_sorted[:10]:
            direction = "-> PQC" if coef > 0 else "-> no-PQC"
            lines.append(f"  {fn:<25s} {coef:>12.4f} {direction:>10s}")
    else:
        lines.append("  [SKIP] Insufficient class balance")
    lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # 6. Cross-tabulation: cluster × domain_class
    # ══════════════════════════════════════════════════════════════════
    lines.append("══ 6. Cluster × Domain Class Cross-Tabulation ═══════════════════")

    xtab: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for i, cid in enumerate(best_labels):
        domain = valid_rows[i].get("domain", "")
        dc = class_map.get(domain, "unknown")
        label = cluster_stats.get(int(cid), {}).get("label", f"cluster_{cid}")
        xtab[label][dc] += 1

    all_classes = sorted({dc for row in xtab.values() for dc in row})
    header = f"  {'Cluster':<22s}" + "".join(f"{c:>14s}" for c in all_classes)
    lines.append(header)
    lines.append("  " + "-" * (22 + 14 * len(all_classes)))
    for label in sorted(xtab):
        row_str = f"  {label:<22s}"
        for c in all_classes:
            row_str += f"{xtab[label][c]:>14d}"
        lines.append(row_str)

    lines += ["", "=" * 70]

    # ── Write cluster assignments ────────────────────────────────────
    OUT_ASSIGN.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_ASSIGN, "w", newline="", encoding="utf-8") as f:
        fields = [
            "domain", "domain_class", "cluster_id", "cluster_label",
            "scan_tls_ver", "scan_cipher", "scan_cert_key_type",
            "scan_cert_key_bits", "pqc_capable",
            "security_score", "quantum_risk_score",
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for i, r in enumerate(valid_rows):
            cid = int(best_labels[i])
            domain = r.get("domain", "")
            w.writerow({
                "domain": domain,
                "domain_class": class_map.get(domain, "unknown"),
                "cluster_id": cid,
                "cluster_label": cluster_stats.get(cid, {}).get("label", ""),
                "scan_tls_ver": r.get("scan_tls_ver", ""),
                "scan_cipher": r.get("scan_cipher", ""),
                "scan_cert_key_type": r.get("scan_cert_key_type", ""),
                "scan_cert_key_bits": r.get("scan_cert_key_bits", ""),
                "pqc_capable": r.get("pqc_capable", ""),
                "security_score": valid_dicts[i].get("security_score", ""),
                "quantum_risk_score": valid_dicts[i].get("quantum_risk_score", ""),
            })

    summary_text = "\n".join(lines)
    OUT_SUMMARY.write_text(summary_text, encoding="utf-8")

    print(f"Wrote {OUT_ASSIGN}")
    print(f"Wrote {OUT_SILHOUETTE}")
    print(f"Wrote {OUT_SUMMARY}")
    print()
    sys.stdout.buffer.write((summary_text + "\n").encode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
