# QuantumShield  — Full-Stack TLS & PQC Security Platform

A full-stack cybersecurity dashboard for **TLS analysis** and **Post-Quantum Cryptography (PQC) readiness** scoring of Android applications.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Layout](#2-repository-layout)
3. [Tech Stack](#3-tech-stack)
4. [Quick Start (Local Dev)](#4-quick-start-local-dev)
5. [Environment Variables](#5-environment-variables)
6. [Frontend Architecture](#6-frontend-architecture)
7. [Backend Architecture](#7-backend-architecture)
8. [Database Schema](#8-database-schema)
9. [API Reference](#9-api-reference)
10. [Authentication & JWT](#10-authentication--jwt)
11. [OAuth — Google & GitHub](#11-oauth--google--github)
12. [Two-Factor Authentication (TOTP)](#12-two-factor-authentication-totp)
13. [Forgot-Password Flow](#13-forgot-password-flow)
14. [Roles & Access Control](#14-roles--access-control)
15. [TLS Scan Pipeline](#15-tls-scan-pipeline)
16. [ML Prediction Pipeline](#16-ml-prediction-pipeline)
17. [App Report Page](#17-app-report-page)
18. [Notifications System](#18-notifications-system)
19. [DB Management & Sync Jobs](#19-db-management--sync-jobs)
20. [Reports System](#20-reports-system)
21. [User Management (Admin)](#21-user-management-admin)
22. [System Monitor (Admin)](#22-system-monitor-admin)
23. [SDK & API Key Integration](#23-sdk--api-key-integration)
24. [Docker / Production Deployment](#24-docker--production-deployment)
25. [Switching to PostgreSQL](#25-switching-to-postgresql)
26. [Demo Accounts](#26-demo-accounts)
27. [Seeding from Research CSV](#27-seeding-from-research-csv)
28. [Developer Guides](#28-developer-guides)
29. [Known Gotchas](#29-known-gotchas)
30. [Scripts Reference](#30-scripts-reference)

---

## 1. Project Overview

QuantumShield  scans Android apps for TLS weaknesses and post-quantum cryptography (PQC) exposure, scores them using an ML pipeline, and surfaces results through a role-based React dashboard.

**Core capabilities:**

| Capability | Detail |
|---|---|
| TLS analysis | Per-domain TLS version, cipher suite, key exchange, cert info, PQC support flags |
| ML risk scoring | scikit-learn classifier → `security_score`, `risk_level`, `pqc_readiness_score` |
| Role-based dashboard | End users see all public apps; owners/admins see own portfolio |
| OAuth login | Google ID-token flow + GitHub authorization-code flow |
| TOTP 2FA | Google Authenticator compatible; required for password reset if enabled |
| Forgot-password | Real SMTP email with 15-minute secure reset link |
| App report | Printable per-app report with charts, TLS table, vulnerability breakdown, ML prediction |
| Notifications | Role-aware real-time bell (polls backend, session-scoped, persistent dismissals) |
| DB Management | Live knowledge-base sync with job tracking, auto-scheduler, import/export |
| Reports | Auto-generated monthly/quarterly aggregate reports with live stats |
| SDK | Python and JavaScript SDKs with API-key auth |
| Admin tools | User management, system health, ML retraining, CSV seeding |

---

## 2. Repository Layout

```
PCD-2.0-main/
│
├── README.md
│
├── QuantumShield2.0/                  ← React 19 frontend (Vite + TypeScript)
│   ├── src/
│   │   ├── App.tsx                    ← route definitions (all pages lazy-loaded)
│   │   ├── main.tsx                   ← React entry point
│   │   ├── index.css                  ← Tailwind v4 globals, font, scrollbar, eye-icon fix
│   │   │
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx          ← email/pwd + Google + GitHub + forgot-password panel
│   │   │   ├── SignUpPage.tsx         ← registration + Google + GitHub
│   │   │   ├── ResetPasswordPage.tsx  ← reads ?token= from URL, submits new password
│   │   │   ├── GithubCallbackPage.tsx ← GitHub OAuth callback handler
│   │   │   ├── DashboardPage.tsx      ← KPI cards + TLS bar chart + risk donut (role-scoped)
│   │   │   ├── BrowseAppsPage.tsx     ← app list + Sheet detail panel (global, deduplicated)
│   │   │   ├── AnalyzeAppPage.tsx     ← APK upload / package-name submission
│   │   │   ├── MyApplicationsPage.tsx ← portfolio view for app_owner/admin + View Report button
│   │   │   ├── AppReportPage.tsx      ← standalone printable security report with charts
│   │   │   ├── AccountPage.tsx        ← profile, password, 2FA, sessions, API key
│   │   │   ├── ReportsPage.tsx        ← aggregated reports list with KPI cards + charts
│   │   │   ├── ContactPage.tsx        ← contact form (persisted + optional SMTP)
│   │   │   ├── UserManagementPage.tsx ← admin: CRUD users, role change, force logout, reset 2FA
│   │   │   ├── SystemMonitorPage.tsx  ← admin: health, scan queue, ML metrics, CSV seed button
│   │   │   └── DatabaseManagementPage.tsx ← admin: KB sync, job history, import/export, scheduler config
│   │   │
│   │   ├── components/
│   │   │   ├── auth/ProtectedRoute.tsx      ← role-gate wrapper
│   │   │   ├── layout/AppLayout.tsx         ← sidebar + topbar shell
│   │   │   ├── layout/AppSidebar.tsx        ← nav links per role; footer → /account
│   │   │   ├── layout/Topbar.tsx            ← theme toggle + notification bell
│   │   │   ├── charts/TlsBarChart.tsx       ← Recharts bar chart
│   │   │   ├── charts/RiskDonutChart.tsx    ← Recharts donut chart
│   │   │   ├── theme-provider.tsx
│   │   │   └── ui/                          ← shadcn/ui components (Radix-based)
│   │   │
│   │   ├── context/AuthContext.tsx    ← user session, login/register/OAuth/logout
│   │   ├── hooks/useNotifications.ts  ← role-based polling, localStorage persistence
│   │   ├── hooks/use-mobile.ts
│   │   └── lib/
│   │       ├── api.ts                 ← ALL fetch calls (single source of truth)
│   │       ├── types.ts               ← shared TypeScript interfaces
│   │       └── utils.ts               ← roleLabel(), cn(), scoreColor(), formatDateTime(), etc.
│   │
│   ├── public/
│   │   ├── favicon.svg                ← atomic-orbit SVG favicon (#818cf8 indigo)
│   │   └── robots.txt                 ← blocks /auth, /admin, /users, etc.
│   ├── vite.config.ts                 ← dev proxy + manualChunks vendor splitting
│   ├── tsconfig.json
│   ├── package.json
│   └── components.json                ← shadcn/ui config
│
├── PCD-main/tls-analyzer/             ← FastAPI backend
│   ├── backend/
│   │   ├── main.py                    ← app factory, CORS, security-headers middleware, lifespan
│   │   ├── config.py                  ← all env vars loaded via python-dotenv
│   │   ├── database.py                ← async SQLAlchemy engine + session factory
│   │   ├── seed.py                    ← idempotent DB seeding (users, pipeline data, KBs, reports)
│   │   ├── limiter.py                 ← slowapi rate-limiter instance
│   │   ├── requirements.txt
│   │   │
│   │   ├── models/
│   │   │   └── db_models.py           ← all SQLAlchemy ORM models
│   │   │
│   │   ├── schemas/
│   │   │   └── pydantic_schemas.py    ← all Pydantic v2 request/response models
│   │   │
│   │   ├── routers/
│   │   │   ├── auth.py                ← /auth/* (login, register, OAuth, 2FA, forgot/reset password)
│   │   │   ├── apps.py                ← /apps/* (CRUD, scan, stats, reports)
│   │   │   ├── admin.py               ← /admin/* (users, system health, CSV seed, send-email)
│   │   │   ├── model.py               ← /admin/ml/* (train, predict)
│   │   │   ├── databases.py           ← /admin/databases/* (KB sync, job history, import/export, config, scheduler)
│   │   │   ├── reports.py             ← /reports/* (list, download, regenerate)
│   │   │   └── contact.py             ← /contact/
│   │   │
│   │   └── services/
│   │       ├── tls_scanner.py         ← TLS scan logic (per-domain)
│   │       ├── ml_predictor.py        ← model load/predict
│   │       ├── warranty_engine.py     ← security warranty issuance logic
│   │       ├── report_generator.py    ← PDF + JSON report generation
│   │       ├── apk_extractor.py       ← APK domain extraction
│   │       ├── cve_mapper.py          ← CVE to domain mapping
│   │       └── nvd_client.py          ← NVD API client for vulnerability data
│   │
│   ├── ml/
│   │   └── model.pkl                  ← trained scikit-learn model (auto-generated on first run)
│   │
│   ├── pqc-research/
│   │   └── data/
│   │       ├── target_apps.json           ← app metadata (727 brands)
│   │       ├── report_per_domain.csv      ← domain-level TLS scan results
│   │       ├── report_per_app.csv         ← app-level TLS scan aggregates
│   │       ├── vulnerability_report.csv   ← CVE / domain mapping
│   │       ├── domain_classification.csv  ← domain categorisation (first-party, CDN, ads…)
│   │       ├── cluster_assignments.csv    ← ML clustering results
│   │       └── feature_importance.csv     ← Random Forest feature importances
│   │
│   ├── sdk/
│   │   ├── python/                    ← Python SDK (pip install -e sdk/python/)
│   │   └── javascript/                ← JavaScript SDK (native fetch, Node 18+)
│   │
│   ├── uploads/                       ← uploaded APK files (runtime, gitignored)
│   ├── tls_analyzer.db                ← SQLite dev DB (auto-created, gitignored)
│   ├── .env                           ← backend secrets (gitignored)
│   └── docker-compose.yml
```

---

## 3. Tech Stack

### Frontend

| Tool | Version | Purpose |
|---|---|---|
| React | 19 | UI library |
| TypeScript | 5 | Type safety |
| Vite | 6 | Build tool / dev server |
| Tailwind CSS | v4 | Utility-first styling |
| shadcn/ui | latest | Radix-based component library |
| Recharts | 2 | Bar, donut, and radial charts |
| `@react-oauth/google` | latest | Google OAuth ID-token flow |
| Lucide React | latest | Icons |
| React Router | v7 | Client-side routing |
| Zod | 3 | Form validation schemas |

### Backend

| Tool | Version | Purpose |
|---|---|---|
| FastAPI | ≥0.111 | REST API framework (async) |
| SQLAlchemy (async) | ≥2.0 | ORM |
| aiosqlite | ≥0.18 | SQLite async driver (dev) |
| asyncpg | ≥0.29 | PostgreSQL async driver (prod) |
| Pydantic v2 | ≥2.7 | Schema validation |
| PyJWT | ≥2.8 | JWT signing (auth + password-reset tokens) |
| passlib + bcrypt | 4.0.1 | Password hashing |
| pyotp | ≥2.9 | TOTP 2FA code generation/verification |
| qrcode[pil] | ≥7.4 | QR code image for 2FA setup |
| scikit-learn | ≥1.5 | ML risk prediction (Random Forest) |
| reportlab | ≥4.2 | PDF generation |
| httpx | ≥0.27 | GitHub OAuth code exchange |
| google-auth | latest | Google ID token verification |
| slowapi | ≥0.1.9 | Rate limiting on auth endpoints |
| smtplib (stdlib) | — | SMTP email (password reset + contact + admin send-mail) |
| python-dotenv | ≥1.0 | Env var loading |
| python-multipart | ≥0.0.9 | File upload (APK, import) |

---

## 4. Quick Start (Local Dev)

### Prerequisites

- Python 3.12
- Node.js 20+
- npm 10+

### Step 1 — Backend

```bash
cd PCD-main/tls-analyzer

# Install Python dependencies
pip install -r backend/requirements.txt

# Start the server (run from tls-analyzer/, NOT from inside backend/)
python -m uvicorn backend.main:app --reload
```

- API base: `http://localhost:8000`
- Interactive docs: `http://localhost:8000/docs`
- The database (`tls_analyzer.db`) is **auto-created** on first run.
- Demo users and seed data are inserted automatically on startup.

> **After a schema change:** delete `PCD-main/tls-analyzer/tls_analyzer.db` and restart. SQLAlchemy will recreate all tables and re-seed automatically.

### Step 2 — Frontend

```bash
cd QuantumShield2.0
npm install
npm run dev
```

- App URL: `http://localhost:5173`

---

## 5. Environment Variables

### Frontend — `QuantumShield2.0/.env.local`

```env
# Backend base URL (no trailing slash)
VITE_API_URL=http://localhost:8000

# Google OAuth — get from Google Cloud Console → APIs & Services → Credentials
# Add http://localhost:5173 to Authorized JavaScript Origins
VITE_GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com

# GitHub OAuth — get from GitHub Settings → Developer settings → OAuth Apps
# Set callback URL to: http://localhost:5173/auth/github/callback
VITE_GITHUB_CLIENT_ID=your-github-oauth-app-client-id
```

### Backend — `PCD-main/tls-analyzer/.env`

```env
# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL=sqlite+aiosqlite:///./tls_analyzer.db
# PostgreSQL (production):
# DATABASE_URL=postgresql+asyncpg://user:password@host:5432/dbname

# ── JWT ───────────────────────────────────────────────────────────────────────
JWT_SECRET=change-me-use-a-long-random-string-in-production
JWT_EXPIRE_MINUTES=1440          # 24 hours

# ── ML pipeline data ──────────────────────────────────────────────────────────
PIPELINE_DATA_DIR=./pqc-research/data

# ── Scan behaviour ────────────────────────────────────────────────────────────
SCAN_TIMEOUT=10
SCAN_CONCURRENCY=20

# ── SMTP — required for forgot-password, contact form, admin send-mail ────────
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your.email@gmail.com
SMTP_PASSWORD=abcdefghijklmnop    # Gmail 16-char App Password — NO spaces
CONTACT_RECIPIENT=recipient@example.com
FRONTEND_URL=http://localhost:5173

# ── OAuth secrets ─────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GITHUB_CLIENT_ID=your-github-oauth-app-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-app-client-secret
```

> **Gmail App Password:** Enable 2-Step Verification → go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) → generate → **remove all spaces** before pasting into `.env`.

---

## 6. Frontend Architecture

### Routing & Lazy Loading

All 15 pages are lazy-loaded via `React.lazy` + `Suspense` in `App.tsx`. Each page compiles into a separate JS chunk downloaded only on first visit.

`vite.config.ts` defines `manualChunks` for vendor splitting:

| Chunk | Libraries |
|---|---|
| `vendor-react` | react, react-dom, react-router-dom |
| `vendor-charts` | recharts + d3 helpers |
| `vendor-radix` | @radix-ui primitives |
| `vendor-oauth` | @react-oauth/google |
| `vendor-icons` | lucide-react |

> Always use `React.lazy` for new pages — a plain top-level `import` collapses it back into the main bundle.

### API Client — `src/lib/api.ts`

Every HTTP call goes through this single file. It:
1. Reads `VITE_API_URL` (defaults to `http://localhost:8000`)
2. Attaches `Authorization: Bearer <token>` from `localStorage` / `sessionStorage` key `qs_token`
3. Throws `ApiError(status, message)` on non-2xx responses

API groups exported: `authApi`, `profileApi`, `appsApi`, `adminApi`, `databasesApi`, `reportsApi`, `contactApi`

### Token & Session Storage

| Key | Storage | Lifetime |
|---|---|---|
| `qs_token` | `localStorage` (remember=true) or `sessionStorage` | JWT_EXPIRE_MINUTES (24 h) |
| `qs_user` | `localStorage` | Until logout or token expiry |
| `qs_notif_seen` | `localStorage` | Persists across logins |
| `qs_notif_dismissed` | `localStorage` | Permanent across logins |
| `qs_session_expired` | `sessionStorage` | One-time flag for expiry banner |

### Vite Dev Proxy

`vite.config.ts` proxies `/auth`, `/apps`, `/admin`, `/reports`, `/contact`, `/health` to `http://localhost:8000` — no cross-origin requests during development. A `bypass` function exempts `/auth/github/callback` so React Router handles it instead of forwarding it to the backend.

### State Management

- **Auth state:** `AuthContext` (React Context) — wraps app in `main.tsx`
- **Server state:** fetched directly in each page via API calls
- **Notifications:** `useNotifications` hook — polling + localStorage persistence
- No Redux, no Zustand

### Key Auth Flows

**Email/password login:**
```
LoginPage → authApi.login() → saveToken() → authApi.me() → setUser() → /dashboard
```

**OAuth (Google / GitHub):**
```
Provider button → credential/code → POST /auth/google or /auth/github
  → JWT returned → saveToken() → authApi.me() → setUser()
  → if new account (created_at < 60s) → role-selection modal
  → POST /auth/set-role → navigate /dashboard
```

**Forgot password:**
```
LoginPage forgot form → POST /auth/forgot-password
  → if 2FA enabled → frontend shows TOTP code input
  → backend sends SMTP email with reset link (/reset-password?token=…)
  → user clicks link → ResetPasswordPage → POST /auth/reset-password → /login
```

### Google Button Overlay Pattern

`GoogleLogin` renders Google's iframe button. We overlay it with a styled `<Button>` (pointer-events-none) and make the Google element invisible but clickable at `opacity: 0.001`:

```tsx
<div className="relative h-9">
  <Button variant="outline" className="pointer-events-none …">
    <GoogleIcon /> Continue with Google
  </Button>
  <div className="absolute inset-0 overflow-hidden" style={{ opacity: 0.001 }}>
    <GoogleLogin onSuccess={onSuccess} … />
  </div>
</div>
```

### UI Details

- **Password eye icon:** Suppressed in `index.css` (`input[type="password"]::-ms-reveal { display: none }`) to avoid a duplicate next to the React-rendered toggle.
- **Scrollbars:** Thin (5 px), invisible at rest, visible on hover — applied globally in `index.css`.
- **Sidebar footer:** Avatar button navigates to `/account` on click.
- **Loading spinners:** `aria-hidden="true"` on the span; `aria-busy={loading}` on the parent `<Button>`.

---

## 7. Backend Architecture

### Security Headers Middleware

Every response receives:

| Header | Value |
|---|---|
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` |

Swagger UI routes (`/docs`, `/redoc`, `/openapi`) use a relaxed CSP that allows the CDN scripts.

### Startup Sequence (lifespan)

```
FastAPI starts
  → init_db()                       # CREATE TABLE IF NOT EXISTS for all ORM models
  → seed_demo_users()               # insert 3 demo accounts (idempotent)
  → seed_from_pipeline()            # load pqc-research/data JSONs if DB is empty
  → repair_missing_predictions()    # fill MLPrediction + SecurityWarranty for apps missing them
  → seed_static_data()              # seed knowledge bases + sample reports
  → reset stuck "syncing" KBs       # any KB left in "syncing" from a crashed run → "synced"
  → asyncio.create_task(scheduler_loop())   # auto-sync scheduler (60 s interval)
  → app ready
  [on shutdown]
  → scheduler_task.cancel()         # clean shutdown
```

### Router Map

| File | Prefix | Key endpoints |
|---|---|---|
| `auth.py` | `/auth` | `POST /login`, `POST /register`, `GET /me`, `PATCH /profile`, `POST /change-password`, `POST /set-role`, `POST /forgot-password`, `POST /reset-password`, `GET/PATCH /preferences`, `GET/POST /api-key`, `GET/DELETE /sessions`, `POST /2fa/setup`, `POST /2fa/verify`, `POST /2fa/disable`, `POST /google`, `POST /github` |
| `apps.py` | `/apps` | `GET /`, `GET /{id}`, `POST /submit`, `POST /upload-apk`, `GET /stats`, `GET /{id}/prediction`, `GET /{id}/vulnerabilities`, `GET /{id}/domains`, `GET /{id}/tls`, `GET /{id}/warranty`, `GET /{id}/report`, `GET /recent-completions`, `GET /recent-public`, `PATCH /{id}/visibility` |
| `admin.py` | `/admin` | `GET /users`, `POST /users`, `PATCH /users/{id}/role`, `DELETE /users/{id}`, `GET /users/{id}/sessions`, `DELETE /users/{id}/sessions`, `DELETE /users/{id}/2fa`, `POST /users/{id}/send-email`, `GET /system/health`, `GET /ml-metrics`, `GET /recent-scans`, `GET /scan-queue`, `GET /metrics/timeseries`, `POST /seed-csv` |
| `model.py` | `/admin/ml` | `POST /train`, `POST /predict/{app_id}` |
| `databases.py` | `/admin/databases` | `GET /`, `GET /jobs`, `POST /sync-all`, `POST /{id}/sync`, `GET /{id}/export`, `POST /{id}/import`, `GET /config`, `PATCH /config` |
| `reports.py` | `/reports` | `GET /`, `GET /{id}/download`, `POST /regenerate` |
| `contact.py` | `/contact` | `POST /` |

### Rate Limiting

`slowapi` protects auth endpoints:

| Endpoint | Limit |
|---|---|
| `POST /auth/login` | 10 req / min / IP |
| `POST /auth/register` | 5 req / min / IP |
| `POST /auth/forgot-password` | 3 req / min / IP |

---

## 8. Database Schema

All tables defined in `backend/models/db_models.py`. SQLAlchemy creates them on startup via `create_all`.

```
users
  id, email (unique), password_hash, role               # end_user | app_owner | admin
  name, company, phone, date_of_birth, location, bio
  totp_secret, totp_enabled
  created_at

user_preferences
  id, user_id (FK→users), email_notifications, security_alerts
  weekly_reports, product_updates

user_api_keys
  id, user_id (FK→users), key (unique, qs_live_sk_…)
  created_at, last_used_at

user_sessions
  id, user_id (FK→users), browser, os, ip
  created_at, last_seen_at, is_active

applications
  id, package_name, apk_path, app_name, category
  install_count, rating, description, is_public
  owner_id (FK→users, nullable for seeded apps)
  submitted_at, scan_status                              # pending | scanning | completed | failed
  scanned_at (nullable)                                  # set when scan completes/fails
  made_public_at (nullable)                              # set when is_public toggled True

domains
  id, app_id (FK→applications), domain, ip, country
  is_third_party, domain_class

tls_results
  id, domain_id (FK→domains)
  tls_version, cipher_suite, key_exchange
  cert_expiry, cert_issuer, cert_validity_days, cert_key_type, cert_key_bits
  supports_pqc, pqc_group, has_ecdh, has_rsa_key_exchange
  flag_legacy_tls, flag_rc4_or_3des
  cipher_strength_score, quantum_risk_score, security_score
  scan_date, scan_error

vulnerabilities
  id, tls_result_id (FK→tls_results)
  cve_id, severity, cvss_score, description, reference_url

ml_predictions
  id, app_id (FK→applications)
  security_score, risk_level, pqc_readiness_score
  confidence, feature_importances (JSON), predicted_at

security_warranties
  id, app_id (FK→applications)
  status                                                 # Certified | Conditional | Not Certified
  issued_at, expires_at, justification

knowledge_bases
  id, name, type, records, size, status                  # synced | syncing | error
  source, last_sync

sync_configs
  id (always 1 — single-row config), sync_interval, backup_retention

sync_jobs
  id, kb_id (FK→knowledge_bases, nullable on delete SET NULL)
  kb_name (snapshot at job creation)
  operation                                              # sync | sync-all | import | export
  status                                                 # running | success | error
  started_at, finished_at (nullable)
  records_before (nullable), records_after (nullable)
  error_msg (nullable)
  triggered_by                                           # manual | scheduler

reports
  id, title, date, type                                  # weekly | monthly | quarterly | custom
  apps_count, status                                     # ready | generating | failed
  created_at

contact_messages
  id, name, email, subject, message, created_at, is_read
```

**Key relationships:**
- `User` → `Application` (one-to-many via `owner_id`)
- `Application` → `Domain` → `TLSResult` → `Vulnerability`
- `Application` → `MLPrediction`, `SecurityWarranty`
- `User` → `UserPreferences`, `UserApiKey`, `UserSession`
- `KnowledgeBase` → `SyncJob` (one-to-many)

---

## 9. API Reference

Full interactive docs at `http://localhost:8000/docs` when running locally.

### Auth header

```
Authorization: Bearer <jwt_token>
```

Or for SDK/programmatic access:

```
X-API-Key: qs_live_sk_your_key_here
```

### Common response shapes

**AppOut:**
```json
{
  "id": 1,
  "package_name": "com.example.app",
  "app_name": "Example App",
  "scan_status": "completed",
  "security_score": 72.5,
  "risk_level": "Medium",
  "pqc_readiness_score": 45.0,
  "is_public": true,
  "owner_id": 3,
  "submitted_at": "2026-01-01T12:00:00",
  "scanned_at": "2026-01-01T12:05:00",
  "made_public_at": "2026-01-01T12:06:00"
}
```

**KnowledgeBaseOut:**
```json
{
  "id": 1,
  "name": "CVE Vulnerability Feed",
  "type": "NVD CVE Feed",
  "records": 248642,
  "size": "1.2 GB",
  "status": "synced",
  "source": "nvd.nist.gov",
  "last_sync": "2026-04-21T17:12:49"
}
```

**SyncJobOut:**
```json
{
  "id": 6,
  "kb_id": 1,
  "kb_name": "CVE Vulnerability Feed",
  "operation": "sync",
  "status": "success",
  "started_at": "2026-04-21T17:12:46",
  "finished_at": "2026-04-21T17:12:49",
  "records_before": 248556,
  "records_after": 248642,
  "error_msg": null,
  "triggered_by": "manual"
}
```

**UserOut:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "name": "Aziza",
  "role": "app_owner",
  "company": "Mertilly",
  "totp_enabled": false,
  "created_at": "2026-01-01T00:00:00"
}
```

> **Timestamp note:** Backend returns UTC without a `Z` suffix. The frontend appends `Z` before passing to `new Date()` to avoid local-time misinterpretation.

---

## 10. Authentication & JWT

- Tokens signed with `HS256` using `JWT_SECRET` from env.
- Expiry: `JWT_EXPIRE_MINUTES` (default `1440` = 24 h).
- Payload: `{ sub: user_id, role, iss, aud, iat, nbf, exp, jti }`.
- **No refresh token** — re-login required after expiry.
- Password-reset tokens use the same secret but carry `"type": "password_reset"` and expire in 15 minutes.
- API keys (`qs_live_sk_…`) are accepted in `X-API-Key` header as an alternative to Bearer tokens.

---

## 11. OAuth — Google & GitHub

### Flow (both providers)

1. User clicks the styled button (Google uses an overlay pattern — see §6).
2. Provider returns a credential (Google ID token) or authorization code (GitHub).
3. Frontend sends it to `POST /auth/google` or `POST /auth/github`.
4. Backend verifies → upserts user (default role `end_user`) → returns JWT.
5. Frontend calls `/auth/me` → sets user state.
6. **New account detection:** if `created_at < 60s ago` → role-selection modal.
7. User picks End User or App Owner → `POST /auth/set-role` → role saved in DB.
8. Navigate to `/dashboard`.

### Setting up GitHub OAuth

1. Go to [github.com/settings/developers](https://github.com/settings/developers) → **OAuth Apps** → **New OAuth App**
2. Fill in:
   - **Homepage URL:** `http://localhost:5173`
   - **Authorization callback URL:** `http://localhost:5173/auth/github/callback`
3. Copy **Client ID** → `VITE_GITHUB_CLIENT_ID` (frontend) and `GITHUB_CLIENT_ID` (backend)
4. Generate a **Client Secret** → `GITHUB_CLIENT_SECRET` (backend only — never expose to frontend)
5. Restart both servers.

> **Production:** create a separate OAuth App with your production domain as the callback URL.

---

## 12. Two-Factor Authentication (TOTP)

Implementation: `pyotp` (backend) + any TOTP app (Google Authenticator, Authy, etc.).

### Enable

1. `POST /auth/2fa/setup` → `{ secret, otpauth_uri, qr_data_url }`
2. User scans QR code
3. User enters 6-digit code → `POST /auth/2fa/verify` → `totp_enabled = True` saved in DB

### Disable

- `POST /auth/2fa/disable` with `{ code }` — clears secret, disables flag

### Admin reset (locked-out user)

- `DELETE /admin/users/{id}/2fa` — disables TOTP for any user (admin only)

**Frontend location:** `AccountPage.tsx` → Security section.

---

## 13. Forgot-Password Flow

1. User submits email on forgot-password panel → `POST /auth/forgot-password`
2. Backend finds the user:
   - If 2FA is enabled and no `totp_code` sent → returns `{ "requires_totp": true }` → frontend shows TOTP input field
   - If 2FA is enabled and `totp_code` sent → verifies; if invalid → `{ "requires_totp": true, "totp_invalid": true }`
   - Generates 15-minute JWT reset token (`"type": "password_reset"`)
   - Sends HTML email via SMTP with reset link → `<FRONTEND_URL>/reset-password?token=…`
3. Non-existent emails always return 200 (prevents user enumeration).
4. If SMTP is unconfigured, the email is silently skipped.
5. User clicks link → `ResetPasswordPage` reads `?token=` → submits new password → `POST /auth/reset-password`
6. Backend validates token type, expiry, user → updates `password_hash` → redirect to `/login`.

> **Why 2FA is required:** Without it, an attacker who knows the email could bypass 2FA by triggering a password reset. The TOTP step proves device possession before dispatching a reset link.

---

## 14. Roles & Access Control

| Role | Value | Capabilities |
|---|---|---|
| End User | `end_user` | Dashboard (global stats), Browse Apps, Account, Contact, Reports |
| App Owner | `app_owner` | All above + Analyze App, My Applications (own apps only), API Key, View Report |
| Admin | `admin` | All above + User Management, System Monitor, DB Management |

### Dashboard data scoping

| Role | TLS Chart Source |
|---|---|
| `end_user` | All apps in the dataset (global) |
| `app_owner` | Only their own submitted apps |
| `admin` | All apps in the dataset (global) |

### Browse Apps deduplication

For `end_user`: only the **newest public scan per package name** is shown. Older public versions are hidden when a newer version exists.

### Frontend route guards

`src/components/auth/ProtectedRoute.tsx` checks `user.role` and redirects to `/dashboard` if the role isn't allowed.

### Backend guards

- `get_current_user` — validates JWT or API key; returns the `User` ORM object
- `require_role("admin")` — additionally checks `user.role == "admin"`

---

## 15. TLS Scan Pipeline

### Submit flow

```
POST /apps/submit (or POST /apps/upload-apk)
  → Application record created (scan_status="pending")
  → background_tasks.add_task(run_scan_pipeline, app.id)
  → response returned immediately
```

### Background pipeline (`services/tls_scanner.py`)

1. Resolve domains for the app's package name
2. Per domain: TLS handshake → extract version, cipher, key exchange, cert details, PQC flags
3. Store `Domain` + `TLSResult` + `Vulnerability` rows
4. Run ML prediction → store `MLPrediction`
5. Issue `SecurityWarranty` based on score
6. Update `app.scan_status = "completed"`, set `app.scanned_at = now`

### Scan status values

`pending` → `scanning` → `completed` / `failed`

---

## 16. ML Prediction Pipeline

### Training data (`pqc-research/data/`)

| File | Description |
|---|---|
| `target_apps.json` | App metadata for 727 unique brands |
| `report_per_domain.csv` | Domain-level TLS scan results from research pipeline |
| `report_per_app.csv` | App-level aggregated scores |
| `vulnerability_report.csv` | CVE-to-domain mapping |
| `domain_classification.csv` | Domain categorisation (first-party, CDN, ads, etc.) |
| `cluster_assignments.csv` | ML clustering results |
| `feature_importance.csv` | Random Forest feature importances |

### Model

- Type: scikit-learn Random Forest
- Stored at `backend/ml/model.pkl` (auto-trained on first startup if missing)

### Endpoints

| Endpoint | Description |
|---|---|
| `POST /admin/ml/train` | Retrain the model |
| `POST /admin/ml/predict/{app_id}` | Run prediction for a specific app |
| `GET /apps/{id}/prediction` | Retrieve stored prediction |

### Score semantics

| Score | Range | Meaning |
|---|---|---|
| `security_score` | 0–100 | Higher = safer |
| `risk_level` | Low / Medium / High / Critical | Derived from security_score |
| `pqc_readiness_score` | 0–100 | Higher = more PQC-ready |
| `confidence` | 0–1 | Model confidence |

### Startup repair

`repair_missing_predictions()` runs on every startup. It finds apps with no `MLPrediction`, looks up their package in `report_per_app.csv`, derives scores, and creates `MLPrediction` + `SecurityWarranty`. Falls back to `score=50, pqc=30` if no CSV row found. Commits every 200 apps to stay memory-safe. Idempotent.

---

## 17. App Report Page

Route: `/apps/:id/report` — rendered **outside** `AppLayout` for clean full-page printing.

**Accessed from:** My Applications → "View Report" button (visible only when `scan_status === "completed"`).

| Section | Detail |
|---|---|
| Header | App name, package name, category, scan date, risk badge, PQC badge |
| KPI cards | Security score, PQC readiness %, vulnerability count, domains scanned |
| Score rings | SVG circle gauges for Security, PQC Readiness, ML Confidence |
| TLS bar chart | Protocol version distribution across scanned domains |
| Vulnerability donut | Severity distribution (Critical / High / Medium / Low) |
| TLS results table | Per-domain: version badge, cipher, key exchange, PQC support, legacy flag, score |
| Vulnerabilities table | CVE ID, severity badge, CVSS score, description |
| Domain inventory | Domain, IP, country, class, third-party flag |
| ML Prediction | Predicted score, risk level, PQC readiness, confidence, feature importances bar |
| Security flags | Legacy TLS count, PQC-enabled domains, RSA key exchange count, RC4/3DES count |

**Save as PDF:** "Save as PDF" button triggers `window.print()`. Toolbar is hidden in print via `.no-print` CSS class.

---

## 18. Notifications System

### Hook: `src/hooks/useNotifications.ts`

Exports: `{ notifications, unreadCount, markRead, markAllRead, dismiss, dismissAll }`

### Poll sources per role

| Role | Interval | Endpoints used |
|---|---|---|
| `admin` | 30 s | `GET /admin/recent-scans`, `GET /admin/system/health`, `GET /apps/recent-completions` |
| `app_owner` | 20 s | `GET /apps/recent-completions?owner_id=…`, `GET /apps/recent-public` |
| `end_user` | 60 s | `GET /apps/recent-public` |

All polls use `sessionStartRef` (ISO timestamp of tab open time) as the `since` parameter — only events that happen **during the current browser session** generate notifications.

### Notification rules

| Role | Event | Kind |
|---|---|---|
| `end_user` | Any app made public this session | `new_app_public` |
| `app_owner` | Own scan completed | `own_scan_complete` |
| `app_owner` | Own scan high-risk | `own_high_risk` |
| `app_owner` | Own scan PQC-ready | `pqc_ready` |
| `admin` | Any scan completed/failed | `scan_complete` / `scan_failed` |
| `admin` | New user registered (last 24 h) | `new_user` |
| `admin` | Scan backlog > 5 pending | `pending_backlog` |

### Persistence (two localStorage keys)

| Key | Purpose |
|---|---|
| `qs_notif_seen` | IDs user has read — dot disappears, item stays in list |
| `qs_notif_dismissed` | IDs permanently dismissed — never reappear even after re-login |

### Bell actions

- **Mark all read** — writes all IDs to `qs_notif_seen`; items stay in list
- **Clear all** — writes all IDs to `qs_notif_dismissed`; items never reappear

---

## 19. DB Management & Sync Jobs

Admin-only page at `/database`. Manages four knowledge bases: CVE Vulnerability Feed, PQC Algorithm Registry, TLS Cipher Suites, Certificate Authorities.

### Knowledge Bases

| KB | Type | Source | Growth per sync |
|---|---|---|---|
| CVE Vulnerability Feed | NVD CVE Feed | nvd.nist.gov | +50–300 records |
| PQC Algorithm Registry | Internal | Internal | +0–5 records |
| TLS Cipher Suites | IANA Registry | iana.org | +0–3 records |
| Certificate Authorities | CA Bundle | Mozilla CA Store | +5–50 records |

### Sync flow

```
POST /admin/databases/{id}/sync
  → KB status set to "syncing" immediately
  → SyncJob record created (status="running")
  → response returned (status="syncing")
  → BackgroundTask: asyncio.sleep(2–4.5s) → update records → KB status="synced"
  → SyncJob updated (status="success", finished_at, records_after)
```

Frontend polls every 3 s while any KB is `"syncing"` or any job is `"running"`.

### Job tracking

`GET /admin/databases/jobs?limit=N` returns the last N jobs, newest first.

Each job records:
- `operation`: `sync` | `sync-all` | `import` | `export`
- `status`: `running` | `success` | `error`
- `records_before` / `records_after` (delta shown in UI as green +N)
- `triggered_by`: `manual` | `scheduler`
- `started_at` / `finished_at` (duration computed in frontend)

### Auto-sync scheduler

`scheduler_loop()` runs as an `asyncio` background task (started in lifespan, cancelled on shutdown). Every 60 seconds it:
1. Reads `SyncConfig` (sync_interval)
2. Checks each KB's `last_sync`
3. If overdue → marks KB `"syncing"`, creates job (`triggered_by="scheduler"`), fires `asyncio.create_task(_do_sync(…))`

Config changes take effect within 60 s (next scheduler tick).

### Import / Export

- **Export:** downloads KB metadata as JSON; writes a `SyncJob` record (operation=`export`, instant success)
- **Import:** accepts `.json` or `.csv`; if JSON contains a `records` integer field, updates the count; writes a `SyncJob` record (operation=`import`); captures `error_msg` if file is unparseable

### Startup safety

On every backend start, any KB stuck in `"syncing"` (from a previous crashed run) is reset to `"synced"` before the scheduler starts.

---

## 20. Reports System

### Auto-generation

`GET /reports/` auto-generates report records on first call if the table is empty:
- **Monthly** — one record per calendar month in which apps were scanned
- **Quarterly** — one record per (year, quarter) bucket
- **Platform Security Overview** — one custom report covering all apps

### Regeneration

`POST /reports/regenerate` (admin only) — rebuilds all report records from current DB data. The System Monitor page has a **"Seed from CSV"** button that automatically calls this after seeding.

### Report download

`GET /reports/{id}/download` — returns a JSON with live computed stats for that time window: avg score, avg PQC readiness, risk distribution, TLS version distribution, app count.

---

## 21. User Management (Admin)

Route: `/users` — admin only.

### Table columns

Name, Email, Role (shadcn Select pill — click to change inline), 2FA indicator, Created date, Actions.

### Row actions (⋮ DropdownMenu via Radix Portal — never clipped by overflow)

| Action | Description | Endpoint |
|---|---|---|
| View details | Full profile + session/login history modal | `GET /admin/users/{id}/sessions` |
| Send mail | In-app SMTP email modal (pre-filled To, admin types Subject + Body) | `POST /admin/users/{id}/send-email` |
| Send password reset | Triggers reset email (uses same SMTP flow as forgot-password) | `POST /auth/forgot-password` |
| Force logout | Revokes all active sessions | `DELETE /admin/users/{id}/sessions` |
| Reset 2FA / MFA | Disables TOTP for a locked-out user | `DELETE /admin/users/{id}/2fa` |
| Delete user | Confirmation popup → permanent delete | `DELETE /admin/users/{id}` |

A red **trash icon** also appears directly in each table row for one-click delete.

### Role editing

Inline shadcn `<Select>` styled as a coloured pill:

| Role | Pill colour |
|---|---|
| `admin` | Red (destructive) |
| `app_owner` | Secondary/muted |
| `end_user` | Outline/transparent |

### Add user

Modal form with email, name, role, temporary password fields → `POST /admin/users`.

---

## 22. System Monitor (Admin)

Route: `/system` — admin only.

| Section | Data source |
|---|---|
| System health | `GET /admin/system/health` — CPU, memory, DB status |
| ML metrics | `GET /admin/ml-metrics` — model accuracy, last trained |
| Recent scans | `GET /admin/recent-scans` — last N completed scans |
| Scan queue | `GET /admin/scan-queue` — pending/scanning apps |
| Metrics timeseries | `GET /admin/metrics/timeseries` — scan volume over time |
| Seed from CSV | Button → `POST /admin/seed-csv` → auto-calls `POST /reports/regenerate` |

---

## 23. SDK & API Key Integration

### API Key auth

Every `app_owner` and `admin` has a personal key (`qs_live_sk_…`) visible in **Account → API Key**:

```
X-API-Key: qs_live_sk_your_key_here
```

`get_current_user` accepts both `Authorization: Bearer <jwt>` and `X-API-Key`. When a key is used, `last_used_at` in `user_api_keys` is updated.

### Python SDK

**Location:** `sdk/python/`

```bash
pip install -e sdk/python/
```

```python
from quantumshield import QuantumShieldClient

qs = QuantumShieldClient(api_key="qs_live_sk_...", base_url="http://localhost:8000")

# One-liner: submit + wait + full report
report = qs.analyze("com.example.myapp", app_name="My App")
print(report["prediction"]["security_score"])   # e.g. 78.4
print(report["prediction"]["risk_level"])        # "Low"

# Step by step
app  = qs.submit_app("com.example.myapp")
app  = qs.wait_for_scan(app["id"])
tls  = qs.get_tls_results(app["id"])
vulns = qs.get_vulnerabilities(app["id"])

# Read-only
apps  = qs.list_apps(sort="score", limit=50)
stats = qs.get_stats()
```

**Available methods:**

| Method | Description |
|---|---|
| `list_apps(q, sort, limit)` | List visible apps |
| `get_app(app_id)` | Single app details |
| `submit_app(package_name, app_name, category)` | Submit for analysis *(app_owner/admin)* |
| `wait_for_scan(app_id, poll_interval, timeout)` | Block until scan completes |
| `analyze(package_name, …, wait=True)` | Submit + wait + report in one call |
| `get_prediction(app_id)` | ML security prediction |
| `get_tls_results(app_id)` | TLS scan results per domain |
| `get_vulnerabilities(app_id)` | CVE / vulnerability records |
| `get_domains(app_id)` | Domain inventory |
| `get_warranty(app_id)` | Security warranty status |
| `get_report(app_id)` | Full security report |
| `get_stats()` | Platform-wide statistics |

**Error handling:**
```python
from quantumshield import AuthenticationError, NotFoundError, QuantumShieldError
try:
    report = qs.get_report(9999)
except NotFoundError:
    print("App not found")
except AuthenticationError:
    print("Bad API key")
except QuantumShieldError as e:
    print(f"API error {e.status_code}: {e.message}")
```

### JavaScript SDK

**Location:** `sdk/javascript/` — native `fetch`, no external dependencies, Node 18+.

```bash
cd sdk/javascript && npm install
```

```javascript
const { QuantumShieldClient } = require("./sdk/javascript/src/index");

const qs = new QuantumShieldClient({ apiKey: "qs_live_sk_...", baseUrl: "http://localhost:8000" });

const report = await qs.analyze("com.example.myapp", { appName: "My App" });
console.log(report.prediction.security_score, report.prediction.risk_level);

const app   = await qs.submitApp("com.example.myapp");
const done  = await qs.waitForScan(app.id);
const tls   = await qs.getTlsResults(done.id);
const vulns = await qs.getVulnerabilities(done.id);
const stats = await qs.getStats();
```

**Available methods** (camelCase mirror of Python SDK):
`listApps`, `getApp`, `submitApp`, `waitForScan`, `analyze`, `getPrediction`, `getTlsResults`, `getVulnerabilities`, `getDomains`, `getWarranty`, `getReport`, `getStats`

**Error handling:**
```javascript
import { AuthenticationError, NotFoundError } from "./sdk/javascript/src/index.js";
try {
  const report = await qs.getReport(9999);
} catch (e) {
  if (e instanceof NotFoundError) console.error("Not found");
  else if (e instanceof AuthenticationError) console.error("Bad key");
}
```

---

## 24. Docker / Production Deployment

```bash
cd PCD-main/tls-analyzer
export JWT_SECRET="a-very-long-random-secret"
docker-compose up --build
```

| Service | Port | Description |
|---|---|---|
| `db` | 5432 | PostgreSQL 16 |
| `elasticsearch` | 9200 | Full-text search (optional) |
| `backend` | 8000 | FastAPI (uvicorn) |
| `frontend` | 5173 | React (nginx) |

Add your production domain to `allow_origins` in `backend/main.py` and to CORS before deploying.

---

## 25. Switching to PostgreSQL

1. Start Postgres:
   ```bash
   docker run -e POSTGRES_USER=pqc -e POSTGRES_PASSWORD=pqc_secret \
     -e POSTGRES_DB=tls_analyzer -p 5432:5432 postgres:16-alpine
   ```
2. Update `.env`:
   ```env
   DATABASE_URL=postgresql+asyncpg://pqc:pqc_secret@localhost:5432/tls_analyzer
   ```
3. Restart the backend. Tables are created automatically via `create_all`.

---

## 26. Demo Accounts

Seeded automatically on startup (`seed.py`) — idempotent:

| Role | Email | Password |
|---|---|---|
| Admin | `admin@qs.io` | `Admin123!` |
| App Owner | `owner@qs.io` | `Owner123!` |
| End User | `user@qs.io` | `User123!` |

To reset all data: delete `tls_analyzer.db` and restart.

---

## 27. Seeding from Research CSV

The research dataset at `pqc-research/data/report_per_domain.csv` contains thousands of domain-level TLS scan results.

**How to seed:**
1. Sign in as `admin@qs.io`
2. Go to **System Monitor** → click **"Seed from CSV"** (or call `POST /admin/seed-csv` via Swagger)
3. The endpoint:
   - Groups domains by root brand name → creates `Application` records for all 727 unique brands
   - Creates `Domain` + `TLSResult` per CSV row
   - Derives `MLPrediction` + `SecurityWarranty` per app
   - Auto-calls `POST /reports/regenerate` after seeding
   - Returns counts: `apps_created`, `predictions_created`, `warranties_created`
4. **Idempotent** — re-running skips existing apps; repairs apps with missing child data (domains/prediction/warranty)

**After seeding:**
- `end_user` dashboard → global stats across all 727 apps
- `app_owner`/`admin` dashboard → only their own submitted apps

---

## 28. Developer Guides

### Adding a New Frontend Page

1. Create `QuantumShield2.0/src/pages/MyNewPage.tsx`
2. Add lazy import to `src/App.tsx`:
   ```tsx
   const MyNewPage = lazy(() => import('./pages/MyNewPage').then(m => ({ default: m.MyNewPage })))
   ```
   Add route inside the `ProtectedRoute / AppLayout` block:
   ```tsx
   <Route path="/my-new" element={<MyNewPage />} />
   ```
3. Add to `PAGE_META` in `src/components/layout/Topbar.tsx` for the header title.
4. Add nav link in `src/components/layout/AppSidebar.tsx`.
5. If role-restricted: `<ProtectedRoute allowedRoles={['admin']} />`.
6. Add API calls to `src/lib/api.ts`.

### Adding a New Backend Endpoint

1. Open the relevant router in `backend/routers/`.
2. Define the endpoint:
   ```python
   @router.get("/my-endpoint", response_model=MySchema)
   async def my_endpoint(
       db: AsyncSession = Depends(get_db),
       user: User = Depends(get_current_user),
   ):
       ...
   ```
3. Add the Pydantic schema to `backend/schemas/pydantic_schemas.py`.
4. If it's a new router file, register it in `backend/main.py`.
5. Add the client call to `src/lib/api.ts`.

---

## 29. Known Gotchas

### Schema changes break the existing SQLite DB

SQLAlchemy uses `create_all` — creates missing tables but does **not** run `ALTER TABLE` for new columns. Fix: delete `tls_analyzer.db` and restart. All data is re-seeded automatically.

### OAuth role defaults to `end_user`

New OAuth accounts start as `end_user`. The role-selection modal fires only within 60 seconds of `created_at`. If missed, the user must contact an admin or update role via `PATCH /auth/set-role`.

### Rate limiting on auth endpoints

`/auth/login` (10/min), `/auth/register` (5/min), `/auth/forgot-password` (3/min) — exceeding returns HTTP 429.

### JWT_SECRET must be set

Falls back to `"change-me-in-production"` if absent. Generate a real secret:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Session-expired banner

When a JWT expires and the user returns, `AuthContext` writes `qs_session_expired=1` to `sessionStorage`. `LoginPage` reads this flag, removes it, and shows an amber banner.

### Gmail App Password — no spaces

Gmail shows `abcd efgh ijkl mnop` but `.env` must have no spaces: `SMTP_PASSWORD=abcdefghijklmnop`.

### `scan_status` values

Backend uses `"completed"` (not `"complete"`). `mapStatus()` in `MyApplicationsPage.tsx` checks for `"completed"`.

### Timestamps from backend have no `Z` suffix

Backend returns UTC timestamps like `"2026-04-15T10:30:00"`. JavaScript treats these as local time without a `Z`. The frontend appends `Z` before `new Date()`.

### CORS errors in the browser

If the frontend URL is not in `main.py`'s `allow_origins`, all API requests will be blocked. Add the origin and restart the backend.

### PDF export requires auth header

`GET /apps/{id}/report?format=pdf` is protected. Use `fetch()` with `Authorization: Bearer <token>` — do **not** use `window.open()` (it doesn't send the auth header). The frontend uses `window.print()` for client-rendered PDF instead.

### 2FA setup secret is temporary

`POST /auth/2fa/setup` generates a secret but does **not** save it until `POST /auth/2fa/verify` is called with a valid code. Closing the panel without verifying means setup must restart.

### KB stuck in "syncing" after crash

On every backend startup, any KB left in `"syncing"` state is automatically reset to `"synced"` before the scheduler starts. This prevents the sync spinner from appearing permanently in the UI.

### Port conflicts

- Backend: `python -m uvicorn backend.main:app --reload --port 9000`
- Frontend: `npm run dev -- --port 3001`
- Update `VITE_API_URL`, `FRONTEND_URL`, and CORS origins accordingly.

---

## 30. Scripts Reference

### Frontend (`QuantumShield2.0/`)

```bash
npm run dev        # Vite dev server → http://localhost:5173
npm run build      # production build → dist/
npm run preview    # preview production build locally
npm run lint       # ESLint check
npx tsc --noEmit   # TypeScript type check (no output files)
```

### Backend (`PCD-main/tls-analyzer/`)

```bash
python -m uvicorn backend.main:app --reload             # dev server (auto-reload)
python -m uvicorn backend.main:app --reload --port 9000 # custom port
python -m uvicorn backend.main:app --workers 4          # production (no --reload)
pip install -r backend/requirements.txt                 # install deps
```
