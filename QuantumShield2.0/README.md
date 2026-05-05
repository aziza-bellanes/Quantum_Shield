# QuantumShield 2.0

QuantumShield 2.0 is a full-stack cybersecurity platform for TLS and post-quantum cryptography (PQC) readiness analysis.

It combines:
- A React + TypeScript frontend dashboard.
- A FastAPI backend that scans domains, scores risk, and exposes role-based APIs.

---

## Main Features

### Authentication
- Email/password login with optional 2FA (TOTP / Google Authenticator).
- OAuth sign-in via **Google** and **GitHub** — buttons are styled consistently.
- **First-time OAuth onboarding** — new accounts created through Google or GitHub are presented with a role-selection modal (End User / App Owner) before reaching the dashboard. The selection is persisted via `POST /auth/set-role`.
- "Keep me signed in" — stores the JWT in `localStorage` (persistent) or `sessionStorage` (tab-scoped) based on checkbox state. JWT is valid for 24h by default (`ACCESS_TOKEN_EXPIRE_MINUTES=1440`).
- **Forgot-password flow** — sends a real reset link via SMTP (requires `SMTP_*` env vars). Link expires in 15 minutes. Frontend at `/reset-password?token=…` validates the token and updates the password.

### Dashboard
- Role-based data views:
  - **End User** — sees global aggregate statistics across all apps in the dataset.
  - **App Owner / Admin** — sees only their own submitted and scanned apps.
- Animated KPI cards (security score, PQC readiness, app count, dominant TLS version).
- TLS version distribution bar chart and risk level donut chart.
- Recent audits table with score, risk badge, PQC readiness, and scan status.

### Reports
- KPI stat cards with distinct colored icons (total, ready, apps analyzed, average apps/report).
- Configurable chart titles — "Report Type Distribution" and "Report Status" charts.
- Filterable report list (by title, type, status) with download support.

### Account
- Profile editing (name, email, company, phone, date of birth, bio, location).
- Location auto-detect via browser Geolocation API.
- **Region** — dynamically derived from the device's IANA timezone (e.g., "Europe/Paris" → "Paris"); overridden by any manually saved location.
- **Last login** — displays the correct local time by treating backend timestamps as UTC.
- Password change with strength indicator.
- Two-factor authentication setup / disable (TOTP QR code flow).
- Active session management — view and revoke sessions.
- API key management (app owners).
- Notification preferences.

### Browse & Analysis
- Browse the app dataset with search and category filters.
- Detailed per-app analysis: TLS results, vulnerabilities, ML predictions, warranty info.
- APK upload and domain submission for app owners.
- **App Report page** (`/apps/:id/report`) — full-page printable report with score rings, TLS bar chart, vulnerability severity donut chart, TLS results table, vulnerability table, domain inventory, ML prediction details, and security flags summary. Use "Save as PDF" to print.
- "View Report" button appears on the **Analyze App** page after a scan completes, and on the **My Applications** page for any app with `scan_status === 'completed'` — both navigate to `/apps/:id/report`.

### Admin
- User management (view, change role, delete).
- System health monitoring.
- ML metrics and model retraining.
- Database management (knowledge bases, sync, export/import).
- Recent scans and scan queue.

### Contact
- Contact form with validation; messages persisted in the backend DB and optionally forwarded via SMTP.

---

## Roles

| Role | Permissions |
|------|-------------|
| **End User** | View dashboards (global data), browse apps, manage account, send contact messages |
| **App Owner** | All End User permissions + submit/analyze own apps, download reports, use API key |
| **Admin** | Full platform access — user management, system monitoring, database management, own-app dashboard view |

---

## Tech Stack

### Frontend

| Library | Purpose |
|---------|---------|
| React 19 | UI framework |
| TypeScript | Type safety |
| Vite | Build tool / dev server |
| Tailwind CSS v4 | Styling |
| shadcn/ui | Component library (Radix primitives) |
| Recharts | Data visualization (bar, donut charts) |
| `@react-oauth/google` | Google OAuth (ID-token flow) |
| React Router v6 | Client-side routing |
| Zod | Runtime form validation |
| Lucide React | Icon set |

### Backend

| Library | Purpose |
|---------|---------|
| FastAPI | REST API framework |
| SQLAlchemy async | ORM |
| Pydantic | Schema validation |
| SQLite (dev) / PostgreSQL (prod) | Database |
| python-jose / passlib | JWT + password hashing |
| pyotp | TOTP two-factor auth |
| SMTP | Contact form email delivery |

---

## Project Structure

```text
QuantumShield2.0/               # Frontend
├── src/
│   ├── pages/                  # Route-level page components
│   │   ├── LoginPage.tsx
│   │   ├── SignUpPage.tsx
│   │   ├── ResetPasswordPage.tsx
│   │   ├── DashboardPage.tsx
│   │   ├── ReportsPage.tsx
│   │   ├── AccountPage.tsx
│   │   ├── BrowseAppsPage.tsx
│   │   ├── AnalyzeAppPage.tsx
│   │   ├── MyApplicationsPage.tsx
│   │   ├── AppReportPage.tsx
│   │   ├── UserManagementPage.tsx
│   │   ├── SystemMonitorPage.tsx
│   │   ├── DatabaseManagementPage.tsx
│   │   ├── ContactPage.tsx
│   │   └── GithubCallbackPage.tsx
│   ├── components/
│   │   ├── charts/             # TlsBarChart, RiskDonutChart
│   │   ├── layout/             # AppLayout, AppSidebar, Topbar
│   │   ├── ui/                 # shadcn/ui primitives
│   │   └── auth/               # ProtectedRoute
│   ├── context/
│   │   └── AuthContext.tsx     # Auth state, login/register/OAuth
│   ├── lib/
│   │   ├── api.ts              # All API calls (authApi, appsApi, profileApi…)
│   │   ├── types.ts            # Shared TypeScript types
│   │   └── utils.ts            # Helpers (scoreColor, roleLabel, formatDate…)
│   └── index.css               # Tailwind + CSS custom properties
├── public/
├── .env.local                  # Frontend env vars (git-ignored)
├── package.json
└── vite.config.ts

PCD-main/tls-analyzer/          # Backend
├── backend/
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── routers/                # auth, apps, admin, contact, reports…
│   ├── services/               # TLS scan, ML pipeline, email…
│   ├── models/
│   ├── schemas/
│   └── seed.py
├── docker-compose.yml
├── pqc-research/
├── uploads/
└── tls_analyzer.db             # local SQLite DB (dev only)
```

---

## Quick Start

### 1) Backend

From `PCD-main/tls-analyzer/backend`:

```bash
pip install -r requirements.txt
python -m uvicorn backend.main:app --reload
```

| URL | Description |
|-----|-------------|
| `http://localhost:8000` | REST API base |
| `http://localhost:8000/docs` | Swagger / OpenAPI docs |

### 2) Frontend

From `QuantumShield2.0`:

```bash
npm install
npm run dev
```

Frontend: `http://localhost:5173`

---

## Environment Variables

### Frontend — `QuantumShield2.0/.env.local`

```env
VITE_API_URL=http://localhost:8000

# Google OAuth (required for Google sign-in button)
VITE_GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com

# GitHub OAuth (required for GitHub sign-in button)
VITE_GITHUB_CLIENT_ID=your-github-oauth-app-client-id
```

To obtain these:
- **Google**: [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials → OAuth 2.0 Client ID. Add `http://localhost:5173` to Authorized JavaScript origins.
- **GitHub**: GitHub Settings → Developer settings → OAuth Apps → New OAuth App. Set callback URL to `http://localhost:5173/auth/github/callback`.

### Backend — `PCD-main/tls-analyzer/.env`

```env
DATABASE_URL=sqlite+aiosqlite:///./tls_analyzer.db
JWT_SECRET=change-me-in-production-use-a-long-random-string

# Set to 1440 (24 h) so "Keep me signed in" works for a full day
ACCESS_TOKEN_EXPIRE_MINUTES=1440

ES_URL=http://localhost:9200
SCAN_TIMEOUT=10
SCAN_CONCURRENCY=20
PIPELINE_DATA_DIR=./pqc-research/data

# SMTP — required for forgot-password emails and contact form forwarding
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=Quantum.Shield.Support@gmail.com
SMTP_PASSWORD=your16charapppassword
CONTACT_RECIPIENT=Quantum.Shield.Support@gmail.com

# Google OAuth secret (backend token verification)
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com

# GitHub OAuth secret (backend code exchange)
GITHUB_CLIENT_ID=your-github-oauth-app-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-app-client-secret

# Frontend base URL — used in password-reset email links
FRONTEND_URL=http://localhost:5173
```

> **SMTP setup (Gmail):** In your Google Account, enable 2-Step Verification, then go to **Security → App passwords** and generate a 16-character app password. Use it as `SMTP_PASSWORD`. Do **not** use your regular Gmail password.
> 
> Without SMTP configured, forgot-password emails are silently skipped but the reset endpoint still works if you construct the link manually.

---

## Demo Credentials

Available on the login page for quick testing:

| Role | Email | Password |
|------|-------|----------|
| End User | `user@qs.io` | `User1234!` |
| App Owner | `owner@qs.io` | `Owner123!` |
| Admin | `admin@qs.io` | `Admin123!` |

---

## OAuth Flow (Google & GitHub)

Both OAuth providers follow the same pattern:

1. User clicks **Continue with Google / GitHub**.
2. Provider returns a credential (Google ID token) or authorization code (GitHub).
3. Frontend sends it to the backend (`POST /auth/google` or `POST /auth/github`).
4. Backend verifies and returns a JWT.
5. **First-time sign-up detection**: if `created_at` is within 60 seconds of login, the frontend shows a role-selection modal (End User / App Owner) before navigating to the dashboard.
6. User selects a role → frontend calls `POST /auth/set-role` → role is saved in DB and in the frontend auth state.
7. On subsequent sign-ins the role modal is skipped and the user goes straight to the dashboard.

## Forgot-Password Flow

1. User enters their email on the "Forgot password?" form → `POST /auth/forgot-password`.
2. Backend looks up the user; if found, generates a 15-minute JWT reset token and sends it by email (requires SMTP config).
3. Email contains a link to `<FRONTEND_URL>/reset-password?token=…`.
4. User clicks the link → `ResetPasswordPage` validates the token and submits `POST /auth/reset-password` with the new password.
5. Password is updated; user is redirected to sign in.

---

## Frontend Scripts

```bash
npm run dev       # Start Vite dev server (hot reload)
npm run build     # Build production assets to dist/
npm run preview   # Preview the production build locally
npm run lint      # Run ESLint
```

---

## Contact Form Behavior

- Frontend sends `name`, `email`, `subject`, and `message` to `POST /contact/`.
- Backend persists every message to `contact_messages` in the database.
- Backend then attempts SMTP forwarding using the configured credentials.
- If SMTP is not configured or fails, the message is still saved in the database.

---

## Security Notes

- Never commit `.env` or `.env.local` files with real secrets.
- Never commit runtime DB dumps (`tls_analyzer.db`) unless explicitly required.
- Rotate SMTP passwords and OAuth secrets if they were ever exposed.
- Use a cryptographically random `JWT_SECRET` of at least 32 characters in production.
- Enable 2FA on your QuantumShield account for additional protection.
- Browser-native password reveal buttons are suppressed via CSS so only the custom toggle is shown.
