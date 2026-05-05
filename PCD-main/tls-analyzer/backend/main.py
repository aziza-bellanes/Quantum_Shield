"""FastAPI application entry point."""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from .database import init_db
from .limiter import limiter
from .routers import auth, apps, admin, model, databases, reports, contact


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables
    await init_db()
    # Seed demo users (idempotent)
    from .seed import seed_demo_users, seed_from_pipeline, seed_static_data, repair_missing_predictions
    await seed_demo_users()
    # Seed database from research pipeline data if empty
    await seed_from_pipeline()
    # Repair any apps missing ML predictions (idempotent)
    await repair_missing_predictions()
    # Seed knowledge bases and reports
    await seed_static_data()

    # Reset any KBs left in "syncing" state from a previous crashed run
    from .database import async_session as _session
    from .models.db_models import KnowledgeBase as _KB
    from sqlalchemy import select as _select, update as _update
    async with _session() as _db:
        await _db.execute(
            _update(_KB).where(_KB.status == "syncing").values(status="synced")
        )
        await _db.commit()

    # Start auto-sync scheduler (checks every 60 s)
    scheduler_task = asyncio.create_task(databases.scheduler_loop())
    yield
    scheduler_task.cancel()
    await asyncio.gather(scheduler_task, return_exceptions=True)


app = FastAPI(
    title="TLS Security Analyzer",
    description="Post-Quantum Cryptography TLS analysis platform",
    version="1.0.0",
    lifespan=lifespan,
)

# ── Rate limiting ──────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite default
        "http://localhost:5174",  # Vite fallback port
        "http://localhost:3000",  # CRA / alternative
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Stop MIME-type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Force HTTPS in production (safe to send in dev too — browsers ignore for http://)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Reduce referrer leakage
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Permissions Policy — disable APIs the app never uses
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Content-Security-Policy — allow Swagger UI on /docs and /redoc, block everything else
    if request.url.path.startswith(("/docs", "/redoc", "/openapi")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
    else:
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response

app.include_router(auth.router)
app.include_router(apps.router)
app.include_router(admin.router)
app.include_router(model.router)
app.include_router(databases.router)
app.include_router(reports.router)
app.include_router(contact.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
