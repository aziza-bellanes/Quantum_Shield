"""Admin routes for knowledge-base / database management."""

import asyncio
import io
import json
import random
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import async_session, get_db
from ..models.db_models import KnowledgeBase, SyncConfig, SyncJob
from ..schemas.pydantic_schemas import (
    KnowledgeBaseOut, SyncConfigOut, SyncConfigUpdate, SyncJobOut,
)
from .auth import require_role

router = APIRouter(prefix="/admin/databases", tags=["databases"])

# Record-growth ranges per KB type (lo, hi new records added per sync)
_GROWTH: dict[str, tuple[int, int]] = {
    "NVD CVE Feed":      (50, 300),
    "Internal":          (0, 5),
    "IANA Registry":     (0, 3),
    "CA Bundle":         (5, 50),
}

# Keep references to fire-and-forget asyncio tasks so GC doesn't collect them
_bg_tasks: set[asyncio.Task] = set()

def _keep(t: asyncio.Task) -> None:
    _bg_tasks.add(t)
    t.add_done_callback(_bg_tasks.discard)


# ── Background sync worker ────────────────────────────────────────────────────

async def _do_sync(kb_id: int, job_id: int) -> None:
    """Simulate a real sync: wait, update record count, mark done."""
    await asyncio.sleep(random.uniform(2.0, 4.5))
    try:
        async with async_session() as db:
            kb_res = await db.execute(select(KnowledgeBase).where(KnowledgeBase.id == kb_id))
            kb = kb_res.scalar_one_or_none()
            job_res = await db.execute(select(SyncJob).where(SyncJob.id == job_id))
            job = job_res.scalar_one_or_none()
            if not kb or not job:
                return
            lo, hi = _GROWTH.get(kb.type, (0, 10))
            delta = random.randint(lo, hi)
            kb.records = (job.records_before or kb.records) + delta
            kb.status = "synced"
            kb.last_sync = datetime.now(timezone.utc)
            job.status = "success"
            job.finished_at = datetime.now(timezone.utc)
            job.records_after = kb.records
            await db.commit()
    except Exception:
        pass


# ── List KBs ──────────────────────────────────────────────────────────────────

@router.get("/", response_model=list[KnowledgeBaseOut])
async def list_databases(
    _admin=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(KnowledgeBase).order_by(KnowledgeBase.id))
    return result.scalars().all()


# ── List jobs ─────────────────────────────────────────────────────────────────

@router.get("/jobs", response_model=list[SyncJobOut])
async def list_jobs(
    limit: int = 50,
    _admin=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(SyncJob).order_by(SyncJob.started_at.desc()).limit(limit)
    )
    return result.scalars().all()


# ── Sync all ──────────────────────────────────────────────────────────────────

@router.post("/sync-all", response_model=list[KnowledgeBaseOut])
async def sync_all(
    background_tasks: BackgroundTasks,
    _admin=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(KnowledgeBase))
    kbs = result.scalars().all()

    pending: list[tuple[int, SyncJob]] = []
    for kb in kbs:
        if kb.status == "syncing":
            continue
        job = SyncJob(
            kb_id=kb.id,
            kb_name=kb.name,
            operation="sync-all",
            status="running",
            records_before=kb.records,
            triggered_by="manual",
        )
        db.add(job)
        kb.status = "syncing"
        pending.append((kb.id, job))

    await db.commit()
    for kb_id, job in pending:
        await db.refresh(job)
        background_tasks.add_task(_do_sync, kb_id, job.id)

    result2 = await db.execute(select(KnowledgeBase).order_by(KnowledgeBase.id))
    return result2.scalars().all()


# ── Sync one ──────────────────────────────────────────────────────────────────

@router.post("/{db_id}/sync", response_model=KnowledgeBaseOut)
async def sync_database(
    db_id: int,
    background_tasks: BackgroundTasks,
    _admin=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(KnowledgeBase).where(KnowledgeBase.id == db_id))
    kb = result.scalar_one_or_none()
    if not kb:
        raise HTTPException(status_code=404, detail="Database not found")
    if kb.status == "syncing":
        return kb  # already in progress

    job = SyncJob(
        kb_id=kb.id,
        kb_name=kb.name,
        operation="sync",
        status="running",
        records_before=kb.records,
        triggered_by="manual",
    )
    db.add(job)
    kb.status = "syncing"
    await db.commit()
    await db.refresh(kb)
    await db.refresh(job)

    background_tasks.add_task(_do_sync, kb.id, job.id)
    return kb


# ── Export ────────────────────────────────────────────────────────────────────

@router.get("/{db_id}/export")
async def export_database(
    db_id: int,
    _admin=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(KnowledgeBase).where(KnowledgeBase.id == db_id))
    kb = result.scalar_one_or_none()
    if not kb:
        raise HTTPException(status_code=404, detail="Database not found")

    now = datetime.now(timezone.utc)
    job = SyncJob(
        kb_id=kb.id,
        kb_name=kb.name,
        operation="export",
        status="success",
        started_at=now,
        finished_at=now,
        records_before=kb.records,
        records_after=kb.records,
        triggered_by="manual",
    )
    db.add(job)
    await db.commit()

    data = {
        "id": kb.id,
        "name": kb.name,
        "type": kb.type,
        "records": kb.records,
        "size": kb.size,
        "status": kb.status,
        "source": kb.source,
        "last_sync": kb.last_sync.isoformat() if kb.last_sync else None,
        "exported_at": now.isoformat(),
    }
    content = json.dumps(data, indent=2).encode()
    filename = kb.name.replace(" ", "_") + ".json"
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Import ────────────────────────────────────────────────────────────────────

@router.post("/{db_id}/import", response_model=KnowledgeBaseOut)
async def import_database(
    db_id: int,
    file: UploadFile = File(...),
    _admin=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(KnowledgeBase).where(KnowledgeBase.id == db_id))
    kb = result.scalar_one_or_none()
    if not kb:
        raise HTTPException(status_code=404, detail="Database not found")

    records_before = kb.records
    error_msg: str | None = None
    raw = await file.read()
    try:
        payload = json.loads(raw)
        if "records" in payload and isinstance(payload["records"], int):
            kb.records = payload["records"]
    except (json.JSONDecodeError, ValueError) as exc:
        error_msg = str(exc)

    now = datetime.now(timezone.utc)
    kb.status = "synced"
    kb.last_sync = now

    job = SyncJob(
        kb_id=kb.id,
        kb_name=kb.name,
        operation="import",
        status="success" if error_msg is None else "error",
        started_at=now,
        finished_at=now,
        records_before=records_before,
        records_after=kb.records,
        error_msg=error_msg,
        triggered_by="manual",
    )
    db.add(job)
    await db.commit()
    await db.refresh(kb)
    return kb


# ── Sync config ───────────────────────────────────────────────────────────────

@router.get("/config", response_model=SyncConfigOut)
async def get_config(
    _admin=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(SyncConfig).where(SyncConfig.id == 1))
    config = result.scalar_one_or_none()
    if not config:
        config = SyncConfig(id=1)
        db.add(config)
        await db.commit()
        await db.refresh(config)
    return config


@router.patch("/config", response_model=SyncConfigOut)
async def update_config(
    body: SyncConfigUpdate,
    _admin=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(SyncConfig).where(SyncConfig.id == 1))
    config = result.scalar_one_or_none()
    if not config:
        config = SyncConfig(id=1)
        db.add(config)
    if body.sync_interval is not None:
        config.sync_interval = body.sync_interval
    if body.backup_retention is not None:
        config.backup_retention = body.backup_retention
    await db.commit()
    await db.refresh(config)
    return config


# ── Auto-sync scheduler helpers (called from main.py lifespan) ────────────────

def _parse_interval_secs(s: str) -> int:
    try:
        if s.endswith("h"):
            return int(s[:-1]) * 3600
        if s.endswith("d"):
            return int(s[:-1]) * 86400
    except ValueError:
        pass
    return 21600  # fallback: 6 h


async def _auto_sync_check() -> None:
    async with async_session() as db:
        cfg_res = await db.execute(select(SyncConfig).where(SyncConfig.id == 1))
        config = cfg_res.scalar_one_or_none()
        interval = _parse_interval_secs(config.sync_interval if config else "6h")

        now = datetime.now(timezone.utc)
        kb_res = await db.execute(select(KnowledgeBase))
        kbs = kb_res.scalars().all()

        to_sync: list[tuple[int, SyncJob]] = []
        for kb in kbs:
            if kb.status == "syncing":
                continue
            ls = kb.last_sync
            if ls and ls.tzinfo is None:
                ls = ls.replace(tzinfo=timezone.utc)
            if ls is None or (now - ls).total_seconds() > interval:
                job = SyncJob(
                    kb_id=kb.id,
                    kb_name=kb.name,
                    operation="sync",
                    status="running",
                    records_before=kb.records,
                    triggered_by="scheduler",
                )
                db.add(job)
                kb.status = "syncing"
                to_sync.append((kb.id, job))

        if to_sync:
            await db.commit()
            for kb_id, job in to_sync:
                await db.refresh(job)
                _keep(asyncio.create_task(_do_sync(kb_id, job.id)))


async def scheduler_loop() -> None:
    """Check every 60 s whether any KB needs an auto-sync."""
    while True:
        await asyncio.sleep(60)
        try:
            await _auto_sync_check()
        except Exception:
            pass
