"""Async SQLAlchemy engine and session factory."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from .config import DATABASE_URL


engine = create_async_engine(DATABASE_URL, echo=False, future=True)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def _ensure_sqlite_schema_compat(conn) -> None:
    """Apply minimal SQLite-only schema patches for older local DB files."""
    if conn.dialect.name != "sqlite":
        return

    table_exists = await conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    )
    if table_exists.scalar_one_or_none() is None:
        return

    pragma_result = await conn.execute(text("PRAGMA table_info(users)"))
    columns = {row[1] for row in pragma_result.fetchall()}

    if "company" not in columns:
        await conn.execute(text("ALTER TABLE users ADD COLUMN company VARCHAR(255)"))


async def get_db() -> AsyncSession:
    """FastAPI dependency that yields a database session."""
    async with async_session() as session:
        yield session


async def init_db():
    """Create all tables (used on startup)."""
    async with engine.begin() as conn:
        from .models.db_models import (  # noqa: F401 — import so metadata is populated
            User, Application, Domain, TLSResult,
            Vulnerability, MLPrediction, SecurityWarranty,
        )
        await conn.run_sync(Base.metadata.create_all)
        await _ensure_sqlite_schema_compat(conn)
