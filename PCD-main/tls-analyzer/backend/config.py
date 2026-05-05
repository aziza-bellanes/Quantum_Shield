"""Application configuration loaded from environment variables."""

import os
from dotenv import load_dotenv

load_dotenv()

# Database — defaults to local SQLite for quick dev; set DATABASE_URL for Postgres
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///"
    + os.path.join(os.path.dirname(__file__), "..", "tls_analyzer.db"),
)
DATABASE_URL_SYNC = DATABASE_URL.replace("+aiosqlite", "").replace("+asyncpg", "")

# JWT
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))  # 24h

# ElasticSearch
ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_INDEX = "tls_apps"

# ML
MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml", "model.pkl")

# Research pipeline data path
PIPELINE_DATA_DIR = os.getenv(
    "PIPELINE_DATA_DIR",
    os.path.join(os.path.dirname(__file__), "..", "pqc-research", "data"),
)

# Scan settings
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "10"))
SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "20"))

# OAuth
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")

# Email / contact form
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
CONTACT_RECIPIENT = os.getenv("CONTACT_RECIPIENT", "Quantum.Shield.Support@gmail.com")
CONTACT_PHONE = os.getenv("CONTACT_PHONE", "+216 41 654 429")

# Frontend base URL — used in password-reset email links
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
