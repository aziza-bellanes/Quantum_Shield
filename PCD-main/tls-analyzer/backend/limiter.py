"""Shared rate-limiter instance.

Import `limiter` in routers that need per-endpoint limits.
Register it on the FastAPI app in main.py (see there for setup).
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Key function: use the real client IP (works behind a proxy too)
limiter = Limiter(key_func=get_remote_address)
