"""Authentication routes: register, login, current user, profile, password, prefs, api-key, sessions, 2FA, OAuth."""

import io
import base64
import logging
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext
import jwt
import pyotp
import qrcode

from ..config import (
    JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRE_MINUTES,
    GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID,
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, FRONTEND_URL,
)
from ..database import get_db
from ..limiter import limiter
from ..models.db_models import User, UserPreferences, UserApiKey, UserSession
from ..schemas.pydantic_schemas import (
    RegisterRequest, LoginRequest, TokenResponse, UserOut,
    UpdateProfileRequest, ChangePasswordRequest,
    PreferencesOut, PreferencesUpdate,
    ApiKeyOut, SessionOut,
    TotpSetupOut, TotpVerifyRequest,
    OAuthGoogleRequest, OAuthGithubRequest,
    ForgotPasswordRequest, ResetPasswordRequest, SetRoleRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _create_token(user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "iss": "quantumshield-v2",
        "aud": "quantumshield-client",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
        "jti": secrets.token_hex(32),   # 64-char unique token ID — makes every token distinct
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                          audience="quantumshield-client")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── Dependency: extract current user from JWT Bearer OR X-API-Key ───────

_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    # 1. Bearer JWT (browser / dashboard sessions)
    if creds and creds.credentials:
        payload = _decode_token(creds.credentials)
        user_id = int(payload["sub"])
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user

    # 2. X-API-Key header (SDK / programmatic access)
    api_key_val = request.headers.get("X-API-Key")
    if api_key_val:
        result = await db.execute(
            select(UserApiKey).where(UserApiKey.key == api_key_val)
        )
        key_obj = result.scalar_one_or_none()
        if key_obj:
            key_obj.last_used_at = datetime.now(timezone.utc)
            await db.commit()
            user_result = await db.execute(select(User).where(User.id == key_obj.user_id))
            user = user_result.scalar_one_or_none()
            if user:
                return user

    raise HTTPException(status_code=401, detail="Not authenticated")


def require_role(*roles: str):
    """Dependency factory: require the current user to have one of the given roles."""
    async def _check(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return _check


# ── Helper: parse browser/OS from user-agent ────────────────────────────

def _parse_ua(ua: str) -> tuple[str, str]:
    browser = (
        "Chrome" if "Chrome" in ua and "Edg" not in ua
        else "Edge" if "Edg" in ua
        else "Firefox" if "Firefox" in ua
        else "Safari" if "Safari" in ua
        else "Browser"
    )
    os_name = (
        "Windows" if "Windows" in ua
        else "macOS" if "Mac OS" in ua
        else "Linux" if "Linux" in ua
        else "Android" if "Android" in ua
        else "iOS" if "iPhone" in ua or "iPad" in ua
        else "Unknown"
    )
    return browser, os_name


# ── Routes ──────────────────────────────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=201)
@limiter.limit("5/minute")
async def register(request: Request, body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=body.email,
        password_hash=pwd_ctx.hash(body.password),
        name=body.name,
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return TokenResponse(access_token=_create_token(user.id, user.role))


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if not user or not pwd_ctx.verify(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Enforce 2FA if enabled
    if user.totp_enabled:
        if not body.totp_code:
            return TokenResponse(requires_2fa=True)
        if not pyotp.TOTP(user.totp_secret).verify(body.totp_code, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid 2FA code")

    # Record session
    ua = request.headers.get("user-agent", "")
    browser, os_name = _parse_ua(ua)
    ip = request.client.host if request.client else None
    session = UserSession(user_id=user.id, browser=browser, os=os_name, ip=ip)
    db.add(session)
    await db.commit()

    return TokenResponse(access_token=_create_token(user.id, user.role))


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)):
    return user


# ── Profile ──────────────────────────────────────────────────────────────────

@router.patch("/profile", response_model=UserOut)
async def update_profile(
    body: UpdateProfileRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if body.email != user.email:
        existing = await db.execute(select(User).where(User.email == body.email))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already in use")
    user.name = body.name
    user.email = body.email
    user.company = body.company
    user.phone = body.phone
    user.date_of_birth = body.date_of_birth
    user.location = body.location
    user.bio = body.bio
    await db.commit()
    await db.refresh(user)
    return user


# ── Password ──────────────────────────────────────────────────────────────────

@router.post("/change-password", status_code=204)
async def change_password(
    body: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not pwd_ctx.verify(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user.password_hash = pwd_ctx.hash(body.new_password)
    await db.commit()


# ── Preferences ───────────────────────────────────────────────────────────────

async def _get_or_create_prefs(user_id: int, db: AsyncSession) -> UserPreferences:
    result = await db.execute(select(UserPreferences).where(UserPreferences.user_id == user_id))
    prefs = result.scalar_one_or_none()
    if not prefs:
        prefs = UserPreferences(user_id=user_id)
        db.add(prefs)
        await db.commit()
        await db.refresh(prefs)
    return prefs


@router.get("/preferences", response_model=PreferencesOut)
async def get_preferences(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await _get_or_create_prefs(user.id, db)


@router.patch("/preferences", response_model=PreferencesOut)
async def update_preferences(
    body: PreferencesUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    prefs = await _get_or_create_prefs(user.id, db)
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(prefs, field, value)
    await db.commit()
    await db.refresh(prefs)
    return prefs


# ── API Key ───────────────────────────────────────────────────────────────────

async def _get_or_create_api_key(user_id: int, db: AsyncSession) -> UserApiKey:
    result = await db.execute(select(UserApiKey).where(UserApiKey.user_id == user_id))
    api_key = result.scalar_one_or_none()
    if not api_key:
        api_key = UserApiKey(user_id=user_id, key=f"qs_live_sk_{secrets.token_urlsafe(16)}")
        db.add(api_key)
        await db.commit()
        await db.refresh(api_key)
    return api_key


@router.get("/api-key", response_model=ApiKeyOut)
async def get_api_key(
    user: User = Depends(require_role("app_owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    return await _get_or_create_api_key(user.id, db)


@router.post("/api-key/regenerate", response_model=ApiKeyOut)
async def regenerate_api_key(
    user: User = Depends(require_role("app_owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(UserApiKey).where(UserApiKey.user_id == user.id))
    api_key = result.scalar_one_or_none()
    new_key_val = f"qs_live_sk_{secrets.token_urlsafe(16)}"
    if not api_key:
        api_key = UserApiKey(user_id=user.id, key=new_key_val)
        db.add(api_key)
    else:
        api_key.key = new_key_val
        api_key.created_at = datetime.now(timezone.utc)
        api_key.last_used_at = None
    await db.commit()
    await db.refresh(api_key)
    return api_key


# ── Sessions ──────────────────────────────────────────────────────────────────

@router.get("/sessions", response_model=list[SessionOut])
async def get_sessions(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == user.id, UserSession.is_active == True)
        .order_by(UserSession.last_seen_at.desc())
    )
    return result.scalars().all()


@router.delete("/sessions", status_code=204)
async def revoke_all_sessions(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserSession).where(UserSession.user_id == user.id, UserSession.is_active == True)
    )
    for s in result.scalars().all():
        s.is_active = False
    await db.commit()


@router.delete("/sessions/{session_id}", status_code=204)
async def revoke_session(
    session_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserSession).where(UserSession.id == session_id, UserSession.user_id == user.id)
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    session.is_active = False
    await db.commit()


# ── 2FA / TOTP ────────────────────────────────────────────────────────────────

def _make_qr_data_url(otpauth_uri: str) -> str:
    img = qrcode.make(otpauth_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


@router.post("/2fa/setup", response_model=TotpSetupOut)
async def setup_2fa(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a new TOTP secret and return the QR code. Does NOT enable 2FA until /2fa/verify."""
    secret = pyotp.random_base32()
    user.totp_secret = secret
    await db.commit()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="QuantumShield")
    return TotpSetupOut(secret=secret, otpauth_uri=uri, qr_data_url=_make_qr_data_url(uri))


@router.post("/2fa/verify", response_model=UserOut)
async def verify_2fa(
    body: TotpVerifyRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify a TOTP code and enable 2FA if correct."""
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA setup not initiated. Call /2fa/setup first.")
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid or expired code.")
    user.totp_enabled = True
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/2fa/disable", response_model=UserOut)
async def disable_2fa(
    body: TotpVerifyRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable 2FA after confirming a valid TOTP code."""
    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA is not enabled.")
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid or expired code.")
    user.totp_enabled = False
    user.totp_secret = None
    await db.commit()
    await db.refresh(user)
    return user


# ── OAuth ─────────────────────────────────────────────────────────────────────

@router.post("/google", response_model=TokenResponse)
async def oauth_google(body: OAuthGoogleRequest, db: AsyncSession = Depends(get_db)):
    """Verify a Google ID token and return a JWT. Creates the user if new."""
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests

    try:
        idinfo = google_id_token.verify_oauth2_token(
            body.credential, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid Google token: {exc}")

    email = idinfo.get("email")
    name = idinfo.get("name", "")
    if not email:
        raise HTTPException(status_code=400, detail="Google token missing email")

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        user = User(email=email, password_hash="", name=name, role="end_user")
        db.add(user)
        await db.commit()
        await db.refresh(user)

    return TokenResponse(access_token=_create_token(user.id, user.role))


@router.post("/github", response_model=TokenResponse)
async def oauth_github(body: OAuthGithubRequest, db: AsyncSession = Depends(get_db)):
    """Exchange a GitHub authorization code for a JWT. Creates the user if new."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_res = await client.post(
                "https://github.com/login/oauth/access_token",
                json={"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": body.code},
                headers={"Accept": "application/json"},
            )
        token_data = token_res.json()
    except Exception as exc:
        logger.exception("GitHub token exchange failed")
        raise HTTPException(status_code=502, detail=f"GitHub OAuth token exchange failed: {exc}") from exc

    access_token = token_data.get("access_token")
    if not access_token:
        error_msg = token_data.get("error_description") or token_data.get("error") or "no access token"
        raise HTTPException(status_code=401, detail=f"GitHub OAuth failed: {error_msg}")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            user_res = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
            emails_res = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
        gh_user = user_res.json()
        gh_emails = emails_res.json() if emails_res.status_code == 200 else []
    except Exception as exc:
        logger.exception("GitHub user info fetch failed")
        raise HTTPException(status_code=502, detail=f"GitHub user info fetch failed: {exc}") from exc

    # Pick primary verified email
    email = None
    if isinstance(gh_emails, list):
        for entry in gh_emails:
            if entry.get("primary") and entry.get("verified"):
                email = entry["email"]
                break
    if not email:
        email = gh_user.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Could not retrieve email from GitHub")

    name = gh_user.get("name") or gh_user.get("login", "")

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        user = User(email=email, password_hash="", name=name, role="end_user")
        db.add(user)
        await db.commit()
        await db.refresh(user)

    return TokenResponse(access_token=_create_token(user.id, user.role))


# ── Forgot password ───────────────────────────────────────────────────────────

def _create_reset_token(user_id: int) -> str:
    """Create a short-lived (15 min) JWT for password reset."""
    payload = {
        "sub": str(user_id),
        "type": "password_reset",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _send_reset_email(to_email: str, reset_token: str) -> None:
    """Send password-reset email. Silently skips if SMTP is not configured."""
    if not SMTP_HOST or not SMTP_USER:
        logger.warning("SMTP not configured — skipping password-reset email")
        return
    reset_url = f"{FRONTEND_URL}/reset-password?token={reset_token}"
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "QuantumShield — Reset your password"
        msg["From"] = SMTP_USER
        msg["To"] = to_email
        body_text = (
            "You requested a password reset for your QuantumShield account.\n\n"
            f"Click the link below to choose a new password (valid for 15 minutes):\n{reset_url}\n\n"
            "If you did not request this, you can safely ignore this email.\n\n"
            "— The QuantumShield Team"
        )
        body_html = f"""
        <p>You requested a password reset for your <strong>QuantumShield</strong> account.</p>
        <p>
          <a href="{reset_url}" style="
            display:inline-block;padding:10px 20px;background:#6366f1;color:#fff;
            border-radius:6px;text-decoration:none;font-weight:600">
            Reset Password
          </a>
        </p>
        <p style="font-size:12px;color:#888">Link expires in 15 minutes.<br>
        If you did not request this, you can safely ignore this email.</p>
        """
        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if SMTP_PASSWORD:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.sendmail(SMTP_USER, to_email, msg.as_string())
    except Exception:
        logger.exception("Failed to send password-reset email to %s", to_email)


@router.post("/forgot-password", status_code=200)
@limiter.limit("3/minute")
async def forgot_password(request: Request, body: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    """
    Request a password-reset link.

    If the account has 2FA enabled and no totp_code is supplied, returns
    {"requires_totp": true} so the client can show the authenticator prompt.
    Sending the TOTP code in the second call unlocks the email dispatch.
    Always returns 200 for non-existent emails (anti-enumeration).
    """
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if user:
        # If the account has 2FA, the caller must prove ownership via TOTP
        # before we send a reset link — otherwise an attacker with only the
        # email address could bypass 2FA by resetting the password.
        if user.totp_enabled:
            if not body.totp_code:
                return {"requires_totp": True,
                        "message": "This account has two-factor authentication enabled. "
                                   "Please enter your authenticator code to receive a reset link."}
            if not user.totp_secret:
                raise HTTPException(status_code=500, detail="2FA configuration error.")
            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(body.totp_code, valid_window=1):
                # Return 200 with an error flag — avoids leaking whether 2FA is
                # the only thing standing between the attacker and a reset email.
                return {"requires_totp": True, "totp_invalid": True,
                        "message": "Invalid authenticator code. Please try again."}

        reset_token = _create_reset_token(user.id)
        _send_reset_email(user.email, reset_token)

    return {"message": "If that email is registered you will receive a reset link shortly."}


@router.post("/reset-password", status_code=200)
async def reset_password(body: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    """Validate a password-reset token and update the user's password."""
    try:
        payload = jwt.decode(body.token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Reset link has expired. Please request a new one.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid reset link.")

    if payload.get("type") != "password_reset":
        raise HTTPException(status_code=400, detail="Invalid token type.")

    user_id = int(payload["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.password_hash = pwd_ctx.hash(body.new_password)
    await db.commit()
    return {"message": "Password updated successfully. You can now sign in with your new password."}


# ── Set role (first-time OAuth onboarding) ────────────────────────────────────

@router.post("/set-role", response_model=UserOut)
async def set_role(
    body: SetRoleRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Allow a newly OAuth-registered user to select their role (end_user or app_owner)."""
    user.role = body.role
    await db.commit()
    await db.refresh(user)
    return user
