"""Contact form routes."""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.db_models import ContactMessage
from ..schemas.pydantic_schemas import ContactMessageRequest, ContactMessageOut
from .auth import require_role
from ..config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, CONTACT_RECIPIENT

router = APIRouter(prefix="/contact", tags=["contact"])

logger = logging.getLogger(__name__)


def _send_contact_email(name: str, sender_email: str, subject: str, message: str) -> None:
    """Send contact form submission by email. Silently skips if SMTP is not configured."""
    if not SMTP_HOST or not CONTACT_RECIPIENT:
        return

    try:
        email = MIMEMultipart("alternative")
        email["Subject"] = f"[QuantumShield Contact] {subject}"
        email["From"] = SMTP_USER or sender_email
        email["To"] = CONTACT_RECIPIENT
        email["Reply-To"] = sender_email

        body = (
            f"Name: {name}\n"
            f"Email: {sender_email}\n"
            f"Subject: {subject}\n\n"
            f"{message}"
        )
        email.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.sendmail(email["From"], CONTACT_RECIPIENT, email.as_string())
    except Exception:
        logger.exception("Failed to send contact form email")


@router.post("/", response_model=ContactMessageOut, status_code=201)
async def send_message(
    body: ContactMessageRequest,
    db: AsyncSession = Depends(get_db),
):
    msg = ContactMessage(
        name=body.name,
        email=body.email,
        subject=body.subject,
        message=body.message,
    )
    db.add(msg)
    await db.commit()
    await db.refresh(msg)

    _send_contact_email(body.name, body.email, body.subject, body.message)

    return msg


@router.get("/messages", response_model=list[ContactMessageOut])
async def list_messages(
    _admin=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ContactMessage).order_by(ContactMessage.created_at.desc())
    )
    return result.scalars().all()
