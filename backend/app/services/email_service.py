"""Outbound email. The only place that talks to an email provider, so
swapping providers later means changing this file and nothing else.

Deliberately never logs a message body or subject: verification emails carry
one-time codes, and codes must never reach the logs.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

from app import config

logger = logging.getLogger("hedr.email")


class EmailNotConfiguredError(RuntimeError):
    """SMTP settings are missing, so nothing can be sent."""


class EmailDeliveryError(RuntimeError):
    """The provider rejected the message or could not be reached."""


def is_configured() -> bool:
    return bool(config.SMTP_HOST and config.SMTP_FROM)


def send_email(*, to: str, subject: str, body: str) -> None:
    if not is_configured():
        raise EmailNotConfiguredError("Email delivery is not configured.")

    message = EmailMessage()
    message["From"] = config.SMTP_FROM
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)

    security = config.SMTP_SECURITY
    try:
        if security == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                config.SMTP_HOST, config.SMTP_PORT, timeout=15, context=ssl.create_default_context()
            )
        else:
            client = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15)
        with client:
            if security == "starttls":
                client.starttls(context=ssl.create_default_context())
            if config.SMTP_USERNAME:
                client.login(config.SMTP_USERNAME, config.SMTP_PASSWORD or "")
            client.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        # Log the failure class only - never the message.
        logger.error("Email delivery failed (%s).", type(exc).__name__)
        raise EmailDeliveryError("Email could not be delivered.") from exc
