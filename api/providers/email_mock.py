"""Mock email provider: "sends" a message by writing it to the email_outbox table.

A real provider (Resend, SES and similar) would replace send_email() and nothing
else would need to change. The mock means the demo can never email a real person.
"""
from api.db import db


def send_email(address: str, subject: str, body: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO email_outbox (address, subject, body) VALUES (?, ?, ?)",
            (address, subject, body),
        )
