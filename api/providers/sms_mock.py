"""Mock SMS provider: "sends" a text by writing it to the sms_outbox table.

A real provider (Twilio and similar) would replace send_sms() and nothing else
would need to change. The mock means the demo can never text a real number or
run up a bill.
"""
from api.db import db


def send_sms(number: str, body: str) -> None:
    with db() as conn:
        conn.execute("INSERT INTO sms_outbox (number, body) VALUES (?, ?)", (number, body))
