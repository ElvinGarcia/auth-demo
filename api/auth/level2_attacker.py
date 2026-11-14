import os

from fastapi import APIRouter, Cookie, HTTPException, Response
from pydantic import BaseModel, Field

from api.auth.level2 import LEVEL, SEED_ACCOUNTS, ensure_phone
from api.db import db
from api.sessions import get_user_by_session

router = APIRouter(prefix="/api/level2/attacker", tags=["level2-attacker"])


def _enabled() -> bool:
    # Set ATTACKER_VIEW=0 to switch the whole attacker view off.
    return os.environ.get("ATTACKER_VIEW", "1") == "1"


def _allowed_usernames(session: str | None) -> set[str]:
    """Seeded demo accounts, plus the caller's own account. Never other visitors."""
    allowed = {u for u, _ in SEED_ACCOUNTS}
    me = get_user_by_session(session)
    if me and me["level"] == LEVEL:
        allowed.add(me["username"])
    return allowed


@router.get("/targets")
def targets(response: Response, session: str | None = Cookie(default=None),
            phone: str | None = Cookie(default=None)):
    if not _enabled():
        raise HTTPException(status_code=404, detail="Not found")
    device = ensure_phone(response, phone)
    allowed = _allowed_usernames(session)
    marks = ",".join("?" * len(allowed))  # only "?" placeholders, never user input
    with db() as conn:
        rows = conn.execute(
            f"""SELECT u.username, n.number, n.device FROM users u
                JOIN sms_numbers n ON n.user_id = u.id
                WHERE u.level = ? AND u.username IN ({marks}) ORDER BY u.id""",
            (LEVEL, *sorted(allowed)),
        ).fetchall()
    return {"targets": [
        {"username": r["username"], "number": r["number"], "held_by_you": r["device"] == device}
        for r in rows
    ]}


class SwapBody(BaseModel):
    username: str = Field(min_length=1, max_length=32)


@router.post("/sim-swap")
def sim_swap(body: SwapBody, response: Response, session: str | None = Cookie(default=None),
             phone: str | None = Cookie(default=None)):
    """Simulates a carrier moving the victim's number onto the attacker's SIM."""
    if not _enabled():
        raise HTTPException(status_code=404, detail="Not found")
    if body.username not in _allowed_usernames(session):
        raise HTTPException(status_code=403, detail="Only the seeded demo accounts can be targeted")
    device = ensure_phone(response, phone)
    with db() as conn:
        cur = conn.execute(
            """UPDATE sms_numbers SET device = ? WHERE user_id =
               (SELECT id FROM users WHERE level = ? AND username = ?)""",
            (device, LEVEL, body.username),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No such account")
        number = conn.execute(
            """SELECT number FROM sms_numbers WHERE user_id =
               (SELECT id FROM users WHERE level = ? AND username = ?)""",
            (LEVEL, body.username),
        ).fetchone()["number"]
    return {"username": body.username, "number": number, "held_by_you": True}
