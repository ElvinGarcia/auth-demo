import os

from fastapi import APIRouter, Cookie, HTTPException, Response

from api.auth.level3 import LEVEL, SEED_ACCOUNTS, ensure_mailbox_device
from api.db import db
from api.sessions import get_user_by_session, session_cookie_name

router = APIRouter(prefix="/api/level3/attacker", tags=["level3-attacker"])


def _enabled() -> bool:
    # Set ATTACKER_VIEW=0 to switch the whole attacker view off.
    return os.environ.get("ATTACKER_VIEW", "1") == "1"


@router.get("/targets")
def targets(response: Response, session: str | None = Cookie(default=None, alias=session_cookie_name(LEVEL)),
            mailbox: str | None = Cookie(default=None)):
    """Seeded demo accounts plus the caller's own. Never other visitors."""
    if not _enabled():
        raise HTTPException(status_code=404, detail="Not found")
    device = ensure_mailbox_device(response, mailbox)
    allowed = {u for u, _ in SEED_ACCOUNTS}
    me = get_user_by_session(session)
    if me and me["level"] == LEVEL:
        allowed.add(me["username"])
    marks = ",".join("?" * len(allowed))  # only "?" placeholders, never user input
    with db() as conn:
        rows = conn.execute(
            f"""SELECT u.username, a.address,
                       EXISTS(SELECT 1 FROM mailbox_grants g
                              WHERE g.device = ? AND g.address = a.address) AS opened
                FROM users u JOIN email_addresses a ON a.user_id = u.id
                WHERE u.level = ? AND u.username IN ({marks}) ORDER BY u.id""",
            (device, LEVEL, *sorted(allowed)),
        ).fetchall()
    return {"targets": [
        {"username": r["username"], "address": r["address"], "mailbox_open": bool(r["opened"])}
        for r in rows
    ]}
