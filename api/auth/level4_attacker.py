import os

from fastapi import APIRouter, Cookie, HTTPException

from api.auth.level4 import LEVEL, SEED_ACCOUNTS
from api.db import db
from api.sessions import get_user_by_session

router = APIRouter(prefix="/api/level4/attacker", tags=["level4-attacker"])


def _enabled() -> bool:
    # Set ATTACKER_VIEW=0 to switch the whole attacker view off.
    return os.environ.get("ATTACKER_VIEW", "1") == "1"


@router.get("/dump")
def dump(session: str | None = Cookie(default=None)):
    """What a thief holding a copy of the TOTP table sees.

    Seeded demo accounts plus the caller's own row, same privacy rule as the other levels.
    """
    if not _enabled():
        raise HTTPException(status_code=404, detail="Not found")
    me = get_user_by_session(session)
    own_id = me["id"] if me and me["level"] == LEVEL else -1
    seeded = [u for u, _ in SEED_ACCOUNTS]
    marks = ",".join("?" * len(seeded))  # only "?" placeholders, never user input
    with db() as conn:
        rows = conn.execute(
            f"""SELECT u.username, t.secret, t.confirmed FROM totp_secrets t
                JOIN users u ON u.id = t.user_id
                WHERE u.level = ? AND (u.username IN ({marks}) OR u.id = ?)
                ORDER BY u.id""",
            (LEVEL, *seeded, own_id),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM users WHERE level = ?", (LEVEL,)
        ).fetchone()[0]
    return {
        "rows": [{"username": r["username"], "secret": r["secret"],
                  "confirmed": bool(r["confirmed"])} for r in rows],
        "hidden": total - len(rows),
    }
