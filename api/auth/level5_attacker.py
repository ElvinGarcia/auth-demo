import os

from fastapi import APIRouter, Cookie, HTTPException

from api.auth.level5 import LEVEL, SEED_ACCOUNTS
from api.db import db
from api.sessions import get_user_by_session

router = APIRouter(prefix="/api/level5/attacker", tags=["level5-attacker"])


def _enabled() -> bool:
    # Set ATTACKER_VIEW=0 to switch the whole attacker view off.
    return os.environ.get("ATTACKER_VIEW", "1") == "1"


@router.get("/dump")
def dump(session: str | None = Cookie(default=None)):
    """What a thief holding a copy of the credentials table sees.

    Seeded demo accounts plus the caller's own rows, same privacy rule as the other levels.
    """
    if not _enabled():
        raise HTTPException(status_code=404, detail="Not found")
    me = get_user_by_session(session)
    own_id = me["id"] if me and me["level"] == LEVEL else -1
    seeded = [u for u, _ in SEED_ACCOUNTS]
    marks = ",".join("?" * len(seeded))  # only "?" placeholders, never user input
    with db() as conn:
        rows = conn.execute(
            f"""SELECT u.username, c.credential_id, c.public_key, c.sign_count
                FROM webauthn_credentials c JOIN users u ON u.id = c.user_id
                WHERE u.level = ? AND (u.username IN ({marks}) OR u.id = ?)
                ORDER BY u.id""",
            (LEVEL, *seeded, own_id),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM users WHERE level = ?", (LEVEL,)
        ).fetchone()[0]
    return {
        "rows": [dict(r) for r in rows],
        "hidden": total - len(rows),
    }
