import os

from fastapi import APIRouter, Cookie, HTTPException

from api.auth.level1 import LEVEL, SEED_ACCOUNTS
from api.db import db
from api.sessions import get_user_by_session

router = APIRouter(prefix="/api/level1/attacker", tags=["level1-attacker"])


def _enabled() -> bool:
    # Set ATTACKER_VIEW=0 to switch the whole attacker view off.
    return os.environ.get("ATTACKER_VIEW", "1") == "1"


@router.get("/dump")
def dump(session: str | None = Cookie(default=None)):
    """What a thief holding a copy of the user table sees at Level 1.

    Seeded demo accounts plus the caller's own row, same privacy rule as Level 0.
    """
    if not _enabled():
        raise HTTPException(status_code=404, detail="Not found")

    me = get_user_by_session(session)
    own_id = me["id"] if me and me["level"] == LEVEL else -1
    seeded = [username for username, _ in SEED_ACCOUNTS]
    marks = ",".join("?" * len(seeded))  # only "?" placeholders, never user input

    with db() as conn:
        rows = conn.execute(
            f"""SELECT username, password FROM users
                WHERE level = ? AND (username IN ({marks}) OR id = ?)
                ORDER BY id""",
            (LEVEL, *seeded, own_id),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM users WHERE level = ?", (LEVEL,)
        ).fetchone()[0]

    return {
        "rows": [{"username": r["username"], "stored": r["password"]} for r in rows],
        "hidden": total - len(rows),
    }
