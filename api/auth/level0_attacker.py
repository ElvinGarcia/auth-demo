import hashlib
import os
import secrets

from fastapi import APIRouter, Cookie, HTTPException

from api.auth.level0 import LEVEL, SEED_ACCOUNTS
from api.db import db
from api.sessions import get_user_by_session

router = APIRouter(prefix="/api/level0/attacker", tags=["level0-attacker"])

ITERATIONS = 100_000


def _enabled() -> bool:
    # Set ATTACKER_VIEW=0 to switch the whole attacker view off.
    return os.environ.get("ATTACKER_VIEW", "1") == "1"


def _hash(password: str) -> str:
    """Salted PBKDF2-SHA256: what a properly hashed dump would look like."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


@router.get("/breach")
def breach(session: str | None = Cookie(default=None)):
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
        "plaintext": [{"username": r["username"], "password": r["password"]} for r in rows],
        # Demo only: computed on the fly. A real system would store only the hash.
        "hashed": [{"username": r["username"], "hash": _hash(r["password"])} for r in rows],
        "hidden": total - len(rows),
    }