from fastapi import APIRouter, Cookie, HTTPException, Response
from pydantic import BaseModel, Field

from api.db import db
from api.sessions import (
    clear_session_cookie,
    create_session,
    delete_session,
    get_user_by_session,
    set_session_cookie,
)

LEVEL = 0
router = APIRouter(prefix="/api/level0", tags=["level0"])

# Deliberately weak accounts so the attacker view has something to attack.
SEED_ACCOUNTS = [
    ("admin", "admin123"),
    ("alice", "password1"),
    ("bob", "qwerty"),
    ("carol", "letmein"),
]


def seed() -> None:
    with db() as conn:
        conn.executemany(
            "INSERT OR IGNORE INTO users (level, username, password) VALUES (?, ?, ?)",
            [(LEVEL, u, p) for u, p in SEED_ACCOUNTS],
        )


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    # Deliberately weak: any non-empty password is accepted.
    password: str = Field(min_length=1, max_length=128)


@router.post("/login")
def login(creds: Credentials, response: Response):
    # Deliberately insecure: no rate limiting or lockout, so guessing is unlimited.
    with db() as conn:
        # First login with a new username creates the account. INSERT OR IGNORE
        # also keeps this safe if two first logins arrive at the same moment.
        cur = conn.execute(
            "INSERT OR IGNORE INTO users (level, username, password) VALUES (?, ?, ?)",
            (LEVEL, creds.username, creds.password),
        )
        created = cur.rowcount == 1
        row = conn.execute(
            "SELECT id, password FROM users WHERE level = ? AND username = ?",
            (LEVEL, creds.username),
        ).fetchone()

    # Deliberately insecure: plaintext comparison against a plaintext column.
    if row["password"] != creds.password:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    set_session_cookie(response, create_session(row["id"]))
    return {"username": creds.username, "created": created}


@router.get("/me")
def me(session: str | None = Cookie(default=None)):
    user = get_user_by_session(session)
    if user is None or user["level"] != LEVEL:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {"username": user["username"], "level": user["level"]}


@router.post("/logout")
def logout(response: Response, session: str | None = Cookie(default=None)):
    delete_session(session)
    clear_session_cookie(response)
    return {"ok": True}