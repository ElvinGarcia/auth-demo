from fastapi import APIRouter, Cookie, HTTPException, Response
from pydantic import BaseModel, Field

from api.db import db
from api.passwords import hash_password, verify_password
from api.sessions import (
    clear_session_cookie,
    create_session,
    delete_session,
    get_user_by_session,
    set_session_cookie,
    session_cookie_name,
)

LEVEL = 1
router = APIRouter(prefix="/api/level1", tags=["level1"])

# Same weak passwords as Level 0, but stored hashed. A hash cannot stop a weak
# password from being guessed; it only stops the stored value being read.
SEED_ACCOUNTS = [
    ("admin", "admin123"),
    ("alice", "password1"),
    ("bob", "qwerty"),
    ("carol", "letmein"),
]


def seed() -> None:
    with db() as conn:
        for username, password in SEED_ACCOUNTS:
            exists = conn.execute(
                "SELECT 1 FROM users WHERE level = ? AND username = ?", (LEVEL, username)
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO users (level, username, password) VALUES (?, ?, ?)",
                    (LEVEL, username, hash_password(password)),
                )


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    # Still weak on purpose: hashing does not fix a bad password policy.
    password: str = Field(min_length=1, max_length=128)


@router.post("/login")
def login(creds: Credentials, response: Response):
    # Still no rate limiting: online guessing works exactly as in Level 0.
    with db() as conn:
        row = conn.execute(
            "SELECT id, password FROM users WHERE level = ? AND username = ?",
            (LEVEL, creds.username),
        ).fetchone()

        created = False
        if row is None:
            # First login with a new username creates the account (no registration).
            cur = conn.execute(
                "INSERT OR IGNORE INTO users (level, username, password) VALUES (?, ?, ?)",
                (LEVEL, creds.username, hash_password(creds.password)),
            )
            created = cur.rowcount == 1
            row = conn.execute(
                "SELECT id, password FROM users WHERE level = ? AND username = ?",
                (LEVEL, creds.username),
            ).fetchone()

    if not created:
        if not verify_password(creds.password, row["password"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")

    set_session_cookie(response, create_session(row["id"]), LEVEL)
    return {"username": creds.username, "created": created}


@router.get("/me")
def me(session: str | None = Cookie(default=None, alias=session_cookie_name(LEVEL))):
    user = get_user_by_session(session)
    if user is None or user["level"] != LEVEL:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {"username": user["username"], "level": user["level"]}


@router.post("/logout")
def logout(response: Response, session: str | None = Cookie(default=None, alias=session_cookie_name(LEVEL))):
    delete_session(session, LEVEL)
    clear_session_cookie(response, LEVEL)
    return {"ok": True}
