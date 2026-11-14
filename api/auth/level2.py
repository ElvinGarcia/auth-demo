import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Cookie, HTTPException, Response
from pydantic import BaseModel, Field

from api.db import db
from api.passwords import hash_password, verify_password
from api.providers.sms_mock import send_sms
from api.sessions import (
    COOKIE_SECURE,
    clear_session_cookie,
    create_session,
    delete_session,
    get_user_by_session,
    set_session_cookie,
)

LEVEL = 2
router = APIRouter(prefix="/api/level2", tags=["level2"])

CODE_TTL = timedelta(minutes=5)      # a code stops working after this
MAX_ATTEMPTS = 5                     # wrong guesses allowed per code
MAX_CODES = 5                        # codes per account per window (stops SMS flooding too)
CODES_WINDOW = timedelta(minutes=10)
PENDING_COOKIE = "pending"           # which code this browser is trying to enter
PHONE_COOKIE = "phone"               # identifies this browser as a "phone"

# Same weak passwords as the earlier levels. The new factor is the SMS code.
SEED_ACCOUNTS = [
    ("admin", "admin123"),
    ("alice", "password1"),
    ("bob", "qwerty"),
    ("carol", "letmein"),
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _code_hash(challenge_id: str, code: str) -> str:
    # Keyed hash (HMAC). A plain hash of a 6-digit code could be reversed instantly
    # by trying all 1,000,000 values; the key stops that if only the table leaks.
    key = os.environ.get("SMS_CODE_KEY", "dev-only-change-me").encode()
    return hmac.new(key, f"{challenge_id}:{code}".encode(), hashlib.sha256).hexdigest()


def _set_cookie(response: Response, name: str, value: str, max_age: int, path: str) -> None:
    response.set_cookie(
        name, value, httponly=True, samesite="lax",
        secure=COOKIE_SECURE, max_age=max_age, path=path,
    )


def ensure_phone(response: Response, phone: str | None) -> str:
    """Give this browser a 'phone' identity if it has none yet."""
    if phone:
        return phone
    phone = secrets.token_urlsafe(16)
    _set_cookie(response, PHONE_COOKIE, phone, 365 * 24 * 3600, "/")
    return phone


def _assign_number(conn: sqlite3.Connection, user_id: int, device: str | None) -> None:
    for _ in range(20):
        number = f"+1 555 {secrets.randbelow(10_000_000):07d}"
        try:
            conn.execute(
                "INSERT INTO sms_numbers (user_id, number, device) VALUES (?, ?, ?)",
                (user_id, number, device),
            )
            return
        except sqlite3.IntegrityError:
            continue
    raise RuntimeError("could not allocate a phone number")


def seed() -> None:
    with db() as conn:
        for i, (username, password) in enumerate(SEED_ACCOUNTS):
            row = conn.execute(
                "SELECT id FROM users WHERE level = ? AND username = ?", (LEVEL, username)
            ).fetchone()
            if row is None:
                cur = conn.execute(
                    "INSERT INTO users (level, username, password) VALUES (?, ?, ?)",
                    (LEVEL, username, hash_password(password)),
                )
                user_id = cur.lastrowid
            else:
                user_id = row["id"]
            # Seeded numbers belong to nobody's browser (device NULL) until "swapped".
            conn.execute(
                "INSERT OR IGNORE INTO sms_numbers (user_id, number, device) VALUES (?, ?, NULL)",
                (user_id, f"+1 555 01001{i:02d}"),
            )


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)  # still weak on purpose


class CodeBody(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


def _issue_code(user_id: int) -> tuple[str, str]:
    """Create and send a new code. Returns (challenge id, masked number hint)."""
    now = _now()
    challenge_id = secrets.token_urlsafe(24)
    code = f"{secrets.randbelow(1_000_000):06d}"
    with db() as conn:
        recent = conn.execute(
            "SELECT COUNT(*) FROM sms_challenges WHERE user_id = ? AND created_at > ?",
            (user_id, (now - CODES_WINDOW).isoformat()),
        ).fetchone()[0]
        number = None
        if recent < MAX_CODES:
            # A new code invalidates any earlier unused one.
            conn.execute("UPDATE sms_challenges SET used = 1 WHERE user_id = ?", (user_id,))
            conn.execute(
                """INSERT INTO sms_challenges (id, user_id, code_hash, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (challenge_id, user_id, _code_hash(challenge_id, code),
                 now.isoformat(), (now + CODE_TTL).isoformat()),
            )
            number = conn.execute(
                "SELECT number FROM sms_numbers WHERE user_id = ?", (user_id,)
            ).fetchone()["number"]
    if number is None:
        raise HTTPException(status_code=429, detail="Too many codes requested. Wait a few minutes.")
    send_sms(number, f"Your demo code is {code}. It expires in 5 minutes. Never share it.")
    return challenge_id, "ending " + number[-4:]


@router.post("/login")
def login(creds: Credentials, response: Response, phone: str | None = Cookie(default=None)):
    """Step 1: password. If correct, a code is texted and the browser must enter it."""
    device = ensure_phone(response, phone)
    with db() as conn:
        row = conn.execute(
            "SELECT id, password FROM users WHERE level = ? AND username = ?",
            (LEVEL, creds.username),
        ).fetchone()
        created = False
        if row is None:
            # First login with a new username creates the account, as in earlier levels.
            # This browser becomes the account's "phone".
            cur = conn.execute(
                "INSERT OR IGNORE INTO users (level, username, password) VALUES (?, ?, ?)",
                (LEVEL, creds.username, hash_password(creds.password)),
            )
            created = cur.rowcount == 1
            row = conn.execute(
                "SELECT id, password FROM users WHERE level = ? AND username = ?",
                (LEVEL, creds.username),
            ).fetchone()
            if created:
                _assign_number(conn, row["id"], device)

    if not created and not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    challenge_id, hint = _issue_code(row["id"])
    _set_cookie(response, PENDING_COOKIE, challenge_id,
                int(CODE_TTL.total_seconds()), "/api/level2")
    return {"step": "code", "phone_hint": hint, "created": created}


@router.post("/verify")
def verify(body: CodeBody, response: Response, pending: str | None = Cookie(default=None)):
    """Step 2: the code. Single use, expires, and limited to MAX_ATTEMPTS guesses."""
    if not pending:
        raise HTTPException(status_code=401, detail="Log in with your password first")

    outcome = "bad"
    user_id = username = None
    with db() as conn:
        ch = conn.execute(
            """SELECT c.*, u.username FROM sms_challenges c
               JOIN users u ON u.id = c.user_id WHERE c.id = ?""",
            (pending,),
        ).fetchone()
        if ch is None or ch["used"] or datetime.fromisoformat(ch["expires_at"]) < _now():
            outcome = "expired"
        elif ch["attempts"] >= MAX_ATTEMPTS:
            outcome = "locked"
        else:
            conn.execute("UPDATE sms_challenges SET attempts = attempts + 1 WHERE id = ?", (pending,))
            if hmac.compare_digest(_code_hash(pending, body.code), ch["code_hash"]):
                conn.execute("UPDATE sms_challenges SET used = 1 WHERE id = ?", (pending,))
                outcome, user_id, username = "ok", ch["user_id"], ch["username"]

    # Raise after the `with` block: leaving it by exception would roll the attempt count back.
    if outcome == "expired":
        raise HTTPException(status_code=401, detail="Code expired or already used. Log in again.")
    if outcome == "locked":
        raise HTTPException(status_code=429, detail="Too many wrong codes. Log in again for a new one.")
    if outcome == "bad":
        raise HTTPException(status_code=401, detail="Wrong code")

    response.delete_cookie(PENDING_COOKIE, path="/api/level2")
    set_session_cookie(response, create_session(user_id))
    return {"username": username}


@router.get("/inbox")
def inbox(response: Response, phone: str | None = Cookie(default=None)):
    """The simulated phone: texts for numbers this browser currently holds."""
    device = ensure_phone(response, phone)
    with db() as conn:
        rows = conn.execute(
            """SELECT o.number, o.body, o.created_at FROM sms_outbox o
               JOIN sms_numbers n ON n.number = o.number
               WHERE n.device = ? ORDER BY o.id DESC LIMIT 20""",
            (device,),
        ).fetchall()
    return {"messages": [dict(r) for r in rows]}


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
    response.delete_cookie(PENDING_COOKIE, path="/api/level2")
    return {"ok": True}
