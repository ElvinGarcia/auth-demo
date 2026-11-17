import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Cookie, HTTPException, Response
from pydantic import BaseModel, Field

from api.db import db
from api.passwords import DUMMY_HASH, hash_password, verify_password
from api.providers.email_mock import send_email
from api.sessions import (
    COOKIE_SECURE,
    clear_session_cookie,
    create_session,
    delete_session,
    get_user_by_session,
    set_session_cookie,
    session_cookie_name,
)

LEVEL = 3
router = APIRouter(prefix="/api/level3", tags=["level3"])

EMAIL_DOMAIN = "demo.invalid"        # reserved TLD: can never receive real mail
CODE_TTL = timedelta(minutes=10)     # email is slower than SMS, so codes live longer
MAX_ATTEMPTS = 5
MAX_CODES = 5
CODES_WINDOW = timedelta(minutes=10)
PENDING_COOKIE = "pending"           # which code this browser is trying to enter
MAILBOX_COOKIE = "mailbox"           # identifies this browser to the mock mail system

# Same weak passwords as the earlier levels. The new factor is the emailed code.
SEED_ACCOUNTS = [
    ("admin", "admin123"),
    ("alice", "password1"),
    ("bob", "qwerty"),
    ("carol", "letmein"),
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _code_hash(challenge_id: str, code: str) -> str:
    # Keyed hash: a plain hash of a 6-digit code could be reversed by trying all 1,000,000.
    key = os.environ.get("EMAIL_CODE_KEY", "dev-only-change-me").encode()
    return hmac.new(key, f"{challenge_id}:{code}".encode(), hashlib.sha256).hexdigest()


def _set_cookie(response: Response, name: str, value: str, max_age: int, path: str) -> None:
    response.set_cookie(
        name, value, httponly=True, samesite="lax",
        secure=COOKIE_SECURE, max_age=max_age, path=path,
    )


def ensure_mailbox_device(response: Response, token: str | None) -> str:
    """Give this browser an identity with the mock mail system if it has none yet."""
    if token:
        return token
    token = secrets.token_urlsafe(16)
    _set_cookie(response, MAILBOX_COOKIE, token, 365 * 24 * 3600, "/")
    return token


def _mask(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}"


def seed() -> None:
    with db() as conn:
        for username, password in SEED_ACCOUNTS:
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
            conn.execute(
                "INSERT OR IGNORE INTO email_addresses (user_id, address) VALUES (?, ?)",
                (user_id, f"{username}@{EMAIL_DOMAIN}"),
            )


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)  # still weak on purpose


class CodeBody(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


def _issue_code(user_id: int) -> tuple[str, str]:
    """Create and email a new code. Returns (challenge id, masked address)."""
    now = _now()
    challenge_id = secrets.token_urlsafe(24)
    code = f"{secrets.randbelow(1_000_000):06d}"
    address = None
    with db() as conn:
        recent = conn.execute(
            "SELECT COUNT(*) FROM email_challenges WHERE user_id = ? AND created_at > ?",
            (user_id, (now - CODES_WINDOW).isoformat()),
        ).fetchone()[0]
        if recent < MAX_CODES:
            conn.execute("UPDATE email_challenges SET used = 1 WHERE user_id = ?", (user_id,))
            conn.execute(
                """INSERT INTO email_challenges (id, user_id, code_hash, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (challenge_id, user_id, _code_hash(challenge_id, code),
                 now.isoformat(), (now + CODE_TTL).isoformat()),
            )
            address = conn.execute(
                "SELECT address FROM email_addresses WHERE user_id = ?", (user_id,)
            ).fetchone()["address"]
    if address is None:
        raise HTTPException(status_code=429, detail="Too many codes requested. Wait a few minutes.")
    send_email(
        address,
        "Your demo login code",
        f"Your code is {code}. It expires in 10 minutes.\n\n"
        "If you did not try to log in, someone knows your password. Change it now.",
    )
    return challenge_id, _mask(address)


@router.post("/login")
def login(creds: Credentials, response: Response, mailbox: str | None = Cookie(default=None)):
    """Step 1: password. If correct, a code is emailed and the browser must enter it."""
    device = ensure_mailbox_device(response, mailbox)
    with db() as conn:
        row = conn.execute(
            "SELECT id, password FROM users WHERE level = ? AND username = ?",
            (LEVEL, creds.username),
        ).fetchone()
        created = False
        if row is None:
            # First login with a new username creates the account, as in earlier levels.
            # This browser gets the new account's mailbox.
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
                address = f"user{row['id']}@{EMAIL_DOMAIN}"
                conn.execute(
                    "INSERT INTO email_addresses (user_id, address) VALUES (?, ?)",
                    (row["id"], address),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO mailbox_grants (device, address) VALUES (?, ?)",
                    (device, address),
                )

    if not created and not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    challenge_id, hint = _issue_code(row["id"])
    _set_cookie(response, PENDING_COOKIE, challenge_id,
                int(CODE_TTL.total_seconds()), "/api/level3")
    return {"step": "code", "email_hint": hint, "created": created}


@router.post("/verify")
def verify(body: CodeBody, response: Response, pending: str | None = Cookie(default=None)):
    """Step 2: the code. Single use, expires, and limited to MAX_ATTEMPTS guesses."""
    if not pending:
        raise HTTPException(status_code=401, detail="Log in with your password first")

    outcome = "bad"
    user_id = username = None
    with db() as conn:
        ch = conn.execute(
            """SELECT c.*, u.username FROM email_challenges c
               JOIN users u ON u.id = c.user_id WHERE c.id = ?""",
            (pending,),
        ).fetchone()
        if ch is None or ch["used"] or datetime.fromisoformat(ch["expires_at"]) < _now():
            outcome = "expired"
        elif ch["attempts"] >= MAX_ATTEMPTS:
            outcome = "locked"
        else:
            conn.execute("UPDATE email_challenges SET attempts = attempts + 1 WHERE id = ?", (pending,))
            if hmac.compare_digest(_code_hash(pending, body.code), ch["code_hash"]):
                conn.execute("UPDATE email_challenges SET used = 1 WHERE id = ?", (pending,))
                outcome, user_id, username = "ok", ch["user_id"], ch["username"]

    # Raise after the `with` block: leaving it by exception would roll the attempt count back.
    if outcome == "expired":
        raise HTTPException(status_code=401, detail="Code expired or already used. Log in again.")
    if outcome == "locked":
        raise HTTPException(status_code=429, detail="Too many wrong codes. Log in again for a new one.")
    if outcome == "bad":
        raise HTTPException(status_code=401, detail="Wrong code")

    response.delete_cookie(PENDING_COOKIE, path="/api/level3")
    set_session_cookie(response, create_session(user_id), LEVEL)
    return {"username": username}


# --- the mock mail system ("webmail") -------------------------------------------

@router.post("/mailbox/login")
def mailbox_login(creds: Credentials, response: Response,
                  mailbox: str | None = Cookie(default=None)):
    """Open a mailbox in this browser.

    Modelled on the common real-world mistake: the mailbox uses the SAME password
    as the account it protects, so anyone who knows one can open the other.
    """
    device = ensure_mailbox_device(response, mailbox)
    with db() as conn:
        row = conn.execute(
            """SELECT u.password, a.address FROM users u
               JOIN email_addresses a ON a.user_id = u.id
               WHERE u.level = ? AND u.username = ?""",
            (LEVEL, creds.username),
        ).fetchone()
    # Same work whether or not the user exists, so timing does not reveal usernames.
    ok = verify_password(creds.password, row["password"] if row else DUMMY_HASH)
    if row is None or not ok:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO mailbox_grants (device, address) VALUES (?, ?)",
            (device, row["address"]),
        )
    return {"address": row["address"]}


@router.get("/mailbox")
def mailbox_view(response: Response, mailbox: str | None = Cookie(default=None)):
    """The simulated inbox: mail for every address this browser has opened."""
    device = ensure_mailbox_device(response, mailbox)
    with db() as conn:
        rows = conn.execute(
            """SELECT o.address, o.subject, o.body, o.created_at FROM email_outbox o
               JOIN mailbox_grants g ON g.address = o.address
               WHERE g.device = ? ORDER BY o.id DESC LIMIT 20""",
            (device,),
        ).fetchall()
        addresses = conn.execute(
            "SELECT address FROM mailbox_grants WHERE device = ? ORDER BY address", (device,)
        ).fetchall()
    return {"addresses": [a["address"] for a in addresses], "messages": [dict(r) for r in rows]}


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
    response.delete_cookie(PENDING_COOKIE, path="/api/level3")
    return {"ok": True}
