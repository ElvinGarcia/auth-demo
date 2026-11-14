import base64
import hmac
import io
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Cookie, HTTPException, Response
from pydantic import BaseModel, Field

from api.db import db
from api.passwords import hash_password, verify_password
from api.sessions import (
    COOKIE_SECURE,
    clear_session_cookie,
    create_session,
    delete_session,
    get_user_by_session,
    set_session_cookie,
)

LEVEL = 4
router = APIRouter(prefix="/api/level4", tags=["level4"])

ISSUER = "Auth Ladder Demo"
STEP = 30                            # seconds per code
DRIFT_STEPS = 1                      # accept one step either side of "now" (clock drift)
CHALLENGE_TTL = timedelta(minutes=5)  # time allowed between password and code
MAX_ATTEMPTS = 5                     # wrong codes per login attempt
MAX_CHALLENGES = 5                   # password-verified login attempts per account per window
CHALLENGES_WINDOW = timedelta(minutes=10)
PENDING_COOKIE = "pending"

# Same weak passwords as the earlier levels. The new factor is the authenticator app.
SEED_ACCOUNTS = [
    ("admin", "admin123"),
    ("alice", "password1"),
    ("bob", "qwerty"),
    ("carol", "letmein"),
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def match_step(secret: str, code: str, now: datetime) -> int | None:
    """Return the time step `code` is valid for (within the drift window), or None."""
    totp = pyotp.TOTP(secret, interval=STEP)
    current = int(now.timestamp()) // STEP
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if hmac.compare_digest(totp.at(step * STEP), code):
            return step
    return None


def _qr_data_url(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=10)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


def _enrollment(username: str, secret: str) -> dict:
    uri = pyotp.TOTP(secret, interval=STEP).provisioning_uri(name=username, issuer_name=ISSUER)
    return {"secret": secret, "uri": uri, "qr": _qr_data_url(uri)}


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
            # Seeded accounts are already enrolled: their "phone" is nobody's browser.
            conn.execute(
                "INSERT OR IGNORE INTO totp_secrets (user_id, secret, confirmed) VALUES (?, ?, 1)",
                (user_id, pyotp.random_base32()),
            )


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)  # still weak on purpose


class CodeBody(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


@router.post("/login")
def login(creds: Credentials, response: Response):
    """Step 1: password. Step 2 (/verify) is the code from the user's authenticator app."""
    with db() as conn:
        row = conn.execute(
            "SELECT id, password FROM users WHERE level = ? AND username = ?",
            (LEVEL, creds.username),
        ).fetchone()
        created = False
        if row is None:
            # First login with a new username creates the account, as in earlier levels,
            # and generates its (not yet confirmed) TOTP secret.
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
                conn.execute(
                    "INSERT INTO totp_secrets (user_id, secret) VALUES (?, ?)",
                    (row["id"], pyotp.random_base32()),
                )

    if not created and not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    now = _now()
    challenge_id = secrets.token_urlsafe(24)
    enroll = None
    too_many = False
    with db() as conn:
        recent = conn.execute(
            "SELECT COUNT(*) FROM totp_challenges WHERE user_id = ? AND created_at > ?",
            (row["id"], (now - CHALLENGES_WINDOW).isoformat()),
        ).fetchone()[0]
        if recent >= MAX_CHALLENGES:
            too_many = True
        else:
            conn.execute("UPDATE totp_challenges SET used = 1 WHERE user_id = ?", (row["id"],))
            conn.execute(
                "INSERT INTO totp_challenges (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (challenge_id, row["id"], now.isoformat(), (now + CHALLENGE_TTL).isoformat()),
            )
            t = conn.execute(
                "SELECT secret, confirmed FROM totp_secrets WHERE user_id = ?", (row["id"],)
            ).fetchone()
            if not t["confirmed"]:
                enroll = _enrollment(creds.username, t["secret"])
    if too_many:
        raise HTTPException(status_code=429, detail="Too many login attempts. Wait a few minutes.")

    response.set_cookie(
        PENDING_COOKIE, challenge_id, httponly=True, samesite="lax", secure=COOKIE_SECURE,
        max_age=int(CHALLENGE_TTL.total_seconds()), path="/api/level4",
    )
    if enroll:
        # Shown once, while the account is not yet confirmed. Never returned afterwards.
        return {"step": "enroll", "enroll": enroll, "created": created}
    return {"step": "code", "created": created}


@router.post("/verify")
def verify(body: CodeBody, response: Response, pending: str | None = Cookie(default=None)):
    """Check the code. It confirms enrollment the first time and works once per time step."""
    if not pending:
        raise HTTPException(status_code=401, detail="Log in with your password first")

    now = _now()
    outcome = "bad"
    user_id = username = None
    with db() as conn:
        ch = conn.execute(
            """SELECT c.*, u.username FROM totp_challenges c
               JOIN users u ON u.id = c.user_id WHERE c.id = ?""",
            (pending,),
        ).fetchone()
        if ch is None or ch["used"] or datetime.fromisoformat(ch["expires_at"]) < now:
            outcome = "expired"
        elif ch["attempts"] >= MAX_ATTEMPTS:
            outcome = "locked"
        else:
            conn.execute("UPDATE totp_challenges SET attempts = attempts + 1 WHERE id = ?", (pending,))
            t = conn.execute(
                "SELECT secret, last_step FROM totp_secrets WHERE user_id = ?", (ch["user_id"],)
            ).fetchone()
            step = match_step(t["secret"], body.code, now)
            # step <= last_step means this code (or an older one) was already used: no replay.
            if step is not None and step > t["last_step"]:
                conn.execute(
                    "UPDATE totp_secrets SET last_step = ?, confirmed = 1 WHERE user_id = ?",
                    (step, ch["user_id"]),
                )
                conn.execute("UPDATE totp_challenges SET used = 1 WHERE id = ?", (pending,))
                outcome, user_id, username = "ok", ch["user_id"], ch["username"]

    # Raise after the `with` block: leaving it by exception would roll the attempt count back.
    if outcome == "expired":
        raise HTTPException(status_code=401, detail="Login expired or already used. Start again.")
    if outcome == "locked":
        raise HTTPException(status_code=429, detail="Too many wrong codes. Log in again.")
    if outcome == "bad":
        raise HTTPException(status_code=401, detail="Wrong code")

    response.delete_cookie(PENDING_COOKIE, path="/api/level4")
    set_session_cookie(response, create_session(user_id))
    return {"username": username}


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
    response.delete_cookie(PENDING_COOKIE, path="/api/level4")
    return {"ok": True}
