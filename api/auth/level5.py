import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import APIRouter, Cookie, HTTPException, Response
from pydantic import BaseModel, Field
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from api.db import db
from api.passwords import hash_password, verify_password
from api.sessions import (
    COOKIE_SECURE,
    clear_session_cookie,
    create_session,
    delete_session,
    get_user_by_session,
    set_session_cookie,
    session_cookie_name,
)

LEVEL = 5
router = APIRouter(prefix="/api/level5", tags=["level5"])

RP_NAME = "Auth Ladder Demo"
CHALLENGE_TTL = timedelta(minutes=5)   # time allowed between password and security key
MAX_CHALLENGES = 5                     # password-verified login attempts per account per window
CHALLENGES_WINDOW = timedelta(minutes=10)
PENDING_COOKIE = "pending"

# Same weak passwords as the earlier levels. The new factor is a security key or passkey.
SEED_ACCOUNTS = [
    ("admin", "admin123"),
    ("alice", "password1"),
    ("bob", "qwerty"),
    ("carol", "letmein"),
]


def rp_id() -> str:
    """The site name credentials are bound to. A credential made for one RP ID is
    unusable on any other, which is what defeats look-alike phishing sites."""
    return os.environ.get("WEBAUTHN_RP_ID", "localhost")


def expected_origins() -> list[str]:
    """Origins this server accepts. Fixed by configuration, NEVER taken from the request:
    trusting the request's Origin header would let a phishing site approve itself."""
    raw = os.environ.get("WEBAUTHN_ORIGINS", "http://localhost:8000")
    return [o.strip() for o in raw.split(",") if o.strip()]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _user_handle(user_id: int) -> bytes:
    # Opaque identifier for the account that contains no personal information.
    return hashlib.sha256(f"level5:{user_id}".encode()).digest()[:16]


def _throwaway_public_key() -> bytes:
    """A real-looking public key whose private half is discarded at once.

    Seeded accounts get one, so nobody can enroll their own key on `admin` just by
    knowing its password, and nobody can ever log in as admin.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    return cbor2.dumps({1: 2, 3: -7, -1: 1,
                        -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})


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
            has_key = conn.execute(
                "SELECT 1 FROM webauthn_credentials WHERE user_id = ?", (user_id,)
            ).fetchone()
            if not has_key:
                conn.execute(
                    "INSERT INTO webauthn_credentials (credential_id, user_id, public_key) VALUES (?, ?, ?)",
                    (bytes_to_base64url(secrets.token_bytes(16)), user_id,
                     bytes_to_base64url(_throwaway_public_key())),
                )


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)  # still weak on purpose


class CredentialBody(BaseModel):
    credential: dict


@router.post("/login")
def login(creds: Credentials, response: Response):
    """Step 1: password. The reply carries the options the browser hands to the authenticator."""
    with db() as conn:
        row = conn.execute(
            "SELECT id, password FROM users WHERE level = ? AND username = ?",
            (LEVEL, creds.username),
        ).fetchone()
        created = False
        if row is None:
            # First login with a new username creates the account, as in earlier levels.
            cur = conn.execute(
                "INSERT OR IGNORE INTO users (level, username, password) VALUES (?, ?, ?)",
                (LEVEL, creds.username, hash_password(creds.password)),
            )
            created = cur.rowcount == 1
            row = conn.execute(
                "SELECT id, password FROM users WHERE level = ? AND username = ?",
                (LEVEL, creds.username),
            ).fetchone()

    if not created and not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    now = _now()
    pending_id = secrets.token_urlsafe(24)
    too_many = False
    options = None
    with db() as conn:
        recent = conn.execute(
            "SELECT COUNT(*) FROM webauthn_challenges WHERE user_id = ? AND created_at > ?",
            (row["id"], (now - CHALLENGES_WINDOW).isoformat()),
        ).fetchone()[0]
        if recent >= MAX_CHALLENGES:
            too_many = True
        else:
            conn.execute("UPDATE webauthn_challenges SET used = 1 WHERE user_id = ?", (row["id"],))
            keys = conn.execute(
                "SELECT credential_id FROM webauthn_credentials WHERE user_id = ?", (row["id"],)
            ).fetchall()
            if keys:
                kind = "authenticate"
                options = generate_authentication_options(
                    rp_id=rp_id(),
                    allow_credentials=[
                        PublicKeyCredentialDescriptor(id=base64url_to_bytes(k["credential_id"]))
                        for k in keys
                    ],
                    user_verification=UserVerificationRequirement.PREFERRED,
                )
            else:
                kind = "register"
                options = generate_registration_options(
                    rp_id=rp_id(),
                    rp_name=RP_NAME,
                    user_name=creds.username,
                    user_id=_user_handle(row["id"]),
                    user_display_name=creds.username,
                    authenticator_selection=AuthenticatorSelectionCriteria(
                        user_verification=UserVerificationRequirement.PREFERRED),
                )
            conn.execute(
                """INSERT INTO webauthn_challenges
                   (id, user_id, kind, challenge, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)""",
                (pending_id, row["id"], kind, bytes_to_base64url(options.challenge),
                 now.isoformat(), (now + CHALLENGE_TTL).isoformat()),
            )
    if too_many:
        raise HTTPException(status_code=429, detail="Too many login attempts. Wait a few minutes.")

    response.set_cookie(
        PENDING_COOKIE, pending_id, httponly=True, samesite="lax", secure=COOKIE_SECURE,
        max_age=int(CHALLENGE_TTL.total_seconds()), path="/api/level5",
    )
    step = "authenticate" if kind == "authenticate" else "register"
    return {"step": step, "options": json.loads(options_to_json(options)), "created": created}


def _take_challenge(pending: str | None, kind: str) -> dict:
    """Consume a pending challenge. ANY attempt burns it, so each challenge gets one try."""
    if not pending:
        raise HTTPException(status_code=401, detail="Log in with your password first")
    now = _now()
    usable = None
    with db() as conn:
        ch = conn.execute(
            """SELECT c.*, u.username FROM webauthn_challenges c
               JOIN users u ON u.id = c.user_id WHERE c.id = ?""",
            (pending,),
        ).fetchone()
        if ch is not None and not ch["used"]:
            conn.execute("UPDATE webauthn_challenges SET used = 1 WHERE id = ?", (pending,))
            if ch["kind"] == kind and datetime.fromisoformat(ch["expires_at"]) >= now:
                usable = dict(ch)
    if usable is None:
        raise HTTPException(status_code=401, detail="Login expired, already used, or wrong step. Start again.")
    return usable


def _log_in(response: Response, user_id: int, username: str) -> dict:
    response.delete_cookie(PENDING_COOKIE, path="/api/level5")
    set_session_cookie(response, create_session(user_id), LEVEL)
    return {"username": username}


@router.post("/register/finish")
def register_finish(body: CredentialBody, response: Response,
                    pending: str | None = Cookie(default=None)):
    """Store the new public key. Only reachable with a 'register' challenge."""
    ch = _take_challenge(pending, "register")
    try:
        verified = verify_registration_response(
            credential=body.credential,
            expected_challenge=base64url_to_bytes(ch["challenge"]),
            expected_rp_id=rp_id(),
            expected_origin=expected_origins(),
        )
    except (WebAuthnException, ValueError, KeyError, TypeError):
        # Say nothing about why: details only help an attacker.
        raise HTTPException(status_code=401, detail="Registration failed")
    with db() as conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO webauthn_credentials
               (credential_id, user_id, public_key, sign_count) VALUES (?, ?, ?, ?)""",
            (bytes_to_base64url(verified.credential_id), ch["user_id"],
             bytes_to_base64url(verified.credential_public_key), verified.sign_count),
        )
    if cur.rowcount == 0:
        raise HTTPException(status_code=409, detail="That security key is already registered")
    return _log_in(response, ch["user_id"], ch["username"])


@router.post("/authenticate/finish")
def authenticate_finish(body: CredentialBody, response: Response,
                        pending: str | None = Cookie(default=None)):
    """Check the signed challenge. Only reachable with an 'authenticate' challenge."""
    ch = _take_challenge(pending, "authenticate")
    cred_id = body.credential.get("id")
    with db() as conn:
        key = conn.execute(
            "SELECT public_key, sign_count FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?",
            (cred_id if isinstance(cred_id, str) else "", ch["user_id"]),
        ).fetchone()
    if key is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    try:
        verified = verify_authentication_response(
            credential=body.credential,
            expected_challenge=base64url_to_bytes(ch["challenge"]),
            expected_rp_id=rp_id(),
            expected_origin=expected_origins(),
            credential_public_key=base64url_to_bytes(key["public_key"]),
            credential_current_sign_count=key["sign_count"],
        )
    except (WebAuthnException, ValueError, KeyError, TypeError):
        raise HTTPException(status_code=401, detail="Authentication failed")
    with db() as conn:
        conn.execute(
            "UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?",
            (verified.new_sign_count, cred_id),
        )
    return _log_in(response, ch["user_id"], ch["username"])


@router.get("/config")
def config():
    """Public: the pages use it to warn when they are opened from an origin the server rejects."""
    return {"rp_id": rp_id(), "origins": expected_origins()}


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
    response.delete_cookie(PENDING_COOKIE, path="/api/level5")
    return {"ok": True}
