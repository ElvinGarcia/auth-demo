# this session script is shared by every level

import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Response

from api.db import db

SESSION_COOKIE = "session"
SESSION_TTL = timedelta(hours=8)
# Set COOKIE_SECURE=1 in production (HTTPS). Must be off for http://localhost.
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (_now() + SESSION_TTL).isoformat()
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, expires_at),
        )
    return token


def get_user_by_session(token: str | None) -> dict | None:
    if not token:
        return None
    with db() as conn:
        row = conn.execute(
            """SELECT u.id, u.level, u.username, s.expires_at
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token = ?""",
            (token,),
        ).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"]) < _now():
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            return None
        return {"id": row["id"], "level": row["level"], "username": row["username"]}


def delete_session(token: str | None) -> None:
    if token:
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        max_age=int(SESSION_TTL.total_seconds()),
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")