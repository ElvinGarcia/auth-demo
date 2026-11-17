import re
from http.cookies import SimpleCookie

import pyotp
import pytest

from api.sessions import get_user_by_session, session_cookie_name, session_cookie_path
from tests.softkey import SoftKey


def full_login(client, level):
    """Complete each real login flow using a fresh account at that level."""
    base = f"/api/level{level}"
    response = client.post(
        f"{base}/login", json={"username": "session-demo", "password": "fake-password"}
    )
    assert response.status_code == 200
    if level in (2, 3):
        inbox = "/inbox" if level == 2 else "/mailbox"
        messages = client.get(base + inbox).json()["messages"]
        code = re.search(r"\b(\d{6})\b", messages[0]["body"]).group(1)
        response = client.post(f"{base}/verify", json={"code": code})
    elif level == 4:
        code = pyotp.TOTP(response.json()["enroll"]["secret"]).now()
        response = client.post(f"{base}/verify", json={"code": code})
    elif level == 5:
        credential = SoftKey().register(response.json()["options"])
        response = client.post(f"{base}/register/finish", json={"credential": credential})
    assert response.status_code == 200
    return response


def test_all_levels_can_stay_logged_in_together(client):
    for level in range(6):
        response = full_login(client, level)
        cookie = SimpleCookie()
        header = next(
            header for header in response.headers.get_list("set-cookie")
            if header.startswith(session_cookie_name(level) + "=")
        )
        cookie.load(header)
        session = cookie[session_cookie_name(level)]
        assert session["path"] == session_cookie_path(level)
        assert session["httponly"]
        assert session["samesite"] == "lax"
        for logged_in in range(level + 1):
            assert client.get(f"/api/level{logged_in}/me").json() == {
                "username": "session-demo", "level": logged_in,
            }

    # Attacker views must still recognize each level's own account.
    for level, endpoint, key in (
        (0, "breach", "plaintext"), (1, "dump", "rows"),
        (2, "targets", "targets"), (3, "targets", "targets"),
        (4, "dump", "rows"), (5, "dump", "rows"),
    ):
        response = client.get(f"/api/level{level}/attacker/{endpoint}")
        assert response.status_code == 200
        assert any(row["username"] == "session-demo" for row in response.json()[key])


@pytest.mark.parametrize("logout_level", range(6))
def test_logout_only_revokes_its_own_level(client, logout_level):
    for level in range(6):
        full_login(client, level)
    token = client.cookies.get(session_cookie_name(logout_level))
    response = client.post(f"/api/level{logout_level}/logout")
    assert response.status_code == 200
    assert get_user_by_session(token) is None
    assert client.cookies.get(session_cookie_name(logout_level)) is None
    for level in range(6):
        expected = 401 if level == logout_level else 200
        assert client.get(f"/api/level{level}/me").status_code == expected


@pytest.mark.parametrize("level", range(6))
def test_foreign_token_cannot_authenticate_or_be_revoked(client, level):
    other_level = (level + 1) % 6
    full_login(client, other_level)
    foreign_token = client.cookies.get(session_cookie_name(other_level))
    client.cookies.set(
        session_cookie_name(level), foreign_token, path=session_cookie_path(level)
    )
    assert client.get(f"/api/level{level}/me").status_code == 401
    assert client.post(f"/api/level{level}/logout").status_code == 200
    assert get_user_by_session(foreign_token)["level"] == other_level
    assert client.get(f"/api/level{other_level}/me").status_code == 200


def test_logout_of_unused_level_keeps_existing_login(client):
    full_login(client, 0)
    assert client.post("/api/level1/logout").status_code == 200
    assert client.get("/api/level0/me").status_code == 200


def test_legacy_shared_cookie_is_ignored(client):
    full_login(client, 0)
    token = client.cookies.get(session_cookie_name(0))
    client.cookies.clear()
    client.cookies.set("session", token)
    assert client.get("/api/level0/me").status_code == 401
    assert client.post("/api/level1/logout").status_code == 200
    assert get_user_by_session(token)["level"] == 0
