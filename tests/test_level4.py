from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from fastapi.testclient import TestClient

from api.auth import level4
from api.auth.level4 import MAX_ATTEMPTS, MAX_CHALLENGES, seed
from api.db import db
from api.main import app

L = "/api/level4"


@pytest.fixture(autouse=True)
def reseed():
    seed()


def login(client, username="dave", password="s3cret"):
    return client.post(f"{L}/login", json={"username": username, "password": password})


def verify(client, code):
    return client.post(f"{L}/verify", json={"code": code})


def secret_of(username):
    with db() as conn:
        return conn.execute(
            """SELECT t.secret FROM totp_secrets t JOIN users u ON u.id = t.user_id
               WHERE u.level = 4 AND u.username = ?""", (username,)
        ).fetchone()[0]


def code_for(username, offset_steps=0):
    totp = pyotp.TOTP(secret_of(username))
    return totp.at(int(datetime.now(timezone.utc).timestamp()) + offset_steps * 30)


def enroll(client, username="dave", password="s3cret"):
    """Create an account and confirm its authenticator, then log out."""
    assert login(client, username, password).json()["step"] == "enroll"
    assert verify(client, code_for(username)).status_code == 200
    client.post(f"{L}/logout")


def shift_clock(monkeypatch, seconds):
    real = level4._now
    monkeypatch.setattr(level4, "_now", lambda: real() + timedelta(seconds=seconds))


# --- enrollment -------------------------------------------------------------------

def test_new_account_gets_a_qr_code_and_secret(client):
    r = login(client).json()
    assert r["step"] == "enroll" and r["created"] is True
    e = r["enroll"]
    assert e["qr"].startswith("data:image/svg+xml;base64,")
    assert e["uri"].startswith("otpauth://totp/") and e["secret"] in e["uri"]


def test_enrollment_is_confirmed_by_the_first_code(client):
    login(client)
    assert client.get(f"{L}/me").status_code == 401  # not logged in until a code is proven
    assert verify(client, code_for("dave")).status_code == 200
    assert client.get(f"{L}/me").json() == {"username": "dave", "level": 4}
    with db() as conn:
        assert conn.execute("SELECT confirmed FROM totp_secrets t JOIN users u ON u.id=t.user_id "
                            "WHERE u.username='dave' AND u.level=4").fetchone()[0] == 1


def test_secret_is_never_shown_again_after_enrollment(client):
    enroll(client)
    r = login(client).json()
    assert r["step"] == "code" and "enroll" not in r


# --- the second factor ------------------------------------------------------------

def test_password_alone_is_not_enough(client):
    enroll(client)
    assert login(client).json()["step"] == "code"
    assert client.get(f"{L}/me").status_code == 401


def test_password_plus_code_logs_in(client):
    enroll(client)
    login(client)
    # The enrollment code was already used in this step, so use the next step's code.
    assert verify(client, code_for("dave", 1)).status_code == 200


def test_wrong_password_creates_no_login_attempt(client):
    enroll(client)
    assert login(client, password="wrong").status_code == 401
    assert verify(client, code_for("dave", 1)).status_code == 401  # nothing pending


def test_wrong_code_rejected(client):
    enroll(client)
    login(client)
    real = code_for("dave", 1)
    wrong = "000000" if real != "000000" else "000001"
    assert verify(client, wrong).status_code == 401


def test_code_cannot_be_replayed(client):
    """The same code works once: a captured code is useless after the user spends it."""
    enroll(client)
    login(client)
    code = code_for("dave", 1)
    assert verify(client, code).status_code == 200
    client.post(f"{L}/logout")
    login(client)
    assert verify(client, code).status_code == 401


def test_one_step_of_clock_drift_is_tolerated(client):
    enroll(client)
    login(client)
    assert verify(client, code_for("dave", 1)).status_code == 200  # a code from the next step
    client.post(f"{L}/logout")


def test_old_codes_are_rejected(client, monkeypatch):
    enroll(client)
    login(client)
    stale = code_for("dave", -5)  # five steps (150 s) in the past
    assert verify(client, stale).status_code == 401


def test_attempt_limit_locks_the_login(client):
    enroll(client)
    login(client)
    wrong = "000000" if code_for("dave", 1) != "000000" else "000001"
    for _ in range(MAX_ATTEMPTS):
        assert verify(client, wrong).status_code == 401
    assert verify(client, code_for("dave", 1)).status_code == 429  # even the right code


def test_pending_login_expires(client):
    enroll(client)
    login(client)
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with db() as conn:
        conn.execute("UPDATE totp_challenges SET expires_at = ?", (past,))
    assert verify(client, code_for("dave", 1)).status_code == 401


def test_login_attempt_flood_is_limited(client):
    enroll(client)
    for _ in range(MAX_CHALLENGES - 1):  # enrollment used one already
        assert login(client).status_code == 200
    assert login(client).status_code == 429


def test_verify_needs_a_pending_login(client):
    assert verify(client, "123456").status_code == 401


def test_code_must_be_six_digits(client):
    login(client)
    assert verify(client, "12").status_code == 422
    assert verify(client, "abcdef").status_code == 422


def test_levels_do_not_share_sessions(client):
    login(client)
    verify(client, code_for("dave"))
    assert client.get("/api/level3/me").status_code == 401


# --- attacker view ----------------------------------------------------------------

def test_known_password_alone_gets_an_attacker_nowhere(client):
    """Unlike SMS and email, there is nothing to intercept: no code is ever sent."""
    assert login(client, "admin", "admin123").json()["step"] == "code"
    for _ in range(MAX_ATTEMPTS):
        assert verify(client, "000000").status_code in (401,)
    assert client.get(f"{L}/me").status_code == 401


def test_a_leaked_secret_defeats_the_factor(client):
    """The real weakness: the server keeps the secret, so a database leak hands it over."""
    leaked = {r["username"]: r["secret"] for r in client.get(f"{L}/attacker/dump").json()["rows"]}
    assert login(client, "admin", "admin123").json()["step"] == "code"
    assert verify(client, pyotp.TOTP(leaked["admin"]).now()).status_code == 200
    assert client.get(f"{L}/me").json()["username"] == "admin"


def test_dump_shows_seeded_accounts(client):
    rows = client.get(f"{L}/attacker/dump").json()["rows"]
    assert {r["username"] for r in rows} == {"admin", "alice", "bob", "carol"}


def test_dump_hides_other_visitors(client):
    login(client)
    stranger = TestClient(app).get(f"{L}/attacker/dump").json()
    assert all(r["username"] != "dave" for r in stranger["rows"])
    assert stranger["hidden"] == 1


def test_dump_shows_your_own_secret(client):
    login(client)
    verify(client, code_for("dave"))
    rows = client.get(f"{L}/attacker/dump").json()["rows"]
    assert any(r["username"] == "dave" and r["secret"] == secret_of("dave") for r in rows)


def test_attacker_view_can_be_switched_off(client, monkeypatch):
    monkeypatch.setenv("ATTACKER_VIEW", "0")
    assert client.get(f"{L}/attacker/dump").status_code == 404
