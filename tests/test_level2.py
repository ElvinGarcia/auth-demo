import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from api.auth.level2 import MAX_ATTEMPTS, MAX_CODES, seed
from api.db import db
from api.main import app

L = "/api/level2"


@pytest.fixture(autouse=True)
def clean_sms():
    with db() as conn:
        conn.execute("DELETE FROM sms_outbox")
    seed()


def login(client, username="dave", password="s3cret"):
    return client.post(f"{L}/login", json={"username": username, "password": password})


def latest_code(client):
    """Read the newest code from this client's own simulated phone."""
    messages = client.get(f"{L}/inbox").json()["messages"]
    return re.search(r"\b(\d{6})\b", messages[0]["body"]).group(1)


def verify(client, code):
    return client.post(f"{L}/verify", json={"code": code})


def full_login(client, username="dave", password="s3cret"):
    assert login(client, username, password).status_code == 200
    return verify(client, latest_code(client))


def test_password_alone_is_not_enough(client):
    r = login(client)
    assert r.status_code == 200 and r.json()["step"] == "code"
    assert client.get(f"{L}/me").status_code == 401  # no session yet


def test_password_plus_code_logs_in(client):
    assert full_login(client).status_code == 200
    assert client.get(f"{L}/me").json() == {"username": "dave", "level": 2}


def test_wrong_password_sends_no_code(client):
    full_login(client)
    client.post(f"{L}/logout")
    before = len(client.get(f"{L}/inbox").json()["messages"])
    assert login(client, password="wrong").status_code == 401
    assert len(client.get(f"{L}/inbox").json()["messages"]) == before


def test_wrong_code_rejected(client):
    login(client)
    real = latest_code(client)
    wrong = "000000" if real != "000000" else "000001"
    assert verify(client, wrong).status_code == 401
    assert client.get(f"{L}/me").status_code == 401


def test_code_is_single_use(client):
    login(client)
    code = latest_code(client)
    with db() as conn:
        challenge_id = conn.execute("SELECT id FROM sms_challenges").fetchone()[0]
    assert verify(client, code).status_code == 200
    # Replay the same challenge and the same (correct) code from a different browser.
    other = TestClient(app)
    other.cookies.set("pending", challenge_id)
    assert verify(other, code).status_code == 401
    assert other.get(f"{L}/me").status_code == 401


def test_code_expires(client):
    login(client)
    code = latest_code(client)
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with db() as conn:
        conn.execute("UPDATE sms_challenges SET expires_at = ?", (past,))
    assert verify(client, code).status_code == 401


def test_attempt_limit_locks_the_code(client):
    login(client)
    real = latest_code(client)
    wrong = "000000" if real != "000000" else "000001"
    for _ in range(MAX_ATTEMPTS):
        assert verify(client, wrong).status_code == 401
    assert verify(client, real).status_code == 429  # even the right code is now refused


def test_new_code_invalidates_old_one(client):
    login(client)
    first_id = client.cookies.get("pending")
    login(client)  # asks for a second code
    with db() as conn:
        used = conn.execute("SELECT used FROM sms_challenges WHERE id = ?", (first_id,)).fetchone()[0]
    assert used == 1  # the first code can no longer be used
    assert verify(client, latest_code(client)).status_code == 200


def test_code_flood_is_limited(client):
    login(client)
    for _ in range(MAX_CODES - 1):
        assert login(client).status_code == 200
    assert login(client).status_code == 429


def test_code_is_not_stored_in_plaintext(client):
    login(client)
    code = latest_code(client)
    with db() as conn:
        stored = conn.execute("SELECT code_hash FROM sms_challenges").fetchone()[0]
    assert code not in stored


def test_verify_needs_a_pending_login(client):
    assert verify(client, "123456").status_code == 401


def test_code_must_be_six_digits(client):
    login(client)
    assert verify(client, "12").status_code == 422
    assert verify(client, "abcdef").status_code == 422


def test_inbox_is_private_to_the_phone(client):
    login(client)
    assert client.get(f"{L}/inbox").json()["messages"]
    stranger = TestClient(app)
    assert stranger.get(f"{L}/inbox").json()["messages"] == []


def test_levels_do_not_share_sessions(client):
    full_login(client)
    assert client.get("/api/level1/me").status_code == 401


# --- attacker view -------------------------------------------------------------

def test_sim_swap_redirects_the_code_to_the_attacker(client):
    attacker = client
    assert attacker.post(f"{L}/attacker/sim-swap", json={"username": "admin"}).status_code == 200
    assert login(attacker, "admin", "admin123").status_code == 200  # password already known
    assert full_login(attacker, "admin", "admin123").status_code == 200
    assert attacker.get(f"{L}/me").json()["username"] == "admin"


def test_without_the_swap_the_attacker_never_sees_the_code(client):
    assert login(client, "admin", "admin123").status_code == 200
    assert client.get(f"{L}/inbox").json()["messages"] == []


def test_cannot_swap_other_visitors(client):
    login(client)  # dave exists, owned by this browser
    stranger = TestClient(app)
    r = stranger.post(f"{L}/attacker/sim-swap", json={"username": "dave"})
    assert r.status_code == 403


def test_can_swap_your_own_account(client):
    full_login(client)
    r = client.post(f"{L}/attacker/sim-swap", json={"username": "dave"})
    assert r.status_code == 200


def test_targets_list_hides_other_visitors(client):
    login(client)
    stranger = TestClient(app)
    names = {t["username"] for t in stranger.get(f"{L}/attacker/targets").json()["targets"]}
    assert "dave" not in names and "admin" in names


def test_attacker_view_can_be_switched_off(client, monkeypatch):
    monkeypatch.setenv("ATTACKER_VIEW", "0")
    assert client.get(f"{L}/attacker/targets").status_code == 404
    assert client.post(f"{L}/attacker/sim-swap", json={"username": "admin"}).status_code == 404
