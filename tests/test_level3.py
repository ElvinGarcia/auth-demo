import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from api.auth.level3 import MAX_ATTEMPTS, MAX_CODES, seed
from api.db import db
from api.main import app

L = "/api/level3"


@pytest.fixture(autouse=True)
def clean_mail():
    with db() as conn:
        conn.execute("DELETE FROM email_outbox")
        conn.execute("DELETE FROM mailbox_grants")
    seed()


def login(client, username="dave", password="s3cret"):
    return client.post(f"{L}/login", json={"username": username, "password": password})


def latest_code(client):
    """Read the newest code from the mailboxes this client has open."""
    messages = client.get(f"{L}/mailbox").json()["messages"]
    return re.search(r"\b(\d{6})\b", messages[0]["body"]).group(1)


def verify(client, code):
    return client.post(f"{L}/verify", json={"code": code})


def full_login(client, username="dave", password="s3cret"):
    assert login(client, username, password).status_code == 200
    return verify(client, latest_code(client))


def test_password_alone_is_not_enough(client):
    r = login(client)
    assert r.status_code == 200 and r.json()["step"] == "code"
    assert client.get(f"{L}/me").status_code == 401


def test_password_plus_code_logs_in(client):
    assert full_login(client).status_code == 200
    assert client.get(f"{L}/me").json() == {"username": "dave", "level": 3}


def test_email_address_is_masked_in_the_response(client):
    hint = login(client).json()["email_hint"]
    assert hint.endswith("@demo.invalid") and "***" in hint


def test_wrong_password_sends_no_email(client):
    full_login(client)
    client.post(f"{L}/logout")
    before = len(client.get(f"{L}/mailbox").json()["messages"])
    assert login(client, password="wrong").status_code == 401
    assert len(client.get(f"{L}/mailbox").json()["messages"]) == before


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
        challenge_id = conn.execute("SELECT id FROM email_challenges").fetchone()[0]
    assert verify(client, code).status_code == 200
    other = TestClient(app)
    other.cookies.set("pending", challenge_id)
    assert verify(other, code).status_code == 401
    assert other.get(f"{L}/me").status_code == 401


def test_code_expires(client):
    login(client)
    code = latest_code(client)
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with db() as conn:
        conn.execute("UPDATE email_challenges SET expires_at = ?", (past,))
    assert verify(client, code).status_code == 401


def test_attempt_limit_locks_the_code(client):
    login(client)
    real = latest_code(client)
    wrong = "000000" if real != "000000" else "000001"
    for _ in range(MAX_ATTEMPTS):
        assert verify(client, wrong).status_code == 401
    assert verify(client, real).status_code == 429


def test_new_code_invalidates_old_one(client):
    login(client)
    first_id = client.cookies.get("pending")
    login(client)
    with db() as conn:
        used = conn.execute("SELECT used FROM email_challenges WHERE id = ?", (first_id,)).fetchone()[0]
    assert used == 1
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
        stored = conn.execute("SELECT code_hash FROM email_challenges").fetchone()[0]
    assert code not in stored


def test_verify_needs_a_pending_login(client):
    assert verify(client, "123456").status_code == 401


def test_code_must_be_six_digits(client):
    login(client)
    assert verify(client, "12").status_code == 422
    assert verify(client, "abcdef").status_code == 422


def test_levels_do_not_share_sessions(client):
    full_login(client)
    assert client.get("/api/level2/me").status_code == 401


# --- the mailbox -----------------------------------------------------------------

def test_mailbox_is_private_to_the_browser(client):
    login(client)
    assert client.get(f"{L}/mailbox").json()["messages"]
    assert TestClient(app).get(f"{L}/mailbox").json()["messages"] == []


def test_mailbox_login_needs_the_right_password(client):
    assert client.post(f"{L}/mailbox/login", json={"username": "admin", "password": "nope"}).status_code == 401
    assert client.post(f"{L}/mailbox/login", json={"username": "ghost", "password": "x"}).status_code == 401
    ok = client.post(f"{L}/mailbox/login", json={"username": "admin", "password": "admin123"})
    assert ok.status_code == 200 and ok.json()["address"] == "admin@demo.invalid"


def test_any_number_of_browsers_can_open_one_mailbox(client):
    login(client, "admin", "admin123")
    a, b = TestClient(app), TestClient(app)
    for who in (a, b):
        who.post(f"{L}/mailbox/login", json={"username": "admin", "password": "admin123"})
        assert who.get(f"{L}/mailbox").json()["messages"]


# --- attacker view ---------------------------------------------------------------

def test_known_password_opens_the_mailbox_and_defeats_the_factor(client):
    attacker = client
    assert login(attacker, "admin", "admin123").status_code == 200
    assert attacker.get(f"{L}/mailbox").json()["messages"] == []  # code went to a mailbox we cannot read
    attacker.post(f"{L}/mailbox/login", json={"username": "admin", "password": "admin123"})
    assert verify(attacker, latest_code(attacker)).status_code == 200
    assert attacker.get(f"{L}/me").json()["username"] == "admin"


def test_without_the_password_the_mailbox_stays_closed(client):
    assert login(client, "admin", "admin123").status_code == 200
    assert client.get(f"{L}/mailbox").json() == {"addresses": [], "messages": []}


def test_targets_list_hides_other_visitors(client):
    login(client)
    names = {t["username"] for t in TestClient(app).get(f"{L}/attacker/targets").json()["targets"]}
    assert "dave" not in names and "admin" in names


def test_targets_show_which_mailboxes_you_have_open(client):
    client.post(f"{L}/mailbox/login", json={"username": "admin", "password": "admin123"})
    targets = {t["username"]: t for t in client.get(f"{L}/attacker/targets").json()["targets"]}
    assert targets["admin"]["mailbox_open"] is True
    assert targets["alice"]["mailbox_open"] is False


def test_attacker_view_can_be_switched_off(client, monkeypatch):
    monkeypatch.setenv("ATTACKER_VIEW", "0")
    assert client.get(f"{L}/attacker/targets").status_code == 404
