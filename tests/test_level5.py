from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from api.auth.level5 import MAX_CHALLENGES, seed
from api.db import db
from api.main import app
from tests.softkey import SoftKey

L = "/api/level5"


@pytest.fixture(autouse=True)
def reseed():
    seed()


def login(client, username="dave", password="s3cret"):
    return client.post(f"{L}/login", json={"username": username, "password": password})


def register_finish(client, credential):
    return client.post(f"{L}/register/finish", json={"credential": credential})


def auth_finish(client, credential):
    return client.post(f"{L}/authenticate/finish", json={"credential": credential})


def enroll(client, key, username="dave", password="s3cret"):
    """Create an account, register `key` on it, and log out."""
    r = login(client, username, password).json()
    assert r["step"] == "register"
    assert register_finish(client, key.register(r["options"])).status_code == 200
    client.post(f"{L}/logout")


def stored_count(username):
    with db() as conn:
        return conn.execute(
            """SELECT c.sign_count FROM webauthn_credentials c JOIN users u ON u.id = c.user_id
               WHERE u.level = 5 AND u.username = ?""", (username,)).fetchone()[0]


# --- registration -----------------------------------------------------------------

def test_new_account_is_asked_to_register_a_key(client):
    r = login(client).json()
    assert r["step"] == "register" and r["created"] is True
    assert r["options"]["rp"]["id"] == "localhost" and r["options"]["challenge"]


def test_registering_a_key_logs_you_in_and_stores_only_the_public_key(client):
    key = SoftKey()
    r = login(client).json()
    assert register_finish(client, key.register(r["options"])).status_code == 200
    assert client.get(f"{L}/me").json() == {"username": "dave", "level": 5}
    with db() as conn:
        columns = [c[1] for c in conn.execute("PRAGMA table_info(webauthn_credentials)")]
        row = conn.execute("SELECT public_key FROM webauthn_credentials WHERE user_id = "
                           "(SELECT id FROM users WHERE level = 5 AND username = 'dave')").fetchone()
    assert row is not None
    assert columns == ["credential_id", "user_id", "public_key", "sign_count", "created_at"]  # no secret column


def test_registration_for_the_wrong_site_is_rejected(client):
    r = login(client).json()
    evil = SoftKey(rp_id="auth-demo.evil.example", origin="https://auth-demo.evil.example")
    assert register_finish(client, evil.register(r["options"])).status_code == 401
    assert client.get(f"{L}/me").status_code == 401


# --- authentication ---------------------------------------------------------------

def test_password_alone_is_not_enough(client):
    enroll(client, SoftKey())
    r = login(client).json()
    assert r["step"] == "authenticate" and r["options"]["allowCredentials"]
    assert client.get(f"{L}/me").status_code == 401


def test_password_plus_key_logs_in_and_the_counter_moves(client):
    key = SoftKey()
    enroll(client, key)
    r = login(client).json()
    assert auth_finish(client, key.authenticate(r["options"])).status_code == 200
    assert client.get(f"{L}/me").json()["username"] == "dave"
    assert stored_count("dave") == key.sign_count


def test_wrong_password_creates_no_challenge(client):
    enroll(client, SoftKey())
    assert login(client, password="wrong").status_code == 401
    assert client.post(f"{L}/authenticate/finish", json={"credential": {}}).status_code == 401


def test_phishing_relay_fails_because_the_browser_signs_the_real_origin(client):
    """The victim is on a look-alike site. Their browser signs THAT site's name, so the
    assertion the phisher forwards to the real server is rejected."""
    key = SoftKey()
    enroll(client, key)
    r = login(client).json()
    relayed = key.authenticate(r["options"], origin="https://auth-demo.evil.example")
    assert auth_finish(client, relayed).status_code == 401
    assert client.get(f"{L}/me").status_code == 401


def test_credential_for_another_site_does_not_work_here(client):
    key = SoftKey()
    enroll(client, key)
    r = login(client).json()
    key.rp_id = "evil.example"  # signs over a different RP ID hash
    assert auth_finish(client, key.authenticate(r["options"])).status_code == 401


def test_recorded_login_cannot_be_replayed(client):
    key = SoftKey()
    enroll(client, key)
    first = login(client).json()
    recorded = key.authenticate(first["options"])
    assert auth_finish(client, recorded).status_code == 200
    client.post(f"{L}/logout")
    login(client)  # attacker starts a new login with the known password: new challenge
    assert auth_finish(client, recorded).status_code == 401


def test_a_challenge_works_once(client):
    key = SoftKey()
    enroll(client, key)
    r = login(client).json()
    assertion = key.authenticate(r["options"])
    assert auth_finish(client, assertion).status_code == 200
    assert auth_finish(TestClient(app), assertion).status_code == 401


def test_a_failed_attempt_burns_the_challenge(client):
    key = SoftKey()
    enroll(client, key)
    r = login(client).json()
    assert auth_finish(client, key.authenticate(r["options"], origin="https://evil.example")).status_code == 401
    assert auth_finish(client, key.authenticate(r["options"])).status_code == 401  # even the right one


def test_signature_from_a_different_key_is_rejected(client):
    key = SoftKey()
    enroll(client, key)
    r = login(client).json()
    forged = key.authenticate(r["options"], signer=ec.generate_private_key(ec.SECP256R1()))
    assert auth_finish(client, forged).status_code == 401


def test_a_cloned_key_is_detected_by_the_counter(client):
    key = SoftKey()
    enroll(client, key)
    r = login(client).json()
    assert auth_finish(client, key.authenticate(r["options"], sign_count=10)).status_code == 200
    client.post(f"{L}/logout")
    r = login(client).json()
    assert auth_finish(client, key.authenticate(r["options"], sign_count=5)).status_code == 401


def test_challenge_expires(client):
    key = SoftKey()
    enroll(client, key)
    r = login(client).json()
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with db() as conn:
        conn.execute("UPDATE webauthn_challenges SET expires_at = ?", (past,))
    assert auth_finish(client, key.authenticate(r["options"])).status_code == 401


def test_finish_needs_a_pending_login(client):
    assert auth_finish(client, {"id": "x"}).status_code == 401
    assert register_finish(client, {"id": "x"}).status_code == 401


def test_malformed_credentials_are_rejected_cleanly(client):
    key = SoftKey()
    enroll(client, key)
    login(client)
    assert auth_finish(client, {"id": 123, "response": "nope"}).status_code == 401


def test_login_attempt_flood_is_limited(client):
    enroll(client, SoftKey())
    for _ in range(MAX_CHALLENGES - 1):  # enrollment used one already
        assert login(client).status_code == 200
    assert login(client).status_code == 429


def test_levels_do_not_share_sessions(client):
    enroll(client, SoftKey())
    login(client)
    assert client.get("/api/level4/me").status_code == 401


# --- attacker view ----------------------------------------------------------------

def test_known_password_cannot_enroll_an_attackers_key_on_a_seeded_account(client):
    r = login(client, "admin", "admin123").json()
    assert r["step"] == "authenticate"  # admin already has a key, so no enrollment is offered
    attacker = SoftKey()
    assert register_finish(client, attacker.register(r["options"])).status_code == 401
    assert client.get(f"{L}/me").status_code == 401


def test_a_leaked_credentials_table_is_useless(client):
    rows = client.get(f"{L}/attacker/dump").json()["rows"]
    admin = next(r for r in rows if r["username"] == "admin")
    assert admin["public_key"] and "private" not in str(admin).lower()
    r = login(client, "admin", "admin123").json()
    forged = SoftKey()
    cred = forged.authenticate(r["options"])
    cred["id"] = cred["rawId"] = admin["credential_id"]  # claim to be admin's key
    cred["response"]["signature"] = admin["public_key"]  # "sign" with the leaked value
    assert auth_finish(client, cred).status_code == 401


def test_dump_shows_seeded_accounts(client):
    rows = client.get(f"{L}/attacker/dump").json()["rows"]
    assert {r["username"] for r in rows} == {"admin", "alice", "bob", "carol"}


def test_dump_hides_other_visitors_and_shows_your_own(client):
    key = SoftKey()
    r = login(client).json()
    register_finish(client, key.register(r["options"]))
    mine = client.get(f"{L}/attacker/dump").json()
    assert any(row["username"] == "dave" for row in mine["rows"])
    stranger = TestClient(app).get(f"{L}/attacker/dump").json()
    assert all(row["username"] != "dave" for row in stranger["rows"])
    assert stranger["hidden"] == 1


def test_attacker_view_can_be_switched_off(client, monkeypatch):
    monkeypatch.setenv("ATTACKER_VIEW", "0")
    assert client.get(f"{L}/attacker/dump").status_code == 404


def test_config_tells_the_page_what_origin_to_expect(client):
    cfg = client.get(f"{L}/config").json()
    assert cfg == {"rp_id": "localhost", "origins": ["http://localhost:8000"]}
