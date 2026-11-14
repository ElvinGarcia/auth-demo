from fastapi.testclient import TestClient

from api.auth.level1 import seed
from api.db import db
from api.main import app
from api.passwords import hash_password, verify_password

DUMP = "/api/level1/attacker/dump"


def login(client, username="dave", password="s3cret"):
    return client.post("/api/level1/login", json={"username": username, "password": password})


def stored(username):
    with db() as conn:
        return conn.execute(
            "SELECT password FROM users WHERE level = 1 AND username = ?", (username,)
        ).fetchone()["password"]


def test_first_login_creates_account(client):
    r = login(client)
    assert r.json() == {"username": "dave", "created": True}
    assert client.get("/api/level1/me").json() == {"username": "dave", "level": 1}


def test_wrong_password_rejected_and_right_one_accepted(client):
    login(client)
    assert login(client, password="wrong").status_code == 401
    assert login(client).json()["created"] is False


def test_password_is_not_stored_in_plaintext(client):
    login(client)
    value = stored("dave")
    assert "s3cret" not in value
    assert value.startswith("pbkdf2_sha256$")


def test_same_password_gives_different_hashes():
    assert hash_password("same") != hash_password("same")


def test_verify_password_roundtrip_and_garbage():
    h = hash_password("pw")
    assert verify_password("pw", h)
    assert not verify_password("other", h)
    assert not verify_password("pw", "not-a-hash")


def test_stolen_hash_is_not_a_password(client):
    """Replaying the stored value as the password does not log you in."""
    seed()
    assert login(client, "admin", stored("admin")).status_code == 401
    assert login(client, "admin", "admin123").status_code == 200


def test_levels_are_separate_accounts(client):
    login(client)
    r = client.post("/api/level0/login", json={"username": "dave", "password": "other"})
    assert r.json()["created"] is True  # a different Level 0 account, not a clash


def test_dump_shows_hashes_never_passwords(client):
    seed()
    rows = client.get(DUMP).json()["rows"]
    assert {r["username"] for r in rows} >= {"admin", "alice", "bob", "carol"}
    assert all(r["stored"].startswith("pbkdf2_sha256$") for r in rows)
    assert "admin123" not in str(rows)


def test_dump_hides_other_visitors(client):
    seed()
    login(client)
    other = TestClient(app).get(DUMP).json()
    assert all(r["username"] != "dave" for r in other["rows"])
    assert other["hidden"] == 1


def test_no_rate_limit_online_guessing_still_works(client):
    seed()
    for i in range(30):
        assert login(client, "admin", f"guess{i}").status_code == 401
    assert login(client, "admin", "admin123").status_code == 200


def test_attacker_view_can_be_switched_off(client, monkeypatch):
    monkeypatch.setenv("ATTACKER_VIEW", "0")
    assert client.get(DUMP).status_code == 404
