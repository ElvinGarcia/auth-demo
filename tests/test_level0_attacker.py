from fastapi.testclient import TestClient

from api.auth.level0 import seed
from api.auth.level0_attacker import _hash
from api.main import app

BREACH = "/api/level0/attacker/breach"


def login(client, username="dave", password="s3cret"):
    return client.post("/api/level0/login", json={"username": username, "password": password})


def test_breach_shows_seeded_accounts_in_plaintext(client):
    seed()
    data = client.get(BREACH).json()
    assert {"username": "admin", "password": "admin123"} in data["plaintext"]


def test_breach_includes_your_own_account(client):
    seed()
    login(client)
    data = client.get(BREACH).json()
    assert {"username": "dave", "password": "s3cret"} in data["plaintext"]


def test_breach_hides_other_visitors(client):
    seed()
    login(client)  # dave logs in
    stranger = TestClient(app)  # a different visitor, no cookie
    data = stranger.get(BREACH).json()
    assert all(r["username"] != "dave" for r in data["plaintext"])
    assert data["hidden"] == 1


def test_hashed_view_never_contains_the_password(client):
    seed()
    data = client.get(BREACH).json()
    assert all(r["hash"].startswith("pbkdf2_sha256$") for r in data["hashed"])
    assert "admin123" not in str(data["hashed"])


def test_hashing_is_salted():
    assert _hash("same") != _hash("same")


def test_attacker_view_can_be_switched_off(client, monkeypatch):
    monkeypatch.setenv("ATTACKER_VIEW", "0")
    assert client.get(BREACH).status_code == 404