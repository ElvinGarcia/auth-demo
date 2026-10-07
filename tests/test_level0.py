from api.auth.level0 import seed
from api.db import db


def login(client, username="dave", password="s3cret"):
    return client.post("/api/level0/login", json={"username": username, "password": password})


def test_first_login_creates_account(client):
    r = login(client)
    assert r.status_code == 200
    assert r.json() == {"username": "dave", "created": True}
    assert client.get("/api/level0/me").json() == {"username": "dave", "level": 0}


def test_second_login_needs_same_password(client):
    login(client)
    assert login(client).json()["created"] is False
    assert login(client, password="wrong").status_code == 401


def test_me_requires_login(client):
    assert client.get("/api/level0/me").status_code == 401


def test_logout_invalidates_session_server_side(client):
    login(client)
    token = client.cookies.get("session")
    client.post("/api/level0/logout")
    client.cookies.set("session", token)  # replay the old cookie
    assert client.get("/api/level0/me").status_code == 401


def test_password_is_stored_in_plaintext(client):
    """The lesson of Level 0: anyone who reads the database reads the passwords."""
    login(client)
    with db() as conn:
        row = conn.execute("SELECT password FROM users WHERE username = 'dave'").fetchone()
    assert row["password"] == "s3cret"


def test_seed_accounts_exist_and_are_weak(client):
    seed()
    seed()  # idempotent
    assert login(client, "admin", "admin123").status_code == 200


def test_no_rate_limit(client):
    seed()
    for i in range(50):
        assert login(client, "admin", f"guess{i}").status_code == 401
    assert login(client, "admin", "admin123").status_code == 200  # never locked out