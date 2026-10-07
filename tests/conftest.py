import os
import tempfile
from pathlib import Path

# Must be set before the app is imported so tests never touch demo.db
os.environ["AUTH_DEMO_DB"] = str(Path(tempfile.mkdtemp()) / "test.db")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.db import db, init_db  # noqa: E402
from api.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean_db():
    init_db()
    with db() as conn:
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM users")
    yield


@pytest.fixture
def client():
    return TestClient(app)