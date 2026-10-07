import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).parent.parent
DB_PATH = Path(os.environ.get("AUTH_DEMO_DB", ROOT / "demo.db"))
SCHEMA_PATH = ROOT / "schema.sql"


@contextmanager
def db():
    """Open a connection, commit on success, roll back on error, always close."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA_PATH.read_text())