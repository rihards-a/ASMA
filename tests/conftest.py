"""Shared fixtures and helpers for the test suite.

Every test gets a fresh application with its own database in a temporary
directory. Test users are inserted directly with one known password, so the
tests do not depend on the temporary password printed at first start.

Run from the project folder:  python -m pytest tests / uv run --with pytest python -m pytest tests
"""
import hashlib
import importlib
import sqlite3
import sys
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

# The application package is the folder that contains tests/. It is imported
# by its folder name, so the tests work wherever the project is checked out.
PACKAGE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PACKAGE_DIR.parent))
app_package = importlib.import_module(PACKAGE_DIR.name)
# Lloaded here for the tests that use it directly.
validation = importlib.import_module(PACKAGE_DIR.name + ".validation")
scanners = importlib.import_module(PACKAGE_DIR.name + ".scanners")
adapters = importlib.import_module(PACKAGE_DIR.name + ".adapters")

PASSWORD = "correct horse battery"
# Hashing is deliberately slow, so the shared password is hashed only once.
PASSWORD_HASH = generate_password_hash(PASSWORD)
# Before any test run. Sessions compare password_changed_at to the second, so
# a password change during a test must not land on the stored value.
LONG_AGO = "2026-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Fixtures (reusable setup code for tests)
# ---------------------------------------------------------------------------

# tmp_path is a temporary directory created by pytest. 
# monkeypatch is a pytest fixture that allows you to modify environment variables and other settings for the duration of a test.
@pytest.fixture
def app(tmp_path, monkeypatch):
    """Application on an empty data directory. The first-start operator
    "admin" (user_id 1) gets PASSWORD and needs no password change."""
    monkeypatch.setenv("ASMA_DATA_DIR", str(tmp_path))
    application = app_package.create_app()
    application.config["TESTING"] = True
    conn = connect(application)
    conn.execute("UPDATE users SET password_hash = ?, must_change_password = 0, "
                 "password_changed_at = ? WHERE username = 'admin'", (PASSWORD_HASH, LONG_AGO))
    conn.close()
    return application


@pytest.fixture
def db(app):
    """Direct connection to the test database, for preparing and checking data."""
    conn = connect(app)
    yield conn
    conn.close()


@pytest.fixture
def client(app):
    """Browser-like client, not signed in."""
    return app.test_client()


@pytest.fixture
def operator(app):
    """Client signed in as the operator "admin"."""
    c = app.test_client()
    login(c, "admin")
    return c


@pytest.fixture
def viewer(app, db):
    """Client signed in as the viewer "victor" (user_id 2)."""
    add_user(db, "victor", "viewer")
    c = app.test_client()
    login(c, "victor")
    return c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def connect(app):
    # no need for isolation because tests run in a single thread and commit after every change
    conn = sqlite3.connect(app.config["DATABASE"], isolation_level=None)
    conn.row_factory = sqlite3.Row # access column by name
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def add_user(db, username, role="viewer", active=1, must_change=0):
    """Insert a user with PASSWORD and return the user_id."""
    return db.execute(
        "INSERT INTO users (username, role, password_hash, must_change_password, is_active, "
        "password_changed_at, created_by_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
        (username, role, PASSWORD_HASH, must_change, active, LONG_AGO, LONG_AGO)).lastrowid


def add_api_key(db, user_id, prefix="n8n", read_only=0):
    """Insert an API key and return the full key string."""
    key = f"asm_{prefix}_" + "A" * 40 + str(user_id).zfill(3)  # 43-character secret
    db.execute("INSERT INTO api_keys (user_id, read_only, key_prefix, key_hash, created_at) "
               "VALUES (?, ?, ?, ?, ?)",
               (user_id, read_only, prefix, hashlib.sha256(key.encode()).hexdigest(), LONG_AGO))
    return key


def add_target(db, kind="domain", value="example.com", label="Example"):
    """Insert a target created by admin and return the target_id."""
    return db.execute(
        "INSERT INTO targets (kind, value, label, created_by_user_id, created_at, updated_at) "
        "VALUES (?, ?, ?, 1, ?, ?)", (kind, value, label, LONG_AGO, LONG_AGO)).lastrowid


def post(client, url, data=None, **kwargs):
    """POST a form with the session's CSRF token, as the browser would."""
    with client.session_transaction() as session:
        token = session.setdefault("csrf_token", "test-csrf-token")
    return client.post(url, data={"csrf_token": token, **(data or {})}, **kwargs)


def login(client, username, password=PASSWORD):
    return post(client, "/login", {"username": username, "password": password})


def audit_events(db, action):
    """Audit rows for one action, oldest first."""
    return db.execute("SELECT * FROM audit_events WHERE action = ? ORDER BY event_id",
                      (action,)).fetchall()
