"""SQLite access: one connection per request, the schema created on first start,
and the audit log helper."""
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import current_app, g, has_request_context, request
from werkzeug.security import generate_password_hash

SCHEMA = Path(__file__).with_name("InitialSchema.sql")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def now() -> str:
    return datetime.now(timezone.utc).strftime(TIME_FORMAT)


def connect(path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # SQLite leaves foreign keys off unless every connection switches them on.
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db() -> sqlite3.Connection:
    """The current request's connection, opened on first use."""
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app(app):
    """Create the database on first start and close connections after requests."""
    if sqlite3.sqlite_version_info < (3, 38):
        # It may work, but optimizations and some built-in JSON functions are missing.
        raise RuntimeError(f"SQLite {sqlite3.sqlite_version} is too old; 3.38 or newer is needed")
    path = Path(app.config["DATABASE"])
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        if conn.execute("PRAGMA user_version").fetchone()[0] == 0:
            # One transaction: the schema is created completely or not at all.
            conn.executescript("BEGIN;\n" + SCHEMA.read_text(encoding="utf-8") + "\nCOMMIT;")
            create_first_operator(conn)
        # WAL lets readers work while a writer is busy (needed once scans run
        # in background threads). It is a property of the file, set once.
        conn.execute("PRAGMA journal_mode = WAL")
    finally:
        conn.close()
    # Cleanup function called at the end of an HTTP request (a context).
    app.teardown_appcontext(close_db)


def create_first_operator(conn):
    """Operator "admin" with a random temporary password, shown once."""
    password = secrets.token_urlsafe(12)
    created = now()
    conn.execute(
        "INSERT INTO users (username, role, password_hash, must_change_password, "
        "password_changed_at, created_at) VALUES ('admin', 'operator', ?, 1, ?, ?)",
        (generate_password_hash(password), created, created))
    audit("user.bootstrap", details={"username": "admin"}, conn=conn)
    conn.commit()
    print(f"\n  Created operator 'admin' with temporary password: {password}\n"
          f"  It must be changed at the first sign-in.\n", flush=True)


def audit(action, outcome="success", details=None, conn=None):
    """Write one audit event; the caller commits it together with its change.

    The actor is taken from the request: the API key, else the signed-in user,
    else anonymous. Outside a request (first start) the actor is the system.
    Details must never contain passwords or keys.
    """
    if has_request_context():
        ip = request.remote_addr
        # g has to be populated before audit() is called if the request is authenticated.
        key, user = g.get("api_key"), g.get("user")
        if key is not None:
            actor = ("api_key", key["user_id"], key["api_key_id"], ip)
        elif user is not None:
            actor = ("user", user["user_id"], None, ip)
        else:
            actor = ("anonymous", None, None, ip)
    else:
        actor = ("system", None, None, None)
    (conn or get_db()).execute(
        "INSERT INTO audit_events (occurred_at, actor_type, user_id, api_key_id, source_ip, "
        "action, outcome, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (now(), *actor, action, outcome, json.dumps(details or {})))
