"""db.py: first start and connections."""
import sqlite3

import pytest

from conftest import app_package, audit_events, connect, login


# monkeypatch is from pytest to temporarily change the env variable, without affecting other tests.
def test_first_start_creates_schema_and_admin(tmp_path, monkeypatch, capsys):
    # This tests avoids using the app and db fixtures, to check the printed temporary password.
    monkeypatch.setenv("ASMA_DATA_DIR", str(tmp_path))
    app = app_package.create_app()
    temporary_password = capsys.readouterr().out.split("temporary password:")[1].split()[0]

    db = connect(app)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    admin = db.execute("SELECT * FROM users").fetchone()
    assert (admin["username"], admin["role"], admin["must_change_password"]) == \
        ("admin", "operator", 1)
    assert audit_events(db, "user.bootstrap")[0]["actor_type"] == "system"
    db.close()

    # The printed password works and leads to the forced password change.
    client = app.test_client()
    login(client, "admin", temporary_password)
    assert client.get("/targets").headers["Location"] == "/password"


def test_restart_keeps_existing_database(app, capsys):
    capsys.readouterr()
    app_package.create_app()  # same ASMA_DATA_DIR as the app fixture
    assert "temporary password" not in capsys.readouterr().out
    db = connect(app)
    assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 1
    db.close()


def test_application_connections_enforce_foreign_keys(app):
    with app.app_context():
        with pytest.raises(sqlite3.IntegrityError):
            app_package.db.get_db().execute(
                "INSERT INTO targets (kind, value, label, created_by_user_id, created_at, "
                "updated_at) VALUES ('domain', 'example.com', 'x', 999, '', '')")
