"""users.py: user management (operators only)."""
from conftest import PASSWORD, add_user, audit_events, login, post


def create_user(client, username="bob", role="viewer", password="temporary secret"):
    return post(client, "/users", {"username": username, "role": role, "password": password},
                follow_redirects=True)


def edit_user(client, user_id, role, active=True, password=""):
    data = {"role": role, "password": password}
    if active:
        data["is_active"] = "on"
    return post(client, f"/users/{user_id}", data, follow_redirects=True)


def test_create_user(operator, db):
    create_user(operator, "Bob")
    user = db.execute("SELECT * FROM users WHERE username = 'Bob'").fetchone()
    assert (user["role"], user["must_change_password"], user["created_by_user_id"]) == \
        ("viewer", 1, 1)
    assert user["password_hash"].startswith("scrypt:")
    assert "temporary secret" not in audit_events(db, "user.create")[-1]["details"]


def test_create_user_rejects_bad_input(operator, db):
    create_user(operator, "bob")
    assert b"already exists" in create_user(operator, "BOB").data  # other letter case
    assert b"Username must be" in create_user(operator, username="b").data
    assert b"Choose a role" in create_user(operator, role="admin").data
    assert b"12 to 128 characters" in create_user(operator, password="short").data
    assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 2


def test_edit_role_and_deactivate(operator, db):
    user_id = add_user(db, "bob")
    edit_user(operator, user_id, "operator", active=False)
    user = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    assert (user["role"], user["is_active"]) == ("operator", 0)
    assert '"role": ["viewer", "operator"]' in audit_events(db, "user.edit")[-1]["details"]


def test_cannot_demote_or_deactivate_self(operator, db):
    assert b"cannot deactivate your own" in edit_user(operator, 1, "viewer").data
    assert b"cannot deactivate your own" in edit_user(operator, 1, "operator", active=False).data
    admin = db.execute("SELECT role, is_active FROM users WHERE user_id = 1").fetchone()
    assert tuple(admin) == ("operator", 1)


def test_new_temporary_password_signs_user_out(app, operator, db):
    user_id = add_user(db, "bob")
    bob = app.test_client()
    login(bob, "bob")
    edit_user(operator, user_id, "viewer", password="fresh temporary pw")
    assert bob.get("/targets").headers["Location"] == "/login"
    assert login(bob, "bob", PASSWORD).status_code == 401
    login(bob, "bob", "fresh temporary pw")
    assert bob.get("/targets").headers["Location"] == "/password"
