"""auth.py: sign-in, sessions, CSRF, password change and access checks."""
from conftest import PASSWORD, add_user, audit_events, login, post


def change_password(client, current, new, confirm=None):
    return post(client, "/password", {"current": current, "new": new,
                                      "confirm": new if confirm is None else confirm},
                follow_redirects=True)


def test_login_success(client, db):
    assert login(client, "ADMIN").status_code == 302  # username is case-insensitive
    assert client.get("/targets").status_code == 200
    event = audit_events(db, "auth.login")[-1]
    assert (event["outcome"], event["actor_type"], event["user_id"]) == ("success", "user", 1)


def test_failed_logins_look_the_same(client, db):
    add_user(db, "gone", active=0)
    for username, password in (("admin", "wrong"), ("nobody", "wrong"), ("gone", PASSWORD)):
        response = login(client, username, password)
        assert response.status_code == 401
        assert b"Invalid username or password." in response.data
    # The audit log records the real reason, with the source IP.
    events = audit_events(db, "auth.login")
    assert [e["actor_type"] for e in events] == ["anonymous"] * 3
    for event, reason in zip(events, ("wrong_password", "unknown_user", "inactive")):
        assert reason in event["details"] and event["source_ip"]


def test_form_without_csrf_token_is_refused(client):
    response = client.post("/login", data={"username": "admin", "password": PASSWORD})
    assert response.status_code == 400


def test_anonymous_is_sent_to_login(client):
    for path in ("/", "/targets", "/users", "/api-keys", "/password"):
        assert client.get(path).headers["Location"] == "/login", path


def test_logout_and_deactivation_end_the_session(operator, viewer, db):
    post(operator, "/logout")
    assert operator.get("/targets").headers["Location"] == "/login"
    db.execute("UPDATE users SET is_active = 0 WHERE username = 'victor'")
    assert viewer.get("/targets").headers["Location"] == "/login"


def test_temporary_password_must_be_changed_first(client, db):
    add_user(db, "newbie", must_change=1)
    login(client, "newbie")
    assert client.get("/targets").headers["Location"] == "/password"
    change_password(client, PASSWORD, "a brand new secret")
    assert client.get("/targets").status_code == 200


def test_password_change_errors(operator):
    assert b"current password is incorrect" in change_password(operator, "wrong", "x" * 12).data
    assert b"do not match" in change_password(operator, PASSWORD, "x" * 12, "y" * 12).data
    assert b"12 to 128 characters" in change_password(operator, PASSWORD, "short").data
    assert b"must differ" in change_password(operator, PASSWORD, PASSWORD).data


def test_password_change_ends_other_sessions(app, operator):
    other = app.test_client()
    login(other, "admin")
    change_password(operator, PASSWORD, "another long secret")
    assert operator.get("/targets").status_code == 200
    assert other.get("/targets").headers["Location"] == "/login"


def test_viewer_is_refused_and_audited(viewer, db):
    assert viewer.get("/users").status_code == 403
    assert post(viewer, "/targets", {"kind": "keyword", "value": "abc",
                                     "label": "x"}).status_code == 403
    denied = audit_events(db, "access.denied")
    assert [(e["outcome"], e["actor_type"]) for e in denied] == [("denied", "user")] * 2
