"""apikeys.py: key management in the web interface and X-API-Key checks."""
import hashlib
import re

from conftest import add_api_key, add_user, audit_events, post

KEY = re.compile(rb"asm_[a-z0-9-]+_[A-Za-z0-9_-]{43}")


def create_key(client, prefix="n8n", description=""):
    return post(client, "/api-keys", {"prefix": prefix, "description": description},
                follow_redirects=True)


def api_get(client, key):
    return client.get("/api/targets", headers={"X-API-Key": key})


def test_key_shown_once_and_stored_as_hash(operator, db):
    key = KEY.search(create_key(operator, "N8N-Prod", "n8n workflows").data).group().decode()
    assert key.startswith("asm_n8n-prod_")
    row = db.execute("SELECT * FROM api_keys").fetchone()
    assert row["key_hash"] == hashlib.sha256(key.encode()).hexdigest()
    assert (row["key_prefix"], row["description"]) == ("n8n-prod", "n8n workflows")
    assert KEY.search(operator.get("/api-keys").data) is None  # not shown again
    assert key.split("_", 2)[2] not in audit_events(db, "apikey.create")[-1]["details"]


def test_prefix_reusable_only_after_revoke(operator):
    create_key(operator)
    assert b"already have an active key" in create_key(operator).data
    post(operator, "/api-keys/1/revoke")
    assert KEY.search(create_key(operator).data)


def test_viewer_key_is_read_only_and_private(viewer, db):
    add_api_key(db, user_id=1, prefix="adminkey")
    create_key(viewer, "reports")
    assert db.execute("SELECT read_only FROM api_keys WHERE key_prefix = 'reports'"
                      ).fetchone()[0] == 1
    assert b"adminkey" not in viewer.get("/api-keys").data
    post(viewer, "/api-keys/1/revoke")  # admin's key
    assert db.execute("SELECT revoked_at FROM api_keys WHERE api_key_id = 1").fetchone()[0] is None


def test_valid_key_is_accepted(client, db):
    assert api_get(client, add_api_key(db, user_id=1)).status_code == 200
    assert db.execute("SELECT last_used_at FROM api_keys").fetchone()[0] is not None


def test_invalid_keys_are_rejected(client, operator, db):
    key = add_api_key(db, user_id=1)
    inactive_owner_key = add_api_key(db, add_user(db, "n8n", "operator", active=0))
    revoked_key = add_api_key(db, user_id=1, prefix="old")
    db.execute("UPDATE api_keys SET revoked_at = '2026-01-02T00:00:00Z' WHERE key_prefix = 'old'")
    # We can set Z here, since we create the API key ending with the users's id which is a number.
    for presented in (None, "garbage", key[:-1] + "Z", inactive_owner_key, revoked_key):
        headers = {"X-API-Key": presented} if presented else {}
        assert client.get("/api/targets", headers=headers).status_code == 401
    # The session cookie is never accepted by the API.
    assert operator.get("/api/targets").status_code == 401
    # Every presented key is audited; a request without a key is not.
    assert len(audit_events(db, "auth.api_key")) == 4


def test_write_needs_operator_key_that_is_not_read_only(client, db):
    read_only = add_api_key(db, user_id=1, read_only=1)
    viewer_key = add_api_key(db, add_user(db, "victor"))
    for key in (read_only, viewer_key):
        response = client.post("/api/targets", headers={"X-API-Key": key},
                               json={"kind": "keyword", "value": "abc", "label": "x"})
        assert response.status_code == 403
    assert audit_events(db, "access.denied")[0]["actor_type"] == "api_key"
