"""targets.py: target pages and the REST API."""
import pytest

from conftest import LONG_AGO, add_api_key, add_target, audit_events, post


def create(client, kind, value, keyword_ids=()):
    return post(client, "/targets", {"kind": kind, "value": value, "label": "Test",
                                     "enabled": "on", "keyword_ids": list(keyword_ids)},
                follow_redirects=True)


# ---------------------------------------------------------------------------
# Web pages
# ---------------------------------------------------------------------------

def test_create_normalizes_value(operator, viewer, db):
    create(operator, "domain", "Example.COM")
    create(operator, "network", "198.51.100.10-40")
    values = [r[0] for r in db.execute("SELECT value FROM targets ORDER BY target_id")]
    assert values == ["example.com", "198.51.100.10-198.51.100.40"]
    assert b"example.com" in viewer.get("/targets").data  # viewers can list
    assert viewer.get("/targets/1").status_code == 200    # and view


def test_create_rejects_bad_input(operator, db):
    create(operator, "keyword", "example")
    for kind, value, message in (("keyword", "EXAMPLE", b"already registered"),
                                 ("domain", "not a domain", b"Invalid domain name."),
                                 ("network", "127.0.0.1", b"reserved range"),
                                 ("planet", "mars", b"Kind must be")):
        assert message in create(operator, kind, value).data
    assert db.execute("SELECT count(*) FROM targets").fetchone()[0] == 1


def test_keywords_link_to_domains_only(operator, db):
    keyword_id = add_target(db, "keyword", "example")
    create(operator, "domain", "example.com", keyword_ids=[keyword_id])
    assert db.execute("SELECT count(*) FROM domain_keywords").fetchone()[0] == 1
    page = create(operator, "network", "203.0.113.0/30", keyword_ids=[keyword_id])
    assert b"Only domain targets can have keywords." in page.data


def test_edit(operator, db):
    target_id = add_target(db)
    # The enabled box is not ticked, so the target becomes disabled.
    post(operator, f"/targets/{target_id}", {"label": "Main site", "notes": "web team"})
    target = db.execute("SELECT * FROM targets").fetchone()
    assert (target["label"], target["notes"], target["enabled"]) == ("Main site", "web team", 0)
    assert audit_events(db, "target.edit")


def test_delete_removes_history(operator, db):
    target_id = add_target(db, "network", "203.0.113.0/30")
    db.execute("INSERT INTO jobs (target_id, created_by_user_id, scanner, params_fingerprint, "
               "status, queued_at, finished_at) VALUES (?, 1, 'nmap', ?, 'completed', ?, ?)",
               (target_id, "f" * 64, LONG_AGO, LONG_AGO))
    post(operator, f"/targets/{target_id}/delete")
    assert db.execute("SELECT count(*) FROM targets").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM jobs").fetchone()[0] == 0


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@pytest.fixture
def headers(db):
    return {"X-API-Key": add_api_key(db, user_id=1)}


def test_api_create_and_read(client, db, headers):
    assert client.get("/api/health").json == {"status": "ok"}  # no key needed
    response = client.post("/api/targets", headers=headers,
                           json={"kind": "domain", "value": "Company.EU", "label": "EU"})
    assert response.status_code == 201 and response.json["value"] == "company.eu"
    target_id = response.json["target_id"]
    assert client.get(f"/api/targets/{target_id}", headers=headers).json["label"] == "EU"
    assert len(client.get("/api/targets", headers=headers).json) == 1
    assert audit_events(db, "target.create")[-1]["actor_type"] == "api_key"


def test_api_errors(client, headers):
    body = {"kind": "domain", "value": "example.com", "label": "x"}
    client.post("/api/targets", headers=headers, json=body)
    assert client.post("/api/targets", headers=headers, json=body).status_code == 409
    assert client.post("/api/targets", headers=headers,
                       json={**body, "value": "-rf"}).status_code == 400 # ** is dictionary unpacking
    assert client.post("/api/targets", headers=headers, data="not json").status_code == 400
    assert client.get("/api/targets/999", headers=headers).status_code == 404


def test_api_patch_changes_only_given_fields(client, db, headers):
    target_id = add_target(db)
    response = client.patch(f"/api/targets/{target_id}", headers=headers,
                            json={"notes": "web team"})
    assert (response.json["notes"], response.json["label"]) == ("web team", "Example")
    response = client.patch(f"/api/targets/{target_id}", headers=headers,
                            json={"value": "example.org"})
    assert response.status_code == 400  # kind and value never change


def test_api_delete(client, db, headers):
    target_id = add_target(db)
    assert client.delete(f"/api/targets/{target_id}", headers=headers).status_code == 204
    assert client.delete(f"/api/targets/{target_id}", headers=headers).status_code == 404
