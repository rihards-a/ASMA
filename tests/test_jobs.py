"""jobs.py: starting, running and cancelling jobs.

No real scan and no background thread is involved:
  - fake_scanner() replaces a scanner's run() with a function of the test, so
    nothing leaves the machine. What the real scanners send and parse is
    tested in test_scanners.py.
  - The queue fixture replaces the scanners' queues. A started job stays
    queued until the test calls queue.run(), which runs it to the end in the
    test's own thread, so there is nothing to wait for.
"""
import hashlib
from pathlib import Path

import httpx
import pytest

from conftest import adapters, add_api_key, add_target, app_package, audit_events, post, scanners


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

class Queue:
    """Stands in for the scanners' queues. Jobs are stored in a shared list here."""

    def __init__(self):
        self.waiting = []

    def submit(self, function, *args):
        # jobs.create_job() submits run_job(app, job_id).
        self.waiting.append((function, args))

    def run(self):
        """Run the waiting jobs, oldest first."""
        while self.waiting:
            function, args = self.waiting.pop(0)
            function(*args)


def no_network():
    raise AssertionError("A test reached for a real service; fake the scanner with fake_scanner().")


@pytest.fixture(autouse=True) # meaning it will automatically run for every test in this module
def queue(app, monkeypatch):
    """For every test: the fake queue, an API key for every scanner, and no
    HTTP client, so a scanner that was not faked fails its job."""
    app.config.update({module.API_KEY: "test-key" for module in adapters.SCANNERS.values()})
    monkeypatch.setattr(scanners, "client", no_network) # this only replaces the client in the scanners module, not conftest
    fake = Queue() # the queue is shared
    # Updates the app's extensions to use the fake queue for all scanners.
    app.extensions["asma_queues"] = dict.fromkeys(app.extensions["asma_queues"], fake)
    return fake


@pytest.fixture
def headers(db):
    """API key of the operator admin."""
    return {"X-API-Key": add_api_key(db, user_id=1)}


def fake_scanner(monkeypatch, name, run):
    """Jobs of scanner name call run(value, api_key, checkpoint) instead of the real scan."""
    monkeypatch.setattr(adapters.SCANNERS[name], "run", run)


def start(client, headers, target_id, scanner):
    """Start a job through the API."""
    return client.post("/api/jobs", headers=headers,
                       json={"target_id": target_id, "scanner": scanner})


def job_row(db, job_id=1):
    return db.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()


def count(db, table):
    return db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


# ---------------------------------------------------------------------------
# Starting jobs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("target_id, scanner, error", [
    (1, "unknown", "Scanner must be one of"),
    (1, ["hibs"], "Scanner must be one of"),     # not text
    ("x", "hibs", "Choose a target."),
    (999, "hibs", "The target does not exist."),
    (1, "hibs", "only scans domain targets"),    # target 1 is a keyword
    (2, "hibs", "The target is disabled."),
    (3, "shodan", "set ASMA_SHODAN_API_KEY"),    # the Shodan key is removed below
])
def test_start_rejects_bad_input(app, client, db, headers, target_id, scanner, error):
    add_target(db, "keyword", "example")             # target 1
    add_target(db, "domain", "example.com")          # target 2, disabled
    db.execute("UPDATE targets SET enabled = 0 WHERE target_id = 2")
    add_target(db, "network", "198.51.100.0/30")     # target 3
    app.config["SHODAN_API_KEY"] = None
    response = start(client, headers, target_id, scanner)
    assert response.status_code == 400 and error in response.json["error"]
    assert count(db, "jobs") == 0


def test_one_active_job_per_target_and_scanner(client, db, headers, queue, monkeypatch):
    fake_scanner(monkeypatch, "opensquat", lambda keyword, api_key, checkpoint: ({}, b"")) # doesn't do anything
    target_id = add_target(db, "keyword", "example")
    assert start(client, headers, target_id, "opensquat").status_code == 201
    response = start(client, headers, target_id, "opensquat")  # the first one is still queued
    assert response.status_code == 409 and "already queued or running" in response.json["error"]
    queue.run()
    assert start(client, headers, target_id, "opensquat").status_code == 201  # finished, so allowed


def test_viewers_cannot_start_or_cancel(viewer, db):
    target_id = add_target(db, "keyword", "example")
    assert post(viewer, "/jobs", {"target_id": target_id, "scanner": "opensquat"}).status_code == 403
    assert post(viewer, "/jobs/1/cancel").status_code == 403
    assert count(db, "jobs") == 0


# ---------------------------------------------------------------------------
# Cancelling and restarts
# ---------------------------------------------------------------------------

def test_cancel_queued_job(client, db, headers, queue, monkeypatch):
    fake_scanner(monkeypatch, "opensquat", lambda *args: pytest.fail("a cancelled job was run")) # fails if the job is run
    start(client, headers, add_target(db, "keyword", "example"), "opensquat")
    response = client.post("/api/jobs/1/cancel", headers=headers)
    assert response.status_code == 200 and response.json["status"] == "cancelled"
    queue.run()  # skips the job
    assert job_row(db)["started_at"] is None
    assert client.post("/api/jobs/1/cancel", headers=headers).status_code == 409  # already over
    assert audit_events(db, "job.cancel")


def test_cancel_running_job(app, client, db, headers, queue, monkeypatch):
    """The scan learns of the cancellation at its next checkpoint, and results
    returned after the cancellation are not stored."""
    def run(keyword, api_key, checkpoint):
        checkpoint()  # still running: passes
        client.post("/api/jobs/1/cancel", headers=headers)  # an operator cancels meanwhile
        with pytest.raises(scanners.Cancelled):
            checkpoint() # raises Cancelled, which the scanner adapter expects
        return {"examp1e.com": {}}, b"raw"  # as if the scan had finished anyway
    fake_scanner(monkeypatch, "opensquat", run)
    start(client, headers, add_target(db, "keyword", "example"), "opensquat")
    queue.run()
    assert job_row(db)["status"] == "cancelled"
    assert count(db, "findings") == count(db, "artifacts") == 0
    assert not (Path(app.config["DATABASE"]).parent / "artifacts/1/opensquat.json").exists()


def test_restart_interrupts_unfinished_jobs(client, db, headers):
    start(client, headers, add_target(db, "keyword", "example"), "opensquat")
    start(client, headers, add_target(db, "domain", "example.com"), "hibs")
    db.execute("UPDATE jobs SET status = 'running' WHERE job_id = 2")  # as if its scan had begun
    app_package.create_app()  # starts again on the same data directory
    rows = db.execute("SELECT status, finished_at, error FROM jobs").fetchall()
    assert [r["status"] for r in rows] == ["interrupted", "interrupted"]
    assert all(r["finished_at"] and r["error"] for r in rows)


# ---------------------------------------------------------------------------
# Web pages
# ---------------------------------------------------------------------------

def test_pages(operator, viewer, db, queue, monkeypatch):
    # Replace the scanner's run() with a fake that returns a result and raw data.
    fake_scanner(monkeypatch, "opensquat", lambda keyword, api_key, checkpoint: (
        {"examp1e.com": {}}, b'{"results": [{"domain": "examp1e.com"}]}'))
    target_id = add_target(db, "keyword", "example")
    response = post(operator, "/jobs", {"target_id": target_id, "scanner": "opensquat"})
    assert response.headers["Location"] == "/jobs/1"
    queue.run()

    assert b"examp1e.com" in viewer.get("/jobs/1").data
    assert b"completed" in viewer.get(f"/jobs?target_id={target_id}").data
    assert b"Start job" not in viewer.get("/jobs").data  # the form is for operators
    assert b"Start job" in operator.get("/jobs").data

    artifact_id = db.execute("SELECT artifact_id FROM artifacts").fetchone()[0]
    download = viewer.get(f"/jobs/1/artifacts/{artifact_id}")
    assert download.status_code == 200 and b"examp1e.com" in download.data
    assert "job-1-opensquat.json" in download.headers["Content-Disposition"]
    assert audit_events(db, "artifact.download")[0]["user_id"] == 2
    assert viewer.get("/jobs/1/artifacts/999").status_code == 404
