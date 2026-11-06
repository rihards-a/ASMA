"""Jobs: one run of one scanner on one target.

A job starts queued, runs in a background thread and ends completed, failed
or cancelled. Every scanner has its own queue with one worker thread, so jobs
of one scanner run one after another (the external APIs have rate limits and
quotas) while different scanners run side by side. The queues live in
memory: jobs still queued or running when the application stops are marked
interrupted at the next start.

The same functions serve the web pages (blueprint "jobs") and the REST API
(blueprint "jobs_api").
"""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
from flask import (Blueprint, abort, current_app, flash, g, jsonify, redirect, render_template,
                   request, send_from_directory, url_for)

from . import validation
from .apikeys import api_key_required
from .auth import login_required, operator_required
from .db import audit, connect, get_db, now
from .scanners import SCANNERS
from .scanners.common import Cancelled, ScanError, details_json

bp = Blueprint("jobs", __name__)
api = Blueprint("jobs_api", __name__, url_prefix="/api")

# The job with its target and the name of the user who started it.
JOB_SELECT = ("SELECT j.*, t.kind AS target_kind, t.value AS target_value, "
              "u.username AS created_by FROM jobs AS j "
              "JOIN targets AS t ON t.target_id = j.target_id "
              "LEFT JOIN users AS u ON u.user_id = j.created_by_user_id ")


def init_app(app):
    """Close jobs left over from the previous run and start the queues."""
    conn = connect(app.config["DATABASE"])
    try:
        conn.execute("UPDATE jobs SET status = 'interrupted', finished_at = ?, error = ? "
                     "WHERE status IN ('queued', 'running')",
                     (now(), "The application stopped before the job finished."))
        conn.commit()
    finally:
        conn.close()
    app.extensions["asma_queues"] = {name: ThreadPoolExecutor(1, thread_name_prefix=name)
                                     for name in SCANNERS}


# ---------------------------------------------------------------------------
# Shared logic
# ---------------------------------------------------------------------------

def get_job(job_id):
    row = get_db().execute(JOB_SELECT + "WHERE j.job_id = ?", (job_id,)).fetchone()
    return dict(row) if row else None


def list_jobs(target_id=None):
    """The newest 100 jobs, of one target when target_id is given."""
    where, args = ("WHERE j.target_id = ? ", (target_id,)) if target_id else ("", ())
    rows = get_db().execute(JOB_SELECT + where + "ORDER BY j.job_id DESC LIMIT 100", args)
    return [dict(r) for r in rows]


def get_findings(job_id):
    return get_db().execute("SELECT * FROM findings WHERE job_id = ? ORDER BY finding_key",
                            (job_id,)).fetchall()


def scanner_and_target(data):
    """The scanner name and the target row named in data, checked to fit each
    other. Shared by jobs and schedules. data: target_id, scanner."""
    name = data.get("scanner")
    if not isinstance(name, str) or name not in SCANNERS:
        raise validation.InputError("Scanner must be one of: " + ", ".join(SCANNERS) + ".")
    scanner = SCANNERS[name]
    try:
        target_id = int(data.get("target_id"))
    except (TypeError, ValueError):
        raise validation.InputError("Choose a target.") from None

    db = get_db()
    target = db.execute("SELECT * FROM targets WHERE target_id = ?", (target_id,)).fetchone()
    if target is None:
        raise validation.InputError("The target does not exist.")
    if target["kind"] != scanner.TARGET_KIND:
        raise validation.InputError(f"The {name} scanner only scans {scanner.TARGET_KIND} targets.")
    return name, target


def create_job(data):
    """Validate and queue a job; returns its ID. data: target_id, scanner."""
    name, target = scanner_and_target(data)
    if not target["enabled"]:
        raise validation.InputError("The target is disabled.")
    return queue_job(current_app._get_current_object(), # current Flask app instance - to pass to the new thread
                     get_db(), target, name, user_id=g.user["user_id"])


def queue_job(app, conn, target, name, user_id=None, schedule_id=None):
    """Insert a queued job and submit it to its scanner's queue; returns its ID.

    Started either by a user (user_id) or by a schedule (schedule_id). The
    caller has checked that the scanner fits the target. Anything the caller
    changed in conn's open transaction is committed together with the job.
    """
    scanner = SCANNERS[name]
    if not app.config[scanner.API_KEY]:
        raise validation.InputError(f"The {name} scanner has no API key; set ASMA_{scanner.API_KEY}.")
    # No scanner takes options yet, so all jobs have the same params.
    params = "{}"
    fingerprint = hashlib.sha256(params.encode()).hexdigest()
    if conn.execute("SELECT 1 FROM jobs WHERE target_id = ? AND scanner = ? AND params_fingerprint = ? "
                    "AND status IN ('queued', 'running')",
                    (target["target_id"], name, fingerprint)).fetchone():
        raise validation.InputError(f"A {name} scan of {target['value']} is already queued or "
                                    f"running with the same parameters.", 409)

    job_id = conn.execute(
        "INSERT INTO jobs (target_id, schedule_id, created_by_user_id, scanner, params, "
        "params_fingerprint, queued_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (target["target_id"], schedule_id, user_id, name, params, fingerprint, now())).lastrowid
    audit("job.create", details={"job_id": job_id, "scanner": name, "target_id": target["target_id"],
                                 "value": target["value"], "schedule_id": schedule_id}, conn=conn)
    conn.commit()
    # Submits the job to the Flasks's background queue, which runs it in a separate thread.
    app.extensions["asma_queues"][name].submit(
        run_job, # the function to run, followed by its arguments
        app,
        job_id
    )
    return job_id


def cancel_job(job):
    """Cancel a queued or running job. A running scan stops at its next checkpoint."""
    db = get_db()
    if not db.execute("UPDATE jobs SET status = 'cancelled', finished_at = ? WHERE job_id = ? "
                      "AND status IN ('queued', 'running')", (now(), job["job_id"])).rowcount:
        raise validation.InputError("Only queued or running jobs can be cancelled.", 409)
    audit("job.cancel", details={"job_id": job["job_id"], "scanner": job["scanner"],
                                 "value": job["target_value"]})
    db.commit()


# ---------------------------------------------------------------------------
# Runner (worker threads, outside any request)
# ---------------------------------------------------------------------------

def run_job(app, job_id):
    """Run one job and record the outcome.

    The job's database row decides whether a job that is no longer queued
    (cancelled, or its target deleted) is skipped, and results are stored 
    only while it is still running.
    """
    conn = connect(app.config["DATABASE"])
    try:
        job = conn.execute("SELECT j.scanner, t.value FROM jobs AS j JOIN targets AS t "
                           "ON t.target_id = j.target_id WHERE j.job_id = ?", (job_id,)).fetchone()
        started = job is not None and conn.execute(
            "UPDATE jobs SET status = 'running', started_at = ? WHERE job_id = ? "
            "AND status = 'queued'", (now(), job_id)).rowcount
        conn.commit()
        if not started: 
            return
        name = job["scanner"]
        scanner = SCANNERS[name]

        def checkpoint():
            row = conn.execute("SELECT status FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if row is None or row["status"] != "running":
                raise Cancelled

        try:
            findings, raw = scanner.run(job["value"], app.config[scanner.API_KEY], checkpoint)
            complete(app, conn, job_id, name, findings, raw)
        except Cancelled:
            return
        except Exception as exc:
            conn.rollback()
            if not isinstance(exc, (ScanError, httpx.HTTPError)):
                app.logger.exception("Job %s failed", job_id)
            conn.execute("UPDATE jobs SET status = 'failed', finished_at = ?, error = ? "
                         "WHERE job_id = ? AND status = 'running'",
                         (now(), error_text(name, exc)[:2000], job_id))
            conn.commit()
    except Exception:
        # Writing the outcome itself failed (e.g. database locked, disk full).
        # The thread ends, but the row keeps its last status (queued or running):
        # an operator can cancel it, otherwise the next start marks it interrupted.
        app.logger.exception("Job %s could not be recorded", job_id)
    finally:
        conn.close()


def complete(app, conn, job_id, name, findings, raw):
    """Store the findings and raw output and mark the job completed, in one
    transaction. Nothing is stored if the job was cancelled meanwhile."""
    scanner = SCANNERS[name]
    finished = now()
    # The file is written first, so a stored artifact row always has its file.
    rel_path = f"artifacts/{job_id}/{scanner.ARTIFACT}"
    path = Path(app.config["DATABASE"]).parent / rel_path
    if raw:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    if not conn.execute("UPDATE jobs SET status = 'completed', finished_at = ?, finding_count = ? "
                        "WHERE job_id = ? AND status = 'running'",
                        (finished, len(findings), job_id)).rowcount:
        conn.rollback()
        path.unlink(missing_ok=True)
        return
    conn.executemany("INSERT INTO findings (job_id, scanner, finding_key, details) "
                     "VALUES (?, ?, ?, ?)",
                     [(job_id, name, key, details_json(details))
                      for key, details in findings.items()])
    if raw:
        conn.execute("INSERT INTO artifacts (job_id, name, rel_path, media_type, size_bytes, "
                     "sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (job_id, scanner.ARTIFACT, rel_path, scanner.MEDIA_TYPE, len(raw),
                      hashlib.sha256(raw).hexdigest(), finished))
    conn.commit()


def error_text(name, exc):
    """The failure as shown to the user. The texts of httpx exceptions are not
    used: they can contain the request URL, and Shodan's URL carries the API key."""
    if isinstance(exc, ScanError):
        return str(exc)
    if isinstance(exc, httpx.HTTPStatusError):
        return (f"The {name} API answered HTTP {exc.response.status_code} "
                f"{exc.response.reason_phrase}.")
    if isinstance(exc, httpx.HTTPError):
        return f"The request to the {name} API failed ({type(exc).__name__})."
    return "Unexpected error; see the application log."


# ---------------------------------------------------------------------------
# Web pages
# ---------------------------------------------------------------------------

@bp.route("/jobs")
@login_required
def search():
    target_id = request.args.get("target_id", type=int)
    targets = get_db().execute("SELECT * FROM targets WHERE enabled = 1 "
                               "ORDER BY kind, value").fetchall()
    return render_template("jobs.html", jobs=list_jobs(target_id), target_id=target_id,
                           targets=targets, scanners=SCANNERS)


@bp.route("/jobs", methods=["POST"])
@operator_required
def create():
    try:
        job_id = create_job(request.form)
    except validation.InputError as exc:
        flash(exc.message, "error")
        return redirect(url_for("jobs.search"))
    flash("Job queued.", "ok")
    return redirect(url_for("jobs.view", job_id=job_id))


@bp.route("/jobs/<int:job_id>")
@login_required
def view(job_id):
    job = get_job(job_id) or abort(404)
    artifacts = get_db().execute("SELECT * FROM artifacts WHERE job_id = ? ORDER BY name",
                                 (job_id,)).fetchall()
    return render_template("job.html", job=job, findings=get_findings(job_id),
                           artifacts=artifacts)


@bp.route("/jobs/<int:job_id>/cancel", methods=["POST"])
@operator_required
def cancel(job_id):
    job = get_job(job_id) or abort(404)
    try:
        cancel_job(job)
    except validation.InputError as exc:
        flash(exc.message, "error")
    else:
        flash("Job cancelled.", "ok")
    return redirect(url_for("jobs.view", job_id=job_id))


@bp.route("/jobs/<int:job_id>/artifacts/<int:artifact_id>")
@login_required
def download(job_id, artifact_id):
    db = get_db()
    artifact = db.execute("SELECT * FROM artifacts WHERE artifact_id = ? AND job_id = ?",
                          (artifact_id, job_id)).fetchone() or abort(404)
    audit("artifact.download", details={"job_id": job_id, "artifact_id": artifact_id,
                                        "name": artifact["name"]})
    db.commit()
    # send_from_directory refuses paths that leave the data directory.
    return send_from_directory(Path(current_app.config["DATABASE"]).parent, artifact["rel_path"],
                               mimetype=artifact["media_type"], as_attachment=True,
                               download_name=f"job-{job_id}-{artifact['name']}")


# ---------------------------------------------------------------------------
# REST API (JSON, X-API-Key)
# ---------------------------------------------------------------------------

def job_json(job):
    """A job as the API returns it: params as an object instead of text."""
    return {**job, "params": json.loads(job["params"])}


@api.route("/jobs")
@api_key_required()
def api_search():
    return jsonify([job_json(j) for j in list_jobs(request.args.get("target_id", type=int))])


@api.route("/jobs", methods=["POST"])
@api_key_required(write=True)
def api_create():
    job_id = create_job(validation.json_object(request.get_json(silent=True)))
    return jsonify(job_json(get_job(job_id))), 201


@api.route("/jobs/<int:job_id>")
@api_key_required()
def api_view(job_id):
    """The job with its findings (details as objects)."""
    job = get_job(job_id) or abort(404, "Job not found.")
    findings = [{"finding_key": f["finding_key"], "details": json.loads(f["details"])}
                for f in get_findings(job_id)]
    return jsonify({**job_json(job), "findings": findings})


@api.route("/jobs/<int:job_id>/cancel", methods=["POST"])
@api_key_required(write=True)
def api_cancel(job_id):
    cancel_job(get_job(job_id) or abort(404, "Job not found."))
    return jsonify(job_json(get_job(job_id)))
