"""Schedules: run one scanner on one target on a cron timetable.

A background thread wakes at the start of every minute and queues a job for
each enabled schedule whose cron expression matches that minute. Cron times
are UTC, like every other time in the application. A schedule starts no job
while its target is disabled. A run is skipped when the scanner has no API key
or the previous job of the same series is still queued or running.

A schedule cannot be edited, only paused, resumed or deleted. Deleting only
marks it (deleted_at), so the jobs it started keep their origin.
"""
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone

from flask import (Blueprint, abort, current_app, flash, g, jsonify, redirect, render_template,
                   request, url_for)

from . import jobs, validation
from .apikeys import api_key_required
from .auth import login_required, operator_required
from .db import TIME_FORMAT, audit, connect, get_db, now
from .scanners import SCANNERS

bp = Blueprint("schedules", __name__)
api = Blueprint("schedules_api", __name__, url_prefix="/api")

# The schedule with its target and the name of the user who created it.
SCHEDULE_SELECT = ("SELECT s.*, t.kind AS target_kind, t.value AS target_value, "
                   "u.username AS created_by FROM schedules AS s "
                   "JOIN targets AS t ON t.target_id = s.target_id "
                   "JOIN users AS u ON u.user_id = s.created_by_user_id ")


# ---------------------------------------------------------------------------
# Cron expressions
# ---------------------------------------------------------------------------

# Allowed values of the five fields: minute, hour, day of month, month and
# day of week (0 is Sunday).
CRON_RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))
# One item of a field: * or n or n-m, optionally followed by /step.
CRON_ITEM = re.compile(r"(\*|[0-9]+(?:-[0-9]+)?)(?:/([0-9]+))?")
# This will then return at most 2 groups.
# Example: 10-20/3
# group(1) -> 10-20 # non capturing ?: group (-[0-9]+) got merged.
# group(2) -> 3     # non capturing ?: slash (/) got merged with nothing (deleted).
# must use with full_match() as it doesn't have anchors.


def parse_cron(expr):
    """The allowed values of each of the five fields, as sets; InputError if invalid."""
    fields = expr.split()
    if len(fields) != 5:
        raise validation.InputError("A cron expression has five fields: minute, hour, "
                                    "day of month, month and day of week.")
    return [parse_field(field, low, high) for field, (low, high) in zip(fields, CRON_RANGES)]


def parse_field(field, low, high):
    """Comma-separated items: *, n, n-m, */step or n-m/step."""
    error = validation.InputError(f"Invalid cron field \"{field}\": use *, n, n-m, */step or "
                                  f"n-m/step, separated by commas, with values {low} to {high}.")
    values = set() # Sets are chosen for the convenience of using the "in" operator.
    for item in field.split(","):
        match = CRON_ITEM.fullmatch(item)
        # A step on a single number is refused: cron reads "5/15" as 5-59/15, which is easy to misread.
        if not match or (match[2] and match[1] != "*" and "-" not in match[1]):
            raise error
        bounds = (low, high) if match[1] == "*" else [int(n) for n in match[1].split("-")]
        first, last, step = bounds[0], bounds[-1], int(match[2] or 1)
        if not low <= first <= last <= high or step < 1:
            raise error
        values.update(range(first, last + 1, step))
    return values


def cron_matches(expr, moment):
    """Whether the cron expression fires in the minute of moment (datetime)."""
    minute, hour, day, month, weekday = parse_cron(expr)
    day_match = moment.day in day
    weekday_match = moment.isoweekday() % 7 in weekday  # isoweekday: Monday 1 to Sunday 7
    # In cron when neither weekday or day starts with *, either of them is enough.
    fields = expr.split()
    if fields[2].startswith("*") or fields[4].startswith("*"):
        date_match = day_match and weekday_match
    else:
        date_match = day_match or weekday_match
    return moment.minute in minute and moment.hour in hour and moment.month in month and date_match


# ---------------------------------------------------------------------------
# Scheduler (background thread, outside any request)
# ---------------------------------------------------------------------------

def init_app(app):
    """Start the scheduler thread. As a daemon thread it ends with the application."""
    threading.Thread(target=run, args=(app,), name="scheduler", daemon=True).start()


def run(app):
    """Every minute, queue the jobs of the schedules due in that minute."""
    while True:
        time.sleep(60 - time.time() % 60)  # until the start of the next minute
        # returns the datetime object: YYYY-MM-DD HH:MM:00+00:00.
        minute = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        try:
            queue_due(app, minute)
        except Exception:
            # Unexpected error (a bug, or the database cannot be written).
            app.logger.exception("The scheduler failed at %s", minute.strftime(TIME_FORMAT))


def queue_due(app, minute):
    """Queue a job for every enabled schedule whose cron expression matches minute."""
    stamp = minute.strftime(TIME_FORMAT)
    conn = connect(app.config["DATABASE"])
    try:
        # enabled = 1 also excludes deleted schedules (the schema keeps them disabled).
        # last_run_at keeps one minute from being handled twice. Usually it shouldn't be
        # a problem, but it is possible that sleep goes faster than the clock by a few ms.
        due = [s for s in conn.execute(
            "SELECT s.*, t.value FROM schedules AS s JOIN targets AS t ON t.target_id = s.target_id "
            "WHERE s.enabled = 1 AND t.enabled = 1 AND (s.last_run_at IS NULL OR s.last_run_at < ?)",
            (stamp,)).fetchall() if cron_matches(s["cron"], minute)]
        for schedule in due:
            # Committed together with the job by queue_job.
            conn.execute("UPDATE schedules SET last_run_at = ? WHERE schedule_id = ?",
                         (stamp, schedule["schedule_id"]))
            try:
                # The row carries target_id and value, which is all queue_job needs of the target.
                jobs.queue_job(app, conn, schedule, schedule["scanner"],
                               schedule_id=schedule["schedule_id"])
            except (validation.InputError, sqlite3.IntegrityError) as exc:
                # No API key, or the series already has a queued or running job.
                conn.rollback()
                app.logger.warning("Schedule %s skipped at %s: %s",
                                   schedule["schedule_id"], stamp, exc)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Shared logic
# ---------------------------------------------------------------------------

def get_schedule(schedule_id):
    """A schedule that is not deleted, as a dict, or None."""
    row = get_db().execute(SCHEDULE_SELECT + "WHERE s.schedule_id = ? AND s.deleted_at IS NULL",
                           (schedule_id,)).fetchone()
    return dict(row) if row else None


def list_schedules():
    rows = get_db().execute(SCHEDULE_SELECT + "WHERE s.deleted_at IS NULL ORDER BY s.schedule_id")
    return [dict(r) for r in rows]


def create_schedule(data):
    """Validate and store a schedule; returns its ID. data: target_id, scanner, cron, enabled."""
    name, target = jobs.scanner_and_target(data)
    scanner = SCANNERS[name]
    if not current_app.config[scanner.API_KEY]:
        raise validation.InputError(f"The {name} scanner has no API key; set ASMA_{scanner.API_KEY}.")
    # Single spaces, so equal timetables are equal text for the duplicate check.
    cron = " ".join(validation.text(data.get("cron"), "Cron", 100).split())
    parse_cron(cron)
    enabled = validation.flag(data.get("enabled", True))

    db = get_db()
    if db.execute("SELECT 1 FROM schedules WHERE target_id = ? AND scanner = ? AND cron = ? "
                  "AND deleted_at IS NULL", (target["target_id"], name, cron)).fetchone():
        raise validation.InputError(f"A {name} schedule of {target['value']} with the cron "
                                    f"expression {cron} already exists.", 409)
    created = now()
    schedule_id = db.execute(
        "INSERT INTO schedules (target_id, scanner, cron, enabled, created_by_user_id, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (target["target_id"], name, cron, enabled, g.user["user_id"], created, created)).lastrowid
    audit("schedule.create", details={"schedule_id": schedule_id, "scanner": name,
                                      "target_id": target["target_id"], "value": target["value"],
                                      "cron": cron, "enabled": enabled})
    db.commit()
    return schedule_id


def set_enabled(schedule, value):
    """Pause (false) or resume (true) a schedule; returns whether it changed."""
    enabled = validation.flag(value)
    if enabled == schedule["enabled"]:
        return False
    db = get_db()
    db.execute("UPDATE schedules SET enabled = ?, updated_at = ? WHERE schedule_id = ?",
               (enabled, now(), schedule["schedule_id"]))
    audit("schedule.edit", details={"schedule_id": schedule["schedule_id"],
                                    "value": schedule["target_value"],
                                    "changes": {"enabled": [schedule["enabled"], enabled]}})
    db.commit()
    return True


def delete_schedule(schedule):
    """Mark the schedule deleted: it is hidden and starts no more jobs."""
    db = get_db()
    deleted = now()
    db.execute("UPDATE schedules SET enabled = 0, deleted_at = ?, updated_at = ? "
               "WHERE schedule_id = ?", (deleted, deleted, schedule["schedule_id"]))
    audit("schedule.delete", details={"schedule_id": schedule["schedule_id"],
                                      "scanner": schedule["scanner"],
                                      "value": schedule["target_value"]})
    db.commit()


# ---------------------------------------------------------------------------
# Web pages
# ---------------------------------------------------------------------------

@bp.route("/schedules")
@login_required
def search():
    targets = get_db().execute("SELECT * FROM targets ORDER BY kind, value").fetchall()
    return render_template("schedules.html", schedules=list_schedules(), targets=targets,
                           scanners=SCANNERS)


@bp.route("/schedules", methods=["POST"])
@operator_required
def create():
    data = {**request.form, "enabled": "enabled" in request.form}
    try:
        create_schedule(data)
    except validation.InputError as exc:
        flash(exc.message, "error")
    else:
        flash("Schedule created.", "ok")
    return redirect(url_for("schedules.search"))


@bp.route("/schedules/<int:schedule_id>", methods=["POST"])
@operator_required
def edit(schedule_id):
    """Pause or resume; the form sends "enabled" only to resume."""
    schedule = get_schedule(schedule_id) or abort(404)
    enabled = "enabled" in request.form
    set_enabled(schedule, enabled)
    flash("Schedule resumed." if enabled else "Schedule paused.", "ok")
    return redirect(url_for("schedules.search"))


@bp.route("/schedules/<int:schedule_id>/delete", methods=["POST"])
@operator_required
def delete(schedule_id):
    schedule = get_schedule(schedule_id) or abort(404)
    delete_schedule(schedule)
    flash("Schedule deleted.", "ok")
    return redirect(url_for("schedules.search"))


# ---------------------------------------------------------------------------
# REST API (JSON, X-API-Key)
# ---------------------------------------------------------------------------

@api.route("/schedules")
@api_key_required()
def api_search():
    return jsonify(list_schedules())


@api.route("/schedules", methods=["POST"])
@api_key_required(write=True)
def api_create():
    schedule_id = create_schedule(validation.json_object(request.get_json(silent=True)))
    return jsonify(get_schedule(schedule_id)), 201


@api.route("/schedules/<int:schedule_id>")
@api_key_required()
def api_view(schedule_id):
    schedule = get_schedule(schedule_id)
    return jsonify(get_schedule(schedule_id) or abort(404, "Schedule not found."))
 

@api.route("/schedules/<int:schedule_id>", methods=["PATCH"])
@api_key_required(write=True)
def api_edit(schedule_id):
    """Pause or resume: the body is {"enabled": true or false}."""
    schedule = get_schedule(schedule_id) or abort(404, "Schedule not found.")
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"enabled"}:
        raise validation.InputError("The body must be {\"enabled\": true or false}.")
    set_enabled(schedule, data["enabled"])
    return jsonify(get_schedule(schedule_id))


@api.route("/schedules/<int:schedule_id>", methods=["DELETE"])
@api_key_required(write=True)
def api_delete(schedule_id):
    delete_schedule(get_schedule(schedule_id) or abort(404, "Schedule not found."))
    return "", 204
