"""Targets: the domains, keywords and IPv4 networks the system may scan.

The same functions serve the web pages (blueprint "targets") and the REST API
(blueprint "api"). Kind and value never change after creation (the database
enforces it), because a target's scan history refers to them.
"""
from flask import (Blueprint, abort, current_app, flash, g, jsonify, redirect, render_template,
                   request, url_for)

from . import validation
from .apikeys import api_key_required
from .auth import login_required, operator_required
from .db import audit, get_db, now

bp = Blueprint("targets", __name__)
api = Blueprint("api", __name__, url_prefix="/api")

KINDS = ("domain", "keyword", "network")


# ---------------------------------------------------------------------------
# Shared logic
# ---------------------------------------------------------------------------

def get_target(target_id):
    """The target as a dict with its keyword links, or None."""
    row = get_db().execute("SELECT * FROM targets WHERE target_id = ?", (target_id,)).fetchone()
    if row is None:
        return None
    target = dict(row)
    # A domain lists its keywords; a keyword lists the domains it feeds.
    target["keyword_ids"] = [r[0] for r in get_db().execute(
        "SELECT keyword_target_id FROM domain_keywords WHERE domain_target_id = ?", (target_id,))]
    target["domain_ids"] = [r[0] for r in get_db().execute(
        "SELECT domain_target_id FROM domain_keywords WHERE keyword_target_id = ?", (target_id,))]
    return target


def clean_keyword_ids(values, kind):
    """IDs of existing keyword targets; only domains can have them."""
    if not values:
        return []
    if kind != "domain":
        raise validation.InputError("Only domain targets can have keywords.")
    try:
        ids = sorted({int(v) for v in values})
    except (TypeError, ValueError):
        raise validation.InputError("Keyword IDs must be numbers.") from None
    for keyword_id in ids:
        row = get_db().execute("SELECT kind FROM targets WHERE target_id = ?",
                               (keyword_id,)).fetchone()
        if row is None or row["kind"] != "keyword":
            raise validation.InputError(f"Target {keyword_id} does not exist or is not a keyword.")
    return ids


def create_target(data):
    """Validate and store a new target; returns its ID. data: kind, value, label,
    notes, enabled, keyword_ids."""
    kind = data.get("kind")
    if kind not in KINDS:
        raise validation.InputError("Kind must be domain, keyword or network.")
    if kind == "domain":
        value = validation.domain(data.get("value"))
    elif kind == "keyword":
        value = validation.keyword(data.get("value"))
    else:
        value = validation.network(data.get("value"), current_app.config["MAX_NETWORK_ADDRESSES"])
    label = validation.text(data.get("label"), "Label", 100)
    notes = validation.text(data.get("notes"), "Notes", 2000, required=False)
    enabled = validation.flag(data.get("enabled", True))
    keyword_ids = clean_keyword_ids(data.get("keyword_ids"), kind)

    db = get_db()
    if db.execute("SELECT 1 FROM targets WHERE kind = ? AND value = ?", (kind, value)).fetchone():
        raise validation.InputError(f"The {kind} {value} is already registered.", 409)
    created = now()
    target_id = db.execute(
        "INSERT INTO targets (kind, value, label, notes, enabled, created_by_user_id, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (kind, value, label, notes, enabled, g.user["user_id"], created, created)).lastrowid
    for keyword_id in keyword_ids:
        db.execute("INSERT INTO domain_keywords (domain_target_id, keyword_target_id, "
                   "created_by_user_id, created_at) VALUES (?, ?, ?, ?)",
                   (target_id, keyword_id, g.user["user_id"], created))
    audit("target.create", details={"target_id": target_id, "kind": kind, "value": value})
    db.commit()
    return target_id


def update_target(target, data):
    """Change label, notes, enabled and keyword links; only keys present in data change."""
    fields = {}
    if "label" in data:
        fields["label"] = validation.text(data["label"], "Label", 100)
    if "notes" in data:
        fields["notes"] = validation.text(data["notes"], "Notes", 2000, required=False)
    if "enabled" in data:
        fields["enabled"] = validation.flag(data["enabled"])
    unknown = set(data) - {"label", "notes", "enabled", "keyword_ids"}
    if unknown:
        raise validation.InputError(f"These fields cannot be changed: {', '.join(sorted(unknown))}.")
    keyword_ids = None
    if "keyword_ids" in data:
        keyword_ids = clean_keyword_ids(data["keyword_ids"], target["kind"])

    db = get_db()
    changed = now()
    changes = {k: [target[k], v] for k, v in fields.items() if target[k] != v}
    for column, (_, value) in changes.items():  # column names come from the fixed set above
        db.execute(f"UPDATE targets SET {column} = ? WHERE target_id = ?",
                   (value, target["target_id"]))
    if keyword_ids is not None and keyword_ids != sorted(target["keyword_ids"]):
        db.execute("DELETE FROM domain_keywords WHERE domain_target_id = ?", (target["target_id"],))
        for keyword_id in keyword_ids:
            db.execute("INSERT INTO domain_keywords (domain_target_id, keyword_target_id, "
                       "created_by_user_id, created_at) VALUES (?, ?, ?, ?)",
                       (target["target_id"], keyword_id, g.user["user_id"], changed))
        changes["keyword_ids"] = [sorted(target["keyword_ids"]), keyword_ids]
    if changes:
        db.execute("UPDATE targets SET updated_at = ? WHERE target_id = ?",
                   (changed, target["target_id"]))
        audit("target.edit", details={"target_id": target["target_id"],
                                      "value": target["value"], "changes": changes})
    db.commit()
    return changes


def delete_target(target):
    """Delete a target; the database removes its links, schedules, jobs and findings too."""
    db = get_db()
    db.execute("DELETE FROM targets WHERE target_id = ?", (target["target_id"],))
    audit("target.delete", details={"target_id": target["target_id"], "kind": target["kind"],
                                    "value": target["value"]})
    db.commit()


# ---------------------------------------------------------------------------
# Web pages
# ---------------------------------------------------------------------------

@bp.route("/targets")
@login_required
def search():
    targets = get_db().execute("SELECT * FROM targets ORDER BY kind, value").fetchall()
    keywords = [t for t in targets if t["kind"] == "keyword"]
    return render_template("targets.html", targets=targets, keywords=keywords, kinds=KINDS)


@bp.route("/targets", methods=["POST"])
@operator_required
def create():
    data = {**request.form, "enabled": "enabled" in request.form,
            "keyword_ids": request.form.getlist("keyword_ids")}
    try:
        target_id = create_target(data)
    except validation.InputError as exc:
        flash(exc.message, "error")
        return redirect(url_for("targets.search"))
    flash("Target created.", "ok")
    return redirect(url_for("targets.view", target_id=target_id))


@bp.route("/targets/<int:target_id>")
@login_required
def view(target_id):
    target = get_target(target_id) or abort(404)
    keywords = get_db().execute("SELECT * FROM targets WHERE kind = 'keyword' "
                                "ORDER BY value").fetchall()
    domains = get_db().execute("SELECT * FROM targets WHERE target_id IN (SELECT "
                               "domain_target_id FROM domain_keywords WHERE keyword_target_id = ?)",
                               (target_id,)).fetchall()
    return render_template("target.html", target=target, keywords=keywords, domains=domains)


@bp.route("/targets/<int:target_id>", methods=["POST"])
@operator_required
def edit(target_id):
    target = get_target(target_id) or abort(404)
    data = {"label": request.form.get("label"), "notes": request.form.get("notes"),
            "enabled": "enabled" in request.form}
    if target["kind"] == "domain":
        data["keyword_ids"] = request.form.getlist("keyword_ids")
    try:
        changes = update_target(target, data)
    except validation.InputError as exc:
        flash(exc.message, "error")
    else:
        flash("Target updated." if changes else "Nothing changed.", "ok")
    return redirect(url_for("targets.view", target_id=target_id))


@bp.route("/targets/<int:target_id>/delete", methods=["POST"])
@operator_required
def delete(target_id):
    target = get_target(target_id) or abort(404)
    delete_target(target)
    flash(f"Target {target['value']} deleted.", "ok")
    return redirect(url_for("targets.search"))


# ---------------------------------------------------------------------------
# REST API (JSON, X-API-Key)
# ---------------------------------------------------------------------------

def json_error(message, status):
    return jsonify(error=message), status


@api.route("/health")
def health():
    return {"status": "ok"}


@api.route("/targets")
@api_key_required()
def api_search():
    rows = get_db().execute("SELECT target_id FROM targets ORDER BY kind, value").fetchall()
    return jsonify([get_target(r["target_id"]) for r in rows])


@api.route("/targets", methods=["POST"])
@api_key_required(write=True)
def api_create():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("The body must be a JSON object.", 400)
    try:
        target_id = create_target(data)
    except validation.InputError as exc:
        return json_error(exc.message, exc.status)
    return jsonify(get_target(target_id)), 201


@api.route("/targets/<int:target_id>")
@api_key_required()
def api_view(target_id):
    target = get_target(target_id)
    return jsonify(target) if target else json_error("Target not found.", 404)


@api.route("/targets/<int:target_id>", methods=["PATCH"])
@api_key_required(write=True)
def api_edit(target_id):
    target = get_target(target_id)
    if target is None:
        return json_error("Target not found.", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("The body must be a JSON object.", 400)
    try:
        update_target(target, data)
    except validation.InputError as exc:
        return json_error(exc.message, exc.status)
    return jsonify(get_target(target_id))


@api.route("/targets/<int:target_id>", methods=["DELETE"])
@api_key_required(write=True)
def api_delete(target_id):
    target = get_target(target_id)
    if target is None:
        return json_error("Target not found.", 404)
    delete_target(target)
    return "", 204
