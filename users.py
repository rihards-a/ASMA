"""User management and the audit log. Operators only.

Users are never deleted, only deactivated: other tables reference them.
At least one active operator must always remain.
"""
from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from . import validation
from .auth import operator_required
from .db import audit, get_db, now

bp = Blueprint("users", __name__)

ROLES = ("viewer", "operator")


@bp.route("/users")
@operator_required
def search():
    users = get_db().execute(
        "SELECT u.*, c.username AS created_by FROM users AS u "
        "LEFT JOIN users AS c ON c.user_id = u.created_by_user_id "
        "ORDER BY u.username COLLATE NOCASE").fetchall()
    return render_template("users.html", users=users, roles=ROLES)


@bp.route("/users", methods=["POST"])
@operator_required
def create():
    db = get_db()
    try:
        username = validation.username(request.form.get("username"))
        role = request.form.get("role")
        if role not in ROLES:
            raise validation.InputError("Choose a role.")
        password = validation.password(request.form.get("password"), username)
        # username is COLLATE NOCASE, so "Anna" matches "anna".
        if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise validation.InputError("A user with this username already exists.", 409)
    except validation.InputError as exc:
        flash(exc.message, "error")
        return redirect(url_for("users.search"))

    created = now()
    user_id = db.execute(
        "INSERT INTO users (username, role, password_hash, must_change_password, "
        "password_changed_at, created_by_user_id, created_at) VALUES (?, ?, ?, 1, ?, ?, ?)",
        (username, role, generate_password_hash(password), created, g.user["user_id"],
         created)).lastrowid
    audit("user.create", details={"user_id": user_id, "username": username, "role": role})
    db.commit()
    flash(f"User {username} created. Give them the temporary password through a separate "
          f"channel; they must change it at the first sign-in.", "ok")
    return redirect(url_for("users.search"))


@bp.route("/users/<int:user_id>", methods=["GET", "POST"])
@operator_required
def edit(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if user is None:
        flash("The user does not exist.", "error")
        return redirect(url_for("users.search"))
    if request.method == "GET":
        return render_template("user.html", user=user, roles=ROLES)

    role = request.form.get("role")
    active = validation.flag(request.form.get("is_active"))
    new_password = request.form.get("password") or None
    try:
        if role not in ROLES:
            raise validation.InputError("Choose a role.")
        if user_id == g.user["user_id"] and (not active or not role == "operator"):
            raise validation.InputError("You cannot deactivate your own operator account.")
        if new_password:
            validation.password(new_password, user["username"])
    except validation.InputError as exc:
        flash(exc.message, "error")
        return redirect(url_for("users.edit", user_id=user_id))

    changes = {}
    if role != user["role"]:
        changes["role"] = [user["role"], role]
    if active != user["is_active"]:
        changes["is_active"] = [user["is_active"], active]
    db.execute("UPDATE users SET role = ?, is_active = ? WHERE user_id = ?",
               (role, active, user_id))
    if new_password:
        # A new password_changed_at signs the user out everywhere.
        db.execute("UPDATE users SET password_hash = ?, must_change_password = 1, "
                   "password_changed_at = ? WHERE user_id = ?",
                   (generate_password_hash(new_password),
                    now(), user_id))
        changes["password_reset"] = True
    if changes:
        audit("user.edit", details={"user_id": user_id, "username": user["username"],
                                    "changes": changes})
    db.commit()
    flash("User updated." if changes else "Nothing changed.", "ok")
    return redirect(url_for("users.search"))


@bp.route("/audit")
@operator_required
def audit_log():
    events = get_db().execute(
        "SELECT e.*, u.username, k.key_prefix FROM audit_events AS e "
        "LEFT JOIN users AS u ON u.user_id = e.user_id "
        "LEFT JOIN api_keys AS k ON k.api_key_id = e.api_key_id "
        "ORDER BY e.event_id DESC LIMIT 200").fetchall()
    return render_template("audit.html", events=events)
