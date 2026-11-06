"""Sign-in, sign-out, password change, and the access checks used by every page.

Sessions are Flask's signed cookie holding the user ID and the user's
password_changed_at. The account is re-read on every request, so deactivation,
role changes and password resets take effect immediately.
"""
import secrets
from functools import wraps

from flask import (Blueprint, abort, flash, g, redirect, render_template, request, session,
                   url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from . import validation
from .db import audit, get_db, now

bp = Blueprint("auth", __name__)

# Checked when the username does not exist, so a wrong username takes as long
# as a wrong password and does not reveal which accounts exist.
DUMMY_HASH = generate_password_hash("dummy")


@bp.before_app_request # runs before every request, so g.user is always set to the current user or None
def load_user():
    g.user = g.api_key = None
    if request.path.startswith("/api/"):
        return  # the API authenticates with X-API-Key only (see apikeys.py)

    # CSRF: every form carries the session's token; a POST without it is refused.
    if request.method == "POST":
        expected = session.get("csrf_token")
        if not expected or not secrets.compare_digest(request.form.get("csrf_token", ""),
                                                       expected):
            abort(400, "The form has expired. Reload the page and try again.")

    user_id = session.get("user_id")
    if user_id:
        user = get_db().execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if user and user["is_active"] and user["password_changed_at"] == session.get("pwc"):
            g.user = user
        else:
            session.clear()


@bp.app_context_processor # adds csrf_token() to every template, so it can be used in forms
def template_helpers():
    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)
        return session["csrf_token"]
    return {"csrf_token": csrf_token}


def login_required(view): # wrapper/decorator definition
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        # A temporary password must be replaced before anything else.
        if g.user["must_change_password"] and request.endpoint not in ("auth.password",
                                                                       "auth.logout"):
            return redirect(url_for("auth.password"))
        return view(*args, **kwargs)
    return wrapped


def operator_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user["role"] != "operator":
            audit("access.denied", "denied", {"path": request.path, "method": request.method})
            get_db().commit()
            abort(403)
        return view(*args, **kwargs)
    return login_required(wrapped)


@bp.route("/")
@login_required
def index():
    return redirect(url_for("targets.search"))

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form.get("username", "").strip()[:50]
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (name,)).fetchone()
        if user is None:
            check_password_hash(DUMMY_HASH, password)
            reason = "unknown_user"
        elif not check_password_hash(user["password_hash"], password):
            reason = "wrong_password"
        elif not user["is_active"]:
            reason = "inactive"
        else:
            reason = None

        if reason:
            # No lockout; failed attempts are logged with the source IP.
            audit("auth.login", "failed", {"username": name, "reason": reason})
            db.commit()
            flash("Invalid username or password.", "error")
            return render_template("login.html", username=name), 401

        db.execute("UPDATE users SET last_login_at = ? WHERE user_id = ?",
                   (now(), user["user_id"]))
        g.user = user
        audit("auth.login")
        db.commit()
        session.clear()
        session.permanent = True
        session["user_id"] = user["user_id"]
        session["pwc"] = user["password_changed_at"]
        return redirect(url_for("auth.index"))
    return render_template("login.html", username="")


@bp.route("/logout", methods=["POST"])
def logout():
    if g.user is not None:
        audit("auth.logout")
        get_db().commit()
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/password", methods=["GET", "POST"])
@login_required
def password():
    if request.method == "POST":
        user, db = g.user, get_db()
        try:
            if not check_password_hash(user["password_hash"], request.form.get("current", "")):
                raise validation.InputError("The current password is incorrect.")
            new = validation.password(request.form.get("new"), user["username"])
            if new != request.form.get("confirm"):
                raise validation.InputError("The new passwords do not match.")
            if check_password_hash(user["password_hash"], new):
                raise validation.InputError("The new password must differ from the current one.")
        except validation.InputError as exc:
            flash(exc.message, "error")
            return redirect(url_for("auth.password"))

        changed = now()
        db.execute("UPDATE users SET password_hash = ?, password_changed_at = ?, "
                   "must_change_password = 0 WHERE user_id = ?",
                   (generate_password_hash(new), changed, user["user_id"]))
        audit("auth.password")
        db.commit()
        # Other sessions of this user end; this one continues.
        session["pwc"] = changed
        flash("Password changed.", "ok")
        return redirect(url_for("auth.index"))
    return render_template("password.html")
