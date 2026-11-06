"""API keys: credentials of a user for programs calling the REST API (e.g. n8n).

A key looks like asm_<prefix>_<secret>. The owner chooses the prefix to tell
keys apart; the secret is random and shown once. The database stores only the
prefix, an optional description and the SHA-256 of the whole key, and finds a
presented key by that hash. A plain SHA-256 is enough here because the secret
is 256 random bits, unlike a human password.

Every user manages their own keys. A key acts with its owner's current role,
or as viewer when read only; viewers can only create read-only keys.
"""
import hashlib
import re
import secrets
from functools import wraps

from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, url_for

from . import validation
from .auth import login_required
from .db import audit, get_db, now

bp = Blueprint("apikeys", __name__)

# 43 chars, because 32 bytes are encoded in base64url (32 * 8 / 6 = 42.6667). 
KEY_FORMAT = re.compile(r"asm_([a-z0-9][a-z0-9-]{1,30}[a-z0-9])_([A-Za-z0-9_-]{43})")


def digest(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def render_keys(new_key=None):
    keys = get_db().execute("SELECT * FROM api_keys WHERE user_id = ? "
                            "ORDER BY revoked_at IS NOT NULL, api_key_id DESC",
                            (g.user["user_id"],)).fetchall()
    return render_template("api_keys.html", keys=keys, new_key=new_key)


@bp.route("/api-keys")
@login_required
def search():
    return render_keys()


@bp.route("/api-keys", methods=["POST"])
@login_required
def create():
    db = get_db()
    try:
        prefix = validation.key_prefix(request.form.get("prefix"))
        description = validation.text(request.form.get("description"), "Description", 200,
                                      required=False)
        if db.execute("SELECT 1 FROM api_keys WHERE user_id = ? AND key_prefix = ? "
                      "AND revoked_at IS NULL", (g.user["user_id"], prefix)).fetchone():
            raise validation.InputError("You already have an active key with this prefix.", 409)
    except validation.InputError as exc:
        flash(exc.message, "error")
        return redirect(url_for("apikeys.search"))

    # Viewers only get read-only keys; operators choose.
    read_only = 1 if g.user["role"] == "viewer" else validation.flag(request.form.get("read_only"))
    key = f"asm_{prefix}_{secrets.token_urlsafe(32)}"
    key_id = db.execute(
        "INSERT INTO api_keys (user_id, description, read_only, key_prefix, key_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (g.user["user_id"], description, read_only, prefix, digest(key), now())).lastrowid
    audit("apikey.create", details={"api_key_id": key_id, "key_prefix": prefix,
                                    "read_only": read_only})
    db.commit()
    # Rendered directly instead of redirecting, so the key never sits in the cookie.
    return render_keys(new_key=key)


@bp.route("/api-keys/<int:key_id>/revoke", methods=["POST"])
@login_required
def revoke(key_id):
    db = get_db()
    updated = db.execute("UPDATE api_keys SET revoked_at = ? WHERE api_key_id = ? "
                         "AND user_id = ? AND revoked_at IS NULL",
                         (now(), key_id, g.user["user_id"])).rowcount
    if updated:
        audit("apikey.revoke", details={"api_key_id": key_id})
        db.commit()
        flash("Key revoked.", "ok")
    return redirect(url_for("apikeys.search"))


# The extra nesting here is necessary as it is a decorator factory,
# which returns different decorators depending on the write field.
def api_key_required(write=False):
    """Decorator for API routes: X-API-Key must be a valid key.

    write=True additionally needs an operator account and a key that is not
    read only. Sets g.user (the owner) and g.api_key.
    """
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            presented = request.headers.get("X-API-Key", "")
            match = KEY_FORMAT.fullmatch(presented)
            db = get_db()
            key = None
            if match:
                key = db.execute(
                    "SELECT k.*, u.username, u.role, u.is_active FROM api_keys AS k "
                    "JOIN users AS u ON u.user_id = k.user_id WHERE k.key_hash = ?",
                    (digest(presented),)).fetchone() # the (x,) is needed to make it a tuple which is required by the execute method
            if key is None or key["revoked_at"] or not key["is_active"]:
                if presented:  # a request without any key is not an attempt worth logging
                    audit("auth.api_key", "failed",
                          {"key_prefix": match.group(1) if match else None})
                    db.commit()
                return jsonify(error="Invalid or missing API key."), 401

            g.api_key, g.user = key, key
            db.execute("UPDATE api_keys SET last_used_at = ? WHERE api_key_id = ?",
                       (now(), key["api_key_id"]))
            if write and (key["read_only"] or key["role"] != "operator"):
                audit("access.denied", "denied", {"path": request.path, "method": request.method})
                db.commit()
                return jsonify(error="This key may not change data."), 403
            db.commit()
            return view(*args, **kwargs)
        return wrapped
    return decorator
