"""
Run:   flask --app asma run
Data:  ./data/asma.db, created on first start together with the operator
       account "admin", whose temporary password is printed to the console once.
"""
import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv
from pathlib import Path

from flask import Flask, request
from werkzeug.exceptions import HTTPException

from . import db, auth, apikeys, users, targets, jobs, schedules, validation

# Load environment variables from a .env file if it exists
load_dotenv() 

def create_app():
    app = Flask(__name__)
    app.config.update(
        # Signs the session cookie. Without ASMA_SECRET_KEY a random key is
        # generated, so everyone is signed out when the application restarts.
        SECRET_KEY=os.environ.get("ASMA_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=Path(os.environ.get("ASMA_DATA_DIR", "data")) / "asma.db",
        # Largest network target, in addresses.
        MAX_NETWORK_ADDRESSES=1024,
        # A session ends after 30 minutes without a request. Flask re-signs the
        # cookie on every request and rejects cookies older than this.
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # API keys of the scanning services; a scanner without its key cannot be started.
        OPENSQUAT_API_KEY=os.environ.get("ASMA_OPENSQUAT_API_KEY"),
        HIBS_API_KEY=os.environ.get("ASMA_HIBS_API_KEY"),
        SHODAN_API_KEY=os.environ.get("ASMA_SHODAN_API_KEY"),
    )
    db.init_app(app)
    
    jobs.init_app(app) # update jobs that were interrupted
    schedules.init_app(app) # start scheduler thread
    app.register_blueprint(auth.bp)
    app.register_blueprint(apikeys.bp)
    app.register_blueprint(users.bp)
    app.register_blueprint(targets.bp)
    app.register_blueprint(targets.api)
    app.register_blueprint(jobs.bp)
    app.register_blueprint(jobs.api)
    app.register_blueprint(schedules.bp)
    app.register_blueprint(schedules.api)

    @app.route("/api/health")
    def health():
        return {"status": "ok"}

    # Web routes catch InputError and flash it; an uncaught one comes from an
    # API route and is answered as JSON, with its status (400 or 409).
    @app.errorhandler(validation.InputError)
    def input_error(exc):
        return {"error": exc.message}, exc.status

    # abort() in an API route (e.g. 404 "Job not found.") and unknown /api URLs
    # answer JSON; web pages keep Flask's HTML error pages.
    @app.errorhandler(HTTPException)
    def http_error(exc):
        if request.path.startswith("/api/"):
            return {"error": exc.description}, exc.code
        return exc

    @app.after_request
    def security_headers(response):
        """Browser security headers, added to every response."""
        # Content Security Policy: which resources the browser may load for this page.
        #   default-src 'none'          nothing may be loaded (scripts, images, fonts,
        #                               connections) unless a directive below allows it;
        #                               also the pages does not use JavaScript.
        #   style-src 'self'            stylesheets only from this application.
        #   form-action 'self'          forms may only be submitted to this application.
        #   base-uri 'none'             a <base> tag cannot redirect the page's relative links.
        #   frame-ancestors 'none'      no site (this one included) may show the page in a
        #                               frame; stops clickjacking, where another site lays an
        #                               invisible frame over its own page in an attempt to
        #                               trick the signed in user into performing actions.
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'")
        # The older header for the same framing rule, for browsers that ignore frame-ancestors.
        response.headers["X-Frame-Options"] = "DENY"
        # The browser must use the declared Content-Type and not guess one from the content,
        # so a downloaded artifact (scanner output) is not run as HTML or script.
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Neither the browser nor anything in between may store a copy of the response:
        # pages show scan results, the audit log and, once, a new API key, which must not
        # stay in the browser cache or be shown again with the Back button.
        # The built in static endpoint is an exception.
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    return app
