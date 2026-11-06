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

    return app
