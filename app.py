"""Secure Authentication Lab - small local auth service (Flask).

Features:
  1. Password hashing (scrypt, salted) + server-side input validation
  2. Secure session cookies (HttpOnly, Secure, SameSite), logout, expiry
  3. Rate limiting on login + generic authentication errors
"""
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta

from flask import Flask, g, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

MAX_ATTEMPTS = 5          # failed logins allowed ...
WINDOW_SECONDS = 15 * 60  # ... per 15 minutes (per IP + email)

# A real hash used to burn equal time when the email does not exist,
# so response time does not reveal which emails are registered.
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get("DATABASE", "users.db"),
        # --- secure cookie settings ---
        SESSION_COOKIE_HTTPONLY=True,    # JS cannot read the cookie
        SESSION_COOKIE_SECURE=True,      # sent only over HTTPS
        SESSION_COOKIE_SAMESITE="Lax",   # blocks cross-site CSRF sends
        SESSION_COOKIE_NAME="session_id",
        # --- session expiry ---
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_ATTEMPTS=MAX_ATTEMPTS,
        WINDOW_SECONDS=WINDOW_SECONDS,
    )
    if config:
        app.config.update(config)

    app.attempts = {}  # key -> list of failure timestamps (in-memory)

    # ---------------- database ----------------
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with app.app_context():
        get_db().execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "email TEXT UNIQUE NOT NULL,"
            "password_hash TEXT NOT NULL)"
        )
        get_db().commit()

    # ---------------- validation ----------------
    def validate_email(email):
        return isinstance(email, str) and len(email) <= 254 and bool(EMAIL_RE.match(email))

    def validate_password(pw):
        """Return a list of problems (empty list = valid)."""
        if not isinstance(pw, str):
            return ["Password must be a string."]
        problems = []
        if not 8 <= len(pw) <= 128:
            problems.append("Password must be 8-128 characters.")
        if not re.search(r"[a-z]", pw):
            problems.append("Password needs a lowercase letter.")
        if not re.search(r"[A-Z]", pw):
            problems.append("Password needs an uppercase letter.")
        if not re.search(r"\d", pw):
            problems.append("Password needs a digit.")
        return problems

    # ---------------- rate limiting ----------------
    def rate_key(email):
        return f"{request.remote_addr}|{(email or '').lower()}"

    def recent_failures(key):
        now = time.time()
        window = app.config["WINDOW_SECONDS"]
        fresh = [t for t in app.attempts.get(key, []) if now - t < window]
        app.attempts[key] = fresh
        return fresh

    # ---------------- routes ----------------
    @app.post("/register")
    def register():
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip().lower() if isinstance(data.get("email"), str) else None
        password = data.get("password")

        if not validate_email(email):
            return jsonify(error="Invalid email address."), 400
        problems = validate_password(password)
        if problems:
            return jsonify(error=" ".join(problems)), 400

        try:
            get_db().execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, generate_password_hash(password)),  # scrypt + random salt
            )
            get_db().commit()
        except sqlite3.IntegrityError:
            # Same response shape as success-ish failure; avoids a clear
            # "this email exists" oracle beyond what registration needs.
            return jsonify(error="Registration failed."), 400
        return jsonify(message="Registered."), 201

    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or {}
        raw_email = data.get("email")
        password = data.get("password")
        email = raw_email.strip().lower() if isinstance(raw_email, str) else ""

        key = rate_key(email)
        failures = recent_failures(key)
        if len(failures) >= app.config["MAX_ATTEMPTS"]:
            retry = int(app.config["WINDOW_SECONDS"] - (time.time() - failures[0])) + 1
            resp = jsonify(error="Too many attempts. Try again later.")
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry)
            return resp

        generic = (jsonify(error="Invalid credentials"), 401)

        if not validate_email(email) or not isinstance(password, str) or not password:
            app.attempts[key].append(time.time())
            return generic

        row = get_db().execute(
            "SELECT id, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()

        # Always run one hash check so timing is the same either way.
        hash_to_check = row["password_hash"] if row else _DUMMY_HASH
        ok = check_password_hash(hash_to_check, password)

        if not (row and ok):
            app.attempts[key].append(time.time())
            return generic  # SAME message for wrong email or wrong password

        app.attempts.pop(key, None)  # reset counter on success
        session.clear()              # prevent session fixation
        session.permanent = True     # applies PERMANENT_SESSION_LIFETIME
        session["user_id"] = row["id"]
        session["issued_at"] = int(time.time())
        return jsonify(message="Logged in.")

    @app.get("/me")
    def me():
        uid = session.get("user_id")
        if uid is None:
            return jsonify(error="Not authenticated."), 401
        row = get_db().execute("SELECT email FROM users WHERE id = ?", (uid,)).fetchone()
        if row is None:
            session.clear()
            return jsonify(error="Not authenticated."), 401
        return jsonify(email=row["email"])

    @app.post("/logout")
    def logout():
        session.clear()  # destroys the session data
        resp = jsonify(message="Logged out.")
        resp.delete_cookie(app.config["SESSION_COOKIE_NAME"])
        return resp

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    return app


if __name__ == "__main__":
    # For local HTTP testing set SESSION_COOKIE_SECURE off via env; default stays secure.
    cfg = {}
    if os.environ.get("INSECURE_LOCAL_COOKIES") == "1":
        cfg["SESSION_COOKIE_SECURE"] = False
    create_app(cfg).run(debug=False)
