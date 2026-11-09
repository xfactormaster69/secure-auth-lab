import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app import create_app  # noqa: E402

EMAIL = "alice@example.com"
PASSWORD = "StrongPass1"


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "DATABASE": str(tmp_path / "t.db")})


@pytest.fixture
def client(app):
    # base_url https so the Secure cookie is accepted by the test client
    return app.test_client(), app


def register(c, email=EMAIL, pw=PASSWORD):
    return c.post("/register", json={"email": email, "password": pw}, base_url="https://localhost")


def login(c, email=EMAIL, pw=PASSWORD):
    return c.post("/login", json={"email": email, "password": pw}, base_url="https://localhost")


# ---------- step 1: hashing + validation ----------
def test_password_is_hashed_not_plaintext(client):
    c, app = client
    register(c)
    import sqlite3
    row = sqlite3.connect(app.config["DATABASE"]).execute("SELECT password_hash FROM users").fetchone()
    assert PASSWORD not in row[0]
    assert row[0].startswith(("scrypt:", "pbkdf2:"))


@pytest.mark.parametrize("email,pw", [
    ("not-an-email", PASSWORD),
    (EMAIL, "short1A"),
    (EMAIL, "alllowercase1"),
    (EMAIL, "NoDigitsHere"),
    (None, PASSWORD),
    (EMAIL, 12345678),
])
def test_server_side_validation_rejects_bad_input(client, email, pw):
    c, _ = client
    assert register(c, email, pw).status_code == 400


# ---------- valid login + step 2: sessions ----------
def test_valid_login_and_me(client):
    c, _ = client
    register(c)
    assert login(c).status_code == 200
    r = c.get("/me", base_url="https://localhost")
    assert r.status_code == 200 and r.get_json()["email"] == EMAIL


def test_cookie_flags(client):
    c, _ = client
    register(c)
    cookie = login(c).headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=Lax" in cookie
    assert "Expires=" in cookie or "Max-Age=" in cookie  # session expiry


def test_logout_destroys_session(client):
    c, _ = client
    register(c)
    login(c)
    assert c.post("/logout", base_url="https://localhost").status_code == 200
    assert c.get("/me", base_url="https://localhost").status_code == 401


def test_expired_session_is_rejected(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "e.db"),
                      "PERMANENT_SESSION_LIFETIME": __import__("datetime").timedelta(seconds=1)})
    c = app.test_client()
    register(c)
    login(c)
    assert c.get("/me", base_url="https://localhost").status_code == 200
    time.sleep(2)
    assert c.get("/me", base_url="https://localhost").status_code == 401


# ---------- invalid sessions ----------
def test_no_session_is_rejected(client):
    c, _ = client
    assert c.get("/me", base_url="https://localhost").status_code == 401


def test_tampered_cookie_is_rejected(client):
    c, _ = client
    register(c)
    login(c)
    c.set_cookie("session_id", "forged.value.here", domain="localhost")
    assert c.get("/me", base_url="https://localhost").status_code == 401


# ---------- step 3: generic errors + rate limiting ----------
def test_generic_error_same_for_wrong_email_and_password(client):
    c, _ = client
    register(c)
    wrong_pw = login(c, pw="WrongPass1")
    wrong_email = login(c, email="nobody@example.com")
    assert wrong_pw.status_code == wrong_email.status_code == 401
    assert wrong_pw.get_json() == wrong_email.get_json() == {"error": "Invalid credentials"}


def test_brute_force_is_rate_limited(client):
    c, app = client
    register(c)
    for _ in range(app.config["MAX_ATTEMPTS"]):
        assert login(c, pw="WrongPass1").status_code == 401
    r = login(c, pw="WrongPass1")
    assert r.status_code == 429 and "Retry-After" in r.headers
    # even the correct password is blocked while locked out
    assert login(c).status_code == 429


def test_successful_login_resets_counter(client):
    c, app = client
    register(c)
    for _ in range(app.config["MAX_ATTEMPTS"] - 1):
        login(c, pw="WrongPass1")
    assert login(c).status_code == 200
    assert login(c, pw="WrongPass1").status_code == 401  # not locked
