# Secure Authentication Lab (Flask)

A small local authentication service built for the Cyber Security **Task-2** lab.

## Run it
```bash
pip install -r requirements.txt
INSECURE_LOCAL_COOKIES=1 SECRET_KEY=change-me python app.py   # local HTTP testing
pytest -v                                                       # run the tests
```
Without `INSECURE_LOCAL_COOKIES=1` the cookie is `Secure` (HTTPS only), which is the production default.

## Endpoints
| Method | Path | Purpose |
|---|---|---|
| POST | `/register` | `{email, password}` -> create user |
| POST | `/login` | `{email, password}` -> start session |
| GET | `/me` | current user (needs session) |
| POST | `/logout` | destroy session |

## What I did (checklist)
1. **Password hashing + server-side validation**
   - Passwords are hashed with Werkzeug's salted **scrypt** (`generate_password_hash`); plain text is never stored.
   - Server validates email format/length and password rules (8-128 chars, upper, lower, digit) and rejects non-string input. Client-side checks are never trusted.
   - SQL uses parameterised queries (no SQL injection).
2. **Secure cookies, logout, expiry**
   - Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax`.
   - Sessions expire after 30 minutes (`PERMANENT_SESSION_LIFETIME`).
   - `/logout` clears the session and deletes the cookie. Session is cleared on login to prevent fixation.
3. **Rate limiting + generic errors**
   - Max 5 failed logins per 15 minutes per IP+email, then HTTP `429` with `Retry-After`.
   - Wrong email and wrong password both return the same `401 {"error": "Invalid credentials"}`.
   - A dummy hash check runs for unknown emails so response timing doesn't reveal valid accounts.
4. **Submission**: this repository link + this README.

## Optional upgrade: tests
`tests/test_auth.py` covers valid login, hashed storage, input validation, cookie flags, logout, expired/invalid/tampered sessions, generic errors, brute-force lockout, and counter reset.

## Evidence and security note
- `test_output.txt`: output of `pytest -v` (16 passed)
- `SECURITY_NOTE.md`: controls, risks they address, and known limitations

## Notes / limitations
- Rate-limit counters are in memory (reset on restart, single process). Use Redis or a DB in production.
- Used scrypt because it ships with Werkzeug; bcrypt or argon2 are equally valid choices.
