# Authentication Security Note

## Controls applied
| Risk | Control | Where |
|---|---|---|
| Stolen database leaks passwords | Salted scrypt hashes (Werkzeug), never plain text | `/register`, `/login` |
| Malformed / malicious input | Server-side validation of email and password; parameterised SQL | `validate_email`, `validate_password` |
| Session cookie theft via XSS | `HttpOnly` cookie | `SESSION_COOKIE_HTTPONLY` |
| Cookie sent over plain HTTP | `Secure` flag (HTTPS only) | `SESSION_COOKIE_SECURE` |
| Cross-site request forgery | `SameSite=Lax` | `SESSION_COOKIE_SAMESITE` |
| Stolen/old sessions | 30-minute expiry, logout clears session and cookie | `PERMANENT_SESSION_LIFETIME`, `/logout` |
| Session fixation | Session cleared before login | `/login` |
| Brute-force guessing | 5 failed logins / 15 min per IP+email, then 429 + `Retry-After` | `/login` |
| Account enumeration | Same `Invalid credentials` message and similar timing for unknown email and wrong password | `/login` |

## Evidence
`test_output.txt` holds the output of `pytest -v` (16 tests passed).

## Known limitations (honest notes)
- Rate-limit data is in memory: resets on restart and is not shared between processes. Use Redis or a database in production.
- The limit is per IP+email, so an attacker trying many different emails from one IP is not blocked. Add a per-IP limit too.
- Behind a proxy, `request.remote_addr` may be the proxy's address; configure trusted proxy headers properly.
- No CSRF token; protection relies on `SameSite=Lax`.
- No multi-factor authentication or password reset flow.
- Set a fixed `SECRET_KEY` in the environment for real use; a random one is generated at startup otherwise, which logs everyone out on restart.

## Private-safe repository
No secrets, real user data or database files are committed (`.gitignore` excludes `*.db` and `.env`). Test accounts use fake data (`alice@example.com`).
