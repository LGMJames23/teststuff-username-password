# Minimal username/password example (Flask + Argon2 + JWT)

This repository provides a small example app for local/dev use demonstrating:

- Registering users with Argon2 password hashing (argon2-cffi)
- Logging in and returning a JWT (PyJWT)
- A protected endpoint that requires a Bearer token

This is intentionally minimal and *not* production-ready. See notes below before reuse.

## Quick start

1. Create a virtualenv and install requirements:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run the app:

```bash
export FLASK_APP=app.py
export FLASK_ENV=development  # optional for nicer errors locally
export SECRET_KEY="dev-secret-change-me"
python app.py
```

3. Open http://127.0.0.1:5000/ in your browser.

## Notes & Security

- The default SECRET_KEY is insecure — set `SECRET_KEY` in the environment for any real testing.
- Don't use this code as-is in production. Use HTTPS, secure cookie storage for tokens, rotate secrets, add rate limiting, input validation, etc.
- Passwords are hashed with Argon2 (argon2-cffi). This is a good default for password storage.
- JWT tokens are signed with HS256 using SECRET_KEY.
- The app uses a simple SQLite file `users.db` by default.

## Files
- `app.py` — Flask application
- `templates/index.html` — example UI
- `static/{style.css,script.js}` — static assets
- `requirements.txt` — Python deps

