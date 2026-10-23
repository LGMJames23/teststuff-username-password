import os
import sqlite3
import datetime
from datetime import timezone

from flask import Flask, request, jsonify, render_template, g, make_response
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt

# Configuration
ENV = os.environ.get("FLASK_ENV", "production")
DATABASE = os.environ.get("DB_PATH", "users.db")
SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    if ENV == "production":
        raise ValueError("CRITICAL: SECRET_KEY environment variable must be set in production.")
    SECRET_KEY = "dev-secret-key-change-in-production"

JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour
COOKIE_NAME = "access_token"

app = Flask(__name__)
ph = PasswordHasher()

# Database setup
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL;")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()

init_db()

# Security Header Middleware
@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Token Retrieval Helper
def get_jwt_payload():
    token = request.cookies.get(COOKIE_NAME)

    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

    if not token:
        return None, ("Missing authentication token", 401)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, ("Token has expired", 401)
    except jwt.InvalidTokenError:
        return None, ("Invalid token", 401)

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    name = (data.get("name") or "").strip()
    password = data.get("password") or ""

    if not username or not name or not password:
        return jsonify({"error": "Username, name, and password are required."}), 400

    if len(username) < 3 or len(username) > 30:
        return jsonify({"error": "Username must be between 3 and 30 characters."}), 400

    if len(name) < 2 or len(name) > 100:
        return jsonify({"error": "Name must be between 2 and 100 characters."}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400

    db = get_db()
    try:
        # Argon2 automatically generates a random salt and stores it in the hash string.
        password_hash = ph.hash(password)
        db.execute(
            "INSERT INTO users (username, name, password_hash) VALUES (?, ?, ?)",
            (username, name, password_hash)
        )
        db.commit()
        return jsonify({"ok": True, "message": "Account created successfully."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username is already taken."}), 409
    except Exception:
        return jsonify({"error": "An error occurred while creating your account."}), 500

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    db = get_db()
    row = db.execute(
        "SELECT id, username, name, password_hash FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    invalid_credentials = (jsonify({"error": "Invalid username or password."}), 401)

    if not row:
        return invalid_credentials

    try:
        ph.verify(row["password_hash"], password)
    except VerifyMismatchError:
        return invalid_credentials
    except Exception:
        return jsonify({"error": "An internal error occurred."}), 500

    now = datetime.datetime.now(timezone.utc)
    payload = {
        "sub": row["username"],
        "user_id": row["id"],
        "name": row["name"],
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)).timestamp()),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)

    response = make_response(
        jsonify({
            "ok": True,
            "message": "Logged in successfully.",
            "user": {
                "username": row["username"],
                "name": row["name"],
            }
        })
    )

    # Store token in HttpOnly cookie to mitigate XSS exposure
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=(ENV == "production"),
        samesite="Lax",
        max_age=JWT_EXP_DELTA_SECONDS
    )
    return response

@app.route("/api/logout", methods=["POST"])
def logout():
    response = make_response(jsonify({"ok": True, "message": "Logged out."}))
    response.set_cookie(COOKIE_NAME, "", expires=0)
    return response

@app.route("/api/protected", methods=["GET"])
def protected():
    payload, err = get_jwt_payload()
    if err:
        return jsonify({"error": err[0]}), err[1]
    return jsonify({
        "message": f"Hello, {payload.get('name') or payload.get('sub')}! Access granted to protected area."
    })
