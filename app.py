import os
import sqlite3
import datetime
from datetime import timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, g, make_response
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt

# =====================================================================
# 1. CONFIGURATION & INITIALIZATION
# =====================================================================
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


# =====================================================================
# 2. DATABASE & MIDDLEWARE HELPERS
# =====================================================================
def get_db():
    """Establishes and returns a secure, high-concurrency database connection."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL;")  # Optimized concurrency
    return db

@app.teardown_appcontext
def close_connection(exception=None):
    """Safely closes the database connection when a request ends."""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database schema if it doesn't already exist."""
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

@app.after_request
def apply_security_headers(response):
    """Applies OWASP security headers to mitigate basic web vulnerabilities."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# =====================================================================
# 3. AUTHENTICATION DECORATOR & RE-USE FUNCTIONS
# =====================================================================
def get_jwt_payload():
    """Extracts and verifies JWT payloads from cookies or Authorization headers."""
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

def login_required(f):
    """
    Custom decorator to protect endpoints. 
    Injects the validated user payload into the route function as `current_user`.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        payload, err = get_jwt_payload()
        if err:
            return jsonify({"error": err[0]}), err[1]
        return f(payload, *args, **kwargs)
    return decorated


# =====================================================================
# 4. SYSTEM ENDPOINTS (Registration, Login, Logout)
# =====================================================================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    name = (data.get("name") or "").strip()
    password = data.get("password") or ""

    # Input Boundary Protections
    if not username or not name or not password:
        return jsonify({"error": "Username, name, and password are required."}), 400
    if len(username) < 3 or len(username) > 30:
        return jsonify({"error": "Username must be between 3 and 30 characters."}), 400
    if len(name) < 2 or len(name) > 100:
        return jsonify({"error": "Name must be between 2 and 100 characters."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400

    # Process Hashing outside DB Transaction
    try:
        password_hash = ph.hash(password)
    except Exception:
        return jsonify({"error": "Internal error setting up security."}), 500

    db = get_db()
    try:
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
        
        # Adaptive Upgrade: Automatically upgrades weaker hashes if Argon2 parameters change
        if ph.check_needs_rehash(row["password_hash"]):
            new_hash = ph.hash(password)
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, row["id"]))
            db.commit()
            
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
            "user": {"username": row["username"], "name": row["name"]}
        })
    )

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


# =====================================================================
# 5. YOUR CUSTOM APPLICATION ENDPOINTS (Examples)
# =====================================================================
@app.route("/api/protected", methods=["GET"])
@login_required
def protected(current_user):
    """An example of using the @login_required decorator template."""
    return jsonify({
        "message": f"Hello, {current_user.get('name')}! Access granted to protected area.",
        "user_details": current_user
    })

if __name__ == "__main__":
    app.run(debug=(ENV != "production"))
