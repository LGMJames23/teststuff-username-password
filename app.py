from flask import Flask, request, jsonify, render_template, g
import os
import sqlite3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt
import datetime

# Configuration
DATABASE = os.environ.get('DB_PATH', 'users.db')
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour

app = Flask(__name__)
ph = PasswordHasher()

# Database helpers
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    db.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'error': 'username and password are required'}), 400

    db = get_db()
    try:
        password_hash = ph.hash(password)
        db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        db.commit()
        return jsonify({'ok': True, 'message': 'user created'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'username already exists'}), 409
    except Exception as e:
        return jsonify({'error': 'internal error'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'error': 'username and password are required'}), 400

    db = get_db()
    row = db.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,)).fetchone()
    if not row:
        return jsonify({'error': 'invalid credentials'}), 401

    try:
        ph.verify(row['password_hash'], password)
    except VerifyMismatchError:
        return jsonify({'error': 'invalid credentials'}), 401
    except Exception:
        return jsonify({'error': 'internal error'}), 500

    payload = {
        'sub': row['username'],
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return jsonify({'token': token})

def decode_token_from_header():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None, ('missing token', 401)
    token = auth.split(' ', 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, ('token expired', 401)
    except jwt.InvalidTokenError:
        return None, ('invalid token', 401)

@app.route('/api/protected')
def protected():
    payload, err = decode_token_from_header()
    if err:
        return jsonify({'error': err[0]}), err[1]
    return jsonify({'message': f"Hello {payload['sub']}, this is protected data."})

if __name__ == '__main__':
    with app.app_context():
        init_db()
    # Do NOT use debug=True in production. This app is for local/dev use only.
    app.run(host='127.0.0.1', port=5000)
