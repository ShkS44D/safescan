import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from functools import wraps

from flask import abort, current_app, g, redirect, request, session, url_for
from scanner import jobs
from scanner.jobs import utc_now

_attempts = defaultdict(deque)
_lock = threading.Lock()

@contextmanager
def _connect():
    db = sqlite3.connect(jobs.DB_PATH)
    try:
        yield db
        db.commit()
    finally:
        db.close()


def initialize_security():
    with _connect() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, created_at TEXT NOT NULL, last_login TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL,
          subject TEXT, ip TEXT, created_at TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS schedules (
          id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, target TEXT NOT NULL,
          config TEXT NOT NULL, cadence TEXT NOT NULL, webhook_url TEXT,
          enabled INTEGER NOT NULL DEFAULT 1, next_run TEXT NOT NULL, created_at TEXT NOT NULL)''')


def password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
    return f'pbkdf2_sha256$600000${salt.hex()}${digest.hex()}'


def password_valid(password, encoded):
    try:
        _, rounds, salt, expected = encoded.split('$')
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_user(email, password):
    initialize_security()
    with _connect() as db:
        cursor = db.execute('INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)',
                            (email.lower().strip(), password_hash(password), utc_now()))
        return cursor.lastrowid


def authenticate(email, password):
    with _connect() as db:
        db.row_factory = sqlite3.Row
        user = db.execute('SELECT * FROM users WHERE email=?', (email.lower().strip(),)).fetchone()
        if user and password_valid(password, user['password_hash']):
            db.execute('UPDATE users SET last_login=? WHERE id=?', (utc_now(), user['id']))
            return dict(user)


def load_user():
    g.user = None
    if session.get('user_id'):
        with _connect() as db:
            db.row_factory = sqlite3.Row
            row = db.execute('SELECT id,email,created_at,last_login FROM users WHERE id=?', (session['user_id'],)).fetchone()
            g.user = dict(row) if row else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_app.testing and not g.user:
            g.user = {'id': None, 'email': 'test@localhost'}
        if not g.user:
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapped


def scanner_access_required(view):
    """Allow a registered account or an active, isolated guest session."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_app.testing and not g.user:
            g.user = {'id': None, 'email': 'test@localhost'}
        if not g.user and not session.get('guest_id'):
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapped


def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']


def verify_csrf():
    if current_app.testing:
        return
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        supplied = request.form.get('_csrf') or request.headers.get('X-CSRF-Token')
        if not supplied or not hmac.compare_digest(supplied, session.get('_csrf', '')):
            abort(400, 'Invalid or missing security token.')


def rate_limit(key, limit, window):
    now = time.monotonic()
    with _lock:
        bucket = _attempts[key]
        while bucket and bucket[0] < now - window: bucket.popleft()
        if len(bucket) >= limit: return False
        bucket.append(now); return True


def audit(action, subject=''):
    initialize_security()
    with _connect() as db:
        db.execute('INSERT INTO audit_log(user_id,action,subject,ip,created_at) VALUES(?,?,?,?,?)',
                   (g.user['id'] if g.user else None, action, subject, request.remote_addr, utc_now()))


initialize_security()
