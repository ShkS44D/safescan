import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path('/tmp/safescan.db') if os.getenv('VERCEL') else Path(__file__).resolve().parent.parent / 'data' / 'scans.db'
_lock = threading.RLock()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def initialize():
    DB_PATH.parent.mkdir(exist_ok=True)
    with _connect() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, target TEXT NOT NULL, config TEXT NOT NULL,
            status TEXT NOT NULL, phase TEXT NOT NULL, progress INTEGER NOT NULL DEFAULT 0,
            cancel_requested INTEGER NOT NULL DEFAULT 0, result TEXT, error TEXT,
            created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
            owner_id INTEGER, schedule_id TEXT
        )''')
        columns = {row['name'] for row in db.execute('PRAGMA table_info(scans)')}
        for name, definition in {'owner_id': 'INTEGER', 'schedule_id': 'TEXT'}.items():
            if name not in columns:
                db.execute(f'ALTER TABLE scans ADD COLUMN {name} {definition}')
        db.execute('CREATE INDEX IF NOT EXISTS idx_scans_owner_created ON scans(owner_id, created_at DESC)')


@contextmanager
def _connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    finally:
        db.close()


def _decode(row):
    if row is None:
        return None
    item = dict(row)
    item['config'] = json.loads(item['config'])
    item['result'] = json.loads(item['result']) if item['result'] else None
    item['cancel_requested'] = bool(item['cancel_requested'])
    return item


def create(target, config, owner_id=None, schedule_id=None):
    initialize()
    item = {'id': uuid.uuid4().hex[:12], 'target': target, 'config': config,
            'status': 'queued', 'phase': 'Queued', 'progress': 0, 'created_at': utc_now()}
    with _lock, _connect() as db:
        db.execute('INSERT INTO scans (id,target,config,status,phase,progress,created_at,owner_id,schedule_id) VALUES (?,?,?,?,?,?,?,?,?)',
                   (item['id'], target, json.dumps(config), item['status'], item['phase'], 0, item['created_at'], owner_id, schedule_id))
    item.update(owner_id=owner_id, schedule_id=schedule_id)
    return item


def get(scan_id):
    initialize()
    with _connect() as db:
        return _decode(db.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone())


def list_recent(limit=30, owner_id=None):
    initialize()
    with _connect() as db:
        if owner_id is None:
            rows = db.execute('SELECT * FROM scans ORDER BY created_at DESC LIMIT ?', (limit,))
        else:
            rows = db.execute('SELECT * FROM scans WHERE owner_id=? ORDER BY created_at DESC LIMIT ?', (owner_id, limit))
        return [_decode(row) for row in rows]


def previous_completed(target, owner_id, exclude_id=None):
    initialize()
    query = "SELECT * FROM scans WHERE target=? AND owner_id=? AND status='completed'"
    params = [target, owner_id]
    if exclude_id:
        query += ' AND id<>?'; params.append(exclude_id)
    query += ' ORDER BY finished_at DESC LIMIT 1'
    with _connect() as db:
        return _decode(db.execute(query, params).fetchone())


def recover_interrupted():
    """Mark jobs abandoned by a previous process; queued jobs can be submitted again."""
    initialize()
    with _lock, _connect() as db:
        db.execute("UPDATE scans SET status='failed', phase='Interrupted', error='Application stopped before the scan finished.', finished_at=? WHERE status='running'", (utc_now(),))
        return [row['id'] for row in db.execute("SELECT id FROM scans WHERE status='queued'")]


def update(scan_id, **values):
    allowed = {'status', 'phase', 'progress', 'cancel_requested', 'result', 'error', 'started_at', 'finished_at'}
    values = {key: value for key, value in values.items() if key in allowed}
    if 'result' in values:
        values['result'] = json.dumps(values['result'])
    if not values:
        return
    with _lock, _connect() as db:
        db.execute(f"UPDATE scans SET {', '.join(f'{key}=?' for key in values)} WHERE id=?", (*values.values(), scan_id))


def request_cancel(scan_id):
    update(scan_id, cancel_requested=1)


def delete_guest_scans(guest_id):
    """Remove every transient scan belonging to one anonymous browser session."""
    if not guest_id:
        return
    initialize()
    with _lock, _connect() as db:
        rows = db.execute('SELECT id,config FROM scans WHERE owner_id IS NULL').fetchall()
        ids = [row['id'] for row in rows if json.loads(row['config']).get('guest_id') == guest_id]
        if ids:
            db.executemany('DELETE FROM scans WHERE id=?', [(scan_id,) for scan_id in ids])


def cleanup_expired_guest_scans(max_age_hours=2):
    cutoff = datetime.now(timezone.utc).timestamp() - max_age_hours * 3600
    initialize()
    with _lock, _connect() as db:
        rows = db.execute('SELECT id,config,created_at FROM scans WHERE owner_id IS NULL').fetchall()
        ids = []
        for row in rows:
            config = json.loads(row['config'])
            if config.get('guest_id') and datetime.fromisoformat(row['created_at']).timestamp() < cutoff:
                ids.append(row['id'])
        if ids:
            db.executemany('DELETE FROM scans WHERE id=?', [(scan_id,) for scan_id in ids])


initialize()
