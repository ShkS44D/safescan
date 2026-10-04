import ipaddress, json, socket, sqlite3, threading, uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
import requests
from scanner import jobs

CADENCES = {'daily': timedelta(days=1), 'weekly': timedelta(days=7), 'monthly': timedelta(days=30)}

def compare_results(current, previous):
    def keys(result): return {f"{x.get('category')}|{x.get('title')}|{x.get('endpoint') or x.get('url')}" for x in (result or {}).get('findings', [])}
    now, before = keys(current), keys(previous)
    return {'new': sorted(now-before), 'resolved': sorted(before-now), 'unchanged': sorted(now & before)}

def validate_webhook(value):
    if not value: return None
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Webhook must be a public HTTPS URL without credentials.')
    for info in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM):
        if not ipaddress.ip_address(info[4][0]).is_global: raise ValueError('Webhook must resolve to a public address.')
    return value

def create_schedule(owner_id, target, config, cadence, webhook_url=None):
    if cadence not in CADENCES: raise ValueError('Unsupported schedule cadence.')
    webhook_url = validate_webhook(webhook_url); schedule_id = uuid.uuid4().hex[:12]; now = datetime.now(timezone.utc)
    with sqlite3.connect(jobs.DB_PATH) as db:
        db.execute('INSERT INTO schedules(id,owner_id,target,config,cadence,webhook_url,next_run,created_at) VALUES(?,?,?,?,?,?,?,?)',
          (schedule_id,owner_id,target,json.dumps(config),cadence,webhook_url,(now+CADENCES[cadence]).isoformat(),now.isoformat()))
    return schedule_id

def list_schedules(owner_id):
    with sqlite3.connect(jobs.DB_PATH) as db:
        db.row_factory=sqlite3.Row
        return [dict(r) for r in db.execute('SELECT * FROM schedules WHERE owner_id=? ORDER BY created_at DESC',(owner_id,))]

def delete_schedule(schedule_id, owner_id):
    with sqlite3.connect(jobs.DB_PATH) as db: db.execute('DELETE FROM schedules WHERE id=? AND owner_id=?',(schedule_id,owner_id))

def notify_completed(job):
    if not job.get('schedule_id'): return
    with sqlite3.connect(jobs.DB_PATH) as db: row=db.execute('SELECT webhook_url FROM schedules WHERE id=?',(job['schedule_id'],)).fetchone()
    if row and row[0]:
        try: requests.post(row[0],json={'event':'scan.completed','scan_id':job['id'],'target':job['target'],'summary':job['result']['summary']},timeout=8)
        except requests.RequestException: pass

def run_due(submit):
    now=datetime.now(timezone.utc)
    with sqlite3.connect(jobs.DB_PATH) as db:
        db.row_factory=sqlite3.Row; due=list(db.execute('SELECT * FROM schedules WHERE enabled=1 AND next_run<=?',(now.isoformat(),)))
        for row in due:
            job=jobs.create(row['target'],json.loads(row['config']),row['owner_id'],row['id'])
            db.execute('UPDATE schedules SET next_run=? WHERE id=?',((now+CADENCES[row['cadence']]).isoformat(),row['id'])); submit(job['id'])

def start_scheduler(submit):
    def loop():
        while True:
            threading.Event().wait(60)
            try: run_due(submit)
            except Exception: pass
    threading.Thread(target=loop,name='scan-scheduler',daemon=True).start()
