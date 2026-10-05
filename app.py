import io, json, os, secrets
from datetime import datetime
from flask import Flask, abort, flash, g, jsonify, make_response, redirect, render_template, request, session, url_for
from scanner import jobs
from scanner.nmap_scanner import available as nmap_available
from scanner.scan_manager import _run, submit
from security import audit, csrf_token, rate_limit, scanner_access_required, verify_csrf
from utils.helpers import parse_target, validate_scan_options
from utils.logger import get_logger

app = Flask(__name__)
app.config.update(SECRET_KEY=os.getenv('SAFESCAN_SECRET_KEY') or os.getenv('VULNSCANNER_SECRET_KEY') or os.urandom(32), SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('SAFESCAN_SECURE_COOKIES',os.getenv('VULNSCANNER_SECURE_COOKIES','0'))=='1', MAX_CONTENT_LENGTH=65536)
logger=get_logger('app')

@app.before_request
def request_security():
    jobs.cleanup_expired_guest_scans()
    session.pop('user_id',None)
    g.user=None
    if request.endpoint not in ('static','health') and not session.get('guest_id'):
        session['guest_id']=secrets.token_urlsafe(24)
    verify_csrf()

@app.after_request
def security_headers(response):
    response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'strict-origin-when-cross-origin',
      'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
      'Content-Security-Policy':"default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"})
    if request.is_secure: response.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    return response

app.jinja_env.globals['csrf_token']=csrf_token

@app.template_filter('datetime_short')
def datetime_short(value): return datetime.fromisoformat(value).astimezone().strftime('%b %d, %Y · %H:%M') if value else '—'
@app.template_filter('duration')
def duration(value):
    seconds=int(value or 0); return f'{seconds//60}m {seconds%60:02d}s' if seconds>=60 else f'{seconds}s'

@app.route('/login',methods=['GET','POST'])
def login(): return redirect(url_for('index'))

@app.route('/register',methods=['GET','POST'])
def register(): return redirect(url_for('index'))

@app.post('/logout')
def logout(): audit('logout'); session.clear(); return redirect(url_for('login'))

@app.post('/guest')
def guest_access():
    session.clear(); session['guest_id']=secrets.token_urlsafe(24); csrf_token(); return redirect(url_for('index'))

@app.post('/guest/end')
@scanner_access_required
def end_guest():
    jobs.delete_guest_scans(session.get('guest_id')); session.clear(); return redirect(url_for('login'))

@app.get('/')
def index(): return render_template('index.html',scans=[],nmap_available=nmap_available(),guest=True,hosted=bool(os.getenv('VERCEL')))

def scan_config_from_form():
    target=parse_target(request.form.get('target','')); profile=request.form.get('profile','fast'); engine=request.form.get('engine','socket')
    if engine not in ('socket','nmap') or engine=='nmap' and not nmap_available(): raise ValueError('The selected scan engine is unavailable.')
    presets={'fast':(1,1024,200),'quick':(1,100,120),'standard':(1,1024,200),'full':(1,65535,200)}
    if profile in presets and request.form.get('use_custom')!='1': start,end,threads=presets[profile]
    else: profile='custom'; start,end,threads=validate_scan_options(request.form.get('port_start'),request.form.get('port_end'),request.form.get('threads'))
    return target,{'port_start':start,'port_end':end,'threads':threads,'profile':profile,'engine':engine,'scheme':target['scheme'],'url_port':target['port']}

@app.post('/scans')
@scanner_access_required
def create_scan():
    actor=f'user:{g.user["id"]}' if g.user else f'guest:{session["guest_id"]}'
    if not rate_limit(f'scan:{actor}',10 if g.user else 3,3600): abort(429)
    if request.form.get('authorized')!='yes' and not app.testing: flash('Confirm that you are authorized to assess this target.','error'); return redirect(url_for('index'))
    try: target,config=scan_config_from_form()
    except ValueError as exc: return render_template('index.html',scans=[],nmap_available=nmap_available(),guest=True,hosted=bool(os.getenv('VERCEL')),error=str(exc)),400
    if os.getenv('VERCEL') and config['profile'] != 'fast':
        return render_template('index.html',scans=[],nmap_available=False,guest=True,hosted=True,
                               error='The hosted scanner supports Fast scans only. Use the self-hosted version for broader port ranges.'),400
    if not g.user: config['guest_id']=session['guest_id']
    job=jobs.create(target['host'],config,g.user['id'] if g.user else None); audit('scan.create',job['id'])
    if os.getenv('VERCEL'):
        _run(job['id'])
    else:
        submit(job['id'])
    return redirect(url_for('scan_detail',scan_id=job['id']))

@app.get('/history')
def history(): return redirect(url_for('index'))

def require_scan(scan_id):
    job=jobs.get(scan_id)
    owned = job and g.user and job.get('owner_id')==g.user['id']
    guest_owned = job and not g.user and session.get('guest_id') and job['config'].get('guest_id')==session['guest_id']
    if not owned and not guest_owned: abort(404)
    return job

@app.get('/scans/<scan_id>')
@scanner_access_required
def scan_detail(scan_id):
    job=require_scan(scan_id)
    return render_template('scan.html',scan=job,previous=None,comparison=None,hosted=bool(os.getenv('VERCEL')))

@app.get('/api/scans/<scan_id>')
@scanner_access_required
def scan_status(scan_id):
    job=require_scan(scan_id); return jsonify({k:job[k] for k in ('id','target','status','phase','progress','error','finished_at')})

@app.post('/scans/<scan_id>/cancel')
@scanner_access_required
def cancel_scan(scan_id):
    job=require_scan(scan_id)
    if job['status'] in ('queued','running'): jobs.request_cancel(scan_id); audit('scan.cancel',scan_id)
    return redirect(url_for('scan_detail',scan_id=scan_id))

def completed_scan(scan_id):
    job=require_scan(scan_id)
    if job['status']!='completed': abort(409)
    return job

@app.get('/scans/<scan_id>/report.json')
@scanner_access_required
def report_json(scan_id):
    response=make_response(json.dumps(completed_scan(scan_id),indent=2)); response.headers['Content-Type']='application/json'; response.headers['Content-Disposition']=f'attachment; filename="safescan-{scan_id}.json"'; return response

@app.get('/scans/<scan_id>/report.html')
@scanner_access_required
def report_html(scan_id):
    response=make_response(render_template('report.html',scan=completed_scan(scan_id))); response.headers['Content-Disposition']=f'attachment; filename="safescan-{scan_id}.html"'; return response

@app.get('/scans/<scan_id>/report.pdf')
@scanner_access_required
def report_pdf(scan_id):
    job=completed_scan(scan_id)
    try: from reportlab.lib.pagesizes import A4; from reportlab.pdfgen.canvas import Canvas
    except ImportError: abort(501,'PDF support is not installed.')
    output=io.BytesIO(); canvas=Canvas(output,pagesize=A4); _,height=A4; y=height-50; canvas.setTitle(f'SafeScan report - {job["target"]}'); canvas.setFont('Helvetica-Bold',18); canvas.drawString(45,y,'SafeScan Network Exposure Report'); y-=28; canvas.setFont('Helvetica',10)
    lines=[f'Target: {job["target"]}',f'Scan ID: {job["id"]}',f'Completed: {job["finished_at"]}','',f'Open ports: {job["result"]["summary"]["open_ports"]}    Findings: {job["result"]["summary"]["observations"]}','','Findings']
    for finding in job['result'].get('findings',[]): lines += [f'[{finding.get("severity","unknown").upper()}] {finding.get("title")}',f'Evidence: {finding.get("evidence")}',f'Remediation: {finding.get("remediation")}','']
    for line in lines:
        for segment in [line[i:i+105] for i in range(0,max(1,len(line)),105)]:
            if y<50: canvas.showPage(); canvas.setFont('Helvetica',10); y=height-50
            canvas.drawString(45,y,segment); y-=14
    canvas.save(); response=make_response(output.getvalue()); response.headers['Content-Type']='application/pdf'; response.headers['Content-Disposition']=f'attachment; filename="safescan-{scan_id}.pdf"'; return response

@app.route('/schedules',methods=['GET','POST'])
def schedules(): return redirect(url_for('index'))

@app.post('/schedules/<schedule_id>/delete')
def remove_schedule(schedule_id): return redirect(url_for('index'))

@app.get('/health')
def health(): return jsonify({'status':'ok'})

@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(409)
@app.errorhandler(429)
@app.errorhandler(500)
def friendly_error(error):
    code=getattr(error,'code',500); messages={400:'The request could not be verified.',404:'That page or assessment was not found.',409:'This action is not available for the current assessment.',429:'Too many requests. Please wait and try again.',500:'The application could not complete that request.'}
    return render_template('error.html',code=code,message=messages.get(code,messages[500])),code

if __name__=='__main__': app.run(host=os.getenv('SAFESCAN_HOST',os.getenv('VULNSCANNER_HOST','127.0.0.1')),port=int(os.getenv('PORT','5000')),debug=False)
