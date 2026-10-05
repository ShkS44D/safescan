import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from scanner.cve_lookup import CVELookup
from scanner.jobs import get, recover_interrupted, update, utc_now
from scanner.os_fingerprint import OSFingerprint
from scanner.port_scanner import COMMON_PORTS, PortScanner, ScanCancelled
from scanner.nmap_scanner import NmapScanner
from scanner.tls_scanner import inspect_tls
from scanner.web_scanner import WebScanner
from scanner.operations import notify_completed
from utils.helpers import web_endpoints

_workers = ThreadPoolExecutor(max_workers=2, thread_name_prefix='scan-job')
_active = set()
_lock = threading.Lock()


def submit(scan_id):
    with _lock:
        if scan_id in _active:
            return
        _active.add(scan_id)
    future = _workers.submit(_run, scan_id)
    future.add_done_callback(lambda _: _active.discard(scan_id))


def _run(scan_id):
    job = get(scan_id)
    if not job or job['status'] != 'queued':
        return
    if job['cancel_requested']:
        update(scan_id, status='cancelled', phase='Cancelled', finished_at=utc_now())
        return
    config = job['config']

    def cancelled():
        current = get(scan_id)
        return not current or current['cancel_requested']

    try:
        update(scan_id, status='running', phase='Resolving target', progress=2, started_at=utc_now())
        fast = config.get('profile') == 'fast'
        # Keep hosted analysis short without changing the selected port range.
        lightweight = fast or bool(os.getenv('VERCEL'))
        if config.get('engine') == 'nmap':
            scanner = NmapScanner(job['target'], config['port_start'], config['port_end'])
        else:
            fast_ports = set(COMMON_PORTS)
            if config.get('url_port'):
                fast_ports.add(config['url_port'])
            scanner = PortScanner(job['target'], config['port_start'], config['port_end'], config['threads'],
                                  timeout=0.35 if lightweight else 0.6, web_scheme=config.get('scheme'),
                                  web_port=config.get('url_port'), ports=fast_ports if fast else None)

        def port_progress(done, total):
            if cancelled():
                raise ScanCancelled()
            update(scan_id, phase=f'Scanning TCP ports · {done:,}/{total:,}', progress=5 + int(55 * done / total))

        services = scanner.scan(progress_callback=port_progress, should_cancel=cancelled)
        if cancelled():
            raise ScanCancelled()
        update(scan_id, phase='Identifying services and OS', progress=64)
        os_info = OSFingerprint().fingerprint(job['target'], [s['port'] for s in services], banners=scanner.service_banners)
        endpoints = web_endpoints({'host': job['target'], 'scheme': config.get('scheme'), 'port': config.get('url_port')}, services)
        web_results = []
        update(scan_id, phase='Inspecting web endpoints', progress=68)
        def inspect_web(endpoint):
            scanner = WebScanner(timeout=3 if lightweight else 4)
            try: return scanner.scan_http(endpoint, deep=not lightweight)
            finally: scanner.session.close()
        with ThreadPoolExecutor(max_workers=min(4, max(1, len(endpoints)))) as endpoint_workers:
            web_futures = [endpoint_workers.submit(inspect_web, endpoint) for endpoint in endpoints]
            for future in as_completed(web_futures):
                if cancelled(): raise ScanCancelled()
                web_results.append(future.result())
        update(scan_id, phase='Inspecting TLS configuration', progress=82)
        tls_endpoints = [endpoint for endpoint in endpoints if endpoint.startswith('https://')]
        with ThreadPoolExecutor(max_workers=min(4, max(1, len(tls_endpoints)))) as tls_workers:
            tls_results = list(tls_workers.map(inspect_tls, tls_endpoints))
        if cancelled():
            raise ScanCancelled()
        update(scan_id, phase='Looking up CVE candidates', progress=84)
        cve_results = CVELookup(api_key=os.getenv('NVD_API_KEY'), rate_limit_sleep=0 if lightweight else 2,
                                max_attempts=1 if lightweight else 2, timeout=4 if lightweight else 6).lookup_services(services)
        if cancelled():
            raise ScanCancelled()
        started = get(scan_id)['started_at']
        duration = max(0, (datetime.now(timezone.utc) - datetime.fromisoformat(started)).total_seconds())
        findings = [finding for web in web_results for finding in web['findings']]
        findings.extend(finding for tls in tls_results if tls for finding in tls['findings'])
        applicable = 0
        service_by_port = {service['port']: service for service in services}
        for port, lookup in cve_results.items():
            for candidate in lookup['candidates']:
                if candidate['status'] == 'applicable':
                    applicable += 1
                    identity = service_by_port[port]
                    findings.append({'title': candidate['id'], 'severity': candidate['severity'],
                                     'confidence': candidate['confidence'], 'status': 'applicable',
                                     'evidence': f"{identity['product']} {identity['version']} matches an NVD vulnerable CPE range.",
                                     'endpoint': f"{job['target']}:{port}", 'url': '', 'remediation': candidate['remediation'], 'category': 'cve'})
        severity_counts = {level: sum(1 for finding in findings if finding.get('severity') == level)
                           for level in ('critical', 'high', 'medium', 'low', 'informational')}
        result = {'services': services, 'os_info': os_info, 'web_results': web_results, 'tls_results': tls_results,
                  'findings': findings, 'severity_counts': severity_counts,
                  'cve_results': {str(key): value for key, value in cve_results.items()},
                  'summary': {'open_ports': len(services), 'web_endpoints': len(endpoints),
                              'observations': len(findings), 'applicable_cves': applicable,
                              'cve_candidates': sum(len(v['candidates']) for v in cve_results.values()),
                              'duration_seconds': round(duration, 1)}}
        update(scan_id, result=result, status='completed', phase='Completed', progress=100, finished_at=utc_now())
        notify_completed(get(scan_id))
    except ScanCancelled:
        update(scan_id, status='cancelled', phase='Cancelled', finished_at=utc_now())
    except Exception as exc:
        update(scan_id, status='failed', phase='Failed', error=str(exc) or type(exc).__name__, finished_at=utc_now())


for _scan_id in recover_interrupted():
    submit(_scan_id)
