import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app import app
from scanner import jobs
from scanner.scan_manager import _run


class PhaseTwoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(jobs, 'DB_PATH', Path(self.temp.name) / 'scans.db')
        self.db_patch.start()
        jobs.initialize()
        app.testing = True
        self.client = app.test_client()

    def tearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def create_job(self):
        return jobs.create('example.test', {'port_start': 1, 'port_end': 100, 'threads': 10,
                                            'profile': 'quick', 'scheme': None, 'url_port': None})

    def result(self):
        return {'services': [{'port': 80, 'transport': 'tcp', 'service': 'http', 'product': 'nginx',
                              'version': '1.24.0', 'confidence': 'observed', 'latency_ms': 1.2,
                              'banner': '<script>unsafe</script>', 'address': '127.0.0.1', 'tls': False,
                              'probe_error': None}],
                'os_info': {'result': 'Unknown', 'confidence': 'unknown', 'method': 'banner_heuristic'},
                'web_results': [{'target': 'http://example.test:80/', 'findings': [], 'headers': {},
                                 'robots': None, 'dirs': [], 'status': 'complete', 'errors': []}],
                'cve_results': {'80': {'status': 'complete', 'message': 'Unverified.', 'candidates': []}},
                'summary': {'open_ports': 1, 'web_endpoints': 1, 'observations': 0,
                            'cve_candidates': 0, 'duration_seconds': 2.1}}

    def test_job_store_roundtrip_and_history(self):
        first = self.create_job()
        second = jobs.create('second.test', first['config'])
        jobs.update(first['id'], status='completed', phase='Completed', progress=100,
                    result=self.result(), finished_at=jobs.utc_now())
        stored = jobs.get(first['id'])
        self.assertEqual(stored['result']['summary']['open_ports'], 1)
        self.assertEqual([item['id'] for item in jobs.list_recent()], [second['id'], first['id']])
        page = self.client.get('/history')
        self.assertEqual(page.status_code, 302)
        self.assertEqual(page.headers['Location'], '/')

    def test_progress_api_and_cancel(self):
        job = self.create_job()
        jobs.update(job['id'], status='running', phase='Scanning TCP ports', progress=42)
        payload = self.client.get(f"/api/scans/{job['id']}").get_json()
        self.assertEqual((payload['status'], payload['progress']), ('running', 42))
        response = self.client.post(f"/scans/{job['id']}/cancel")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(jobs.get(job['id'])['cancel_requested'])

    def test_completed_dashboard_escapes_evidence_and_exports(self):
        job = self.create_job()
        jobs.update(job['id'], status='completed', phase='Completed', progress=100,
                    result=self.result(), finished_at=jobs.utc_now())
        page = self.client.get(f"/scans/{job['id']}")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'Open ports', page.data)
        self.assertIn(b'&lt;script&gt;unsafe&lt;/script&gt;', page.data)
        self.assertNotIn(b'<script>unsafe</script>', page.data)
        report = self.client.get(f"/scans/{job['id']}/report.json")
        self.assertEqual(report.status_code, 200)
        self.assertIn('attachment;', report.headers['Content-Disposition'])
        self.assertEqual(json.loads(report.data)['id'], job['id'])
        html = self.client.get(f"/scans/{job['id']}/report.html")
        self.assertIn(b'Print / Save as PDF', html.data)

    def test_unfinished_report_is_rejected(self):
        job = self.create_job()
        self.assertEqual(self.client.get(f"/scans/{job['id']}/report.json").status_code, 409)

    def test_worker_completes_all_phases(self):
        job = self.create_job()
        services = [{'port': 22, 'banner': 'SSH-2.0-OpenSSH_9.6p1', 'service': 'ssh'}]
        scanner = Mock(service_banners={22: services[0]['banner']})

        def scan(progress_callback, should_cancel):
            progress_callback(1, 1)
            return services

        scanner.scan.side_effect = scan
        web = Mock()
        web.session.close = Mock()
        with patch('scanner.scan_manager.PortScanner', return_value=scanner), \
             patch('scanner.scan_manager.OSFingerprint') as osfp, \
             patch('scanner.scan_manager.WebScanner', return_value=web), \
             patch('scanner.scan_manager.web_endpoints', return_value=[]), \
             patch('scanner.scan_manager.CVELookup') as cve:
            osfp.return_value.fingerprint.return_value = {'result': 'Linux', 'method': 'banner', 'confidence': 'low'}
            cve.return_value.lookup_services.return_value = {22: {'status': 'skipped', 'message': 'No version', 'candidates': []}}
            _run(job['id'])
        stored = jobs.get(job['id'])
        self.assertEqual((stored['status'], stored['progress'], stored['phase']), ('completed', 100, 'Completed'))
        self.assertEqual(stored['result']['summary']['open_ports'], 1)
        web.session.close.assert_not_called()

    def test_worker_honors_prestart_cancellation(self):
        job = self.create_job()
        jobs.request_cancel(job['id'])
        with patch('scanner.scan_manager.PortScanner') as scanner:
            _run(job['id'])
        self.assertEqual(jobs.get(job['id'])['status'], 'cancelled')
        scanner.assert_not_called()

    def test_recovery_marks_running_failed_and_returns_queued(self):
        queued = self.create_job()
        running = jobs.create('running.test', queued['config'])
        jobs.update(running['id'], status='running')
        self.assertEqual(jobs.recover_interrupted(), [queued['id']])
        self.assertEqual(jobs.get(running['id'])['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
