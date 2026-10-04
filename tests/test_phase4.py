import tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from app import app
from scanner import jobs
from scanner.operations import compare_results, validate_webhook
from security import create_user, password_hash, password_valid

class ProductionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.db_patch=patch.object(jobs,'DB_PATH',Path(self.temp.name)/'app.db'); self.db_patch.start(); jobs.initialize(); app.testing=True; self.client=app.test_client()
    def tearDown(self): self.db_patch.stop(); self.temp.cleanup()
    def test_password_hash_is_salted_and_verified(self):
        first,password=password_hash('correct horse battery staple'),'correct horse battery staple'
        self.assertNotEqual(first,password_hash(password)); self.assertTrue(password_valid(password,first)); self.assertFalse(password_valid('wrong',first))
    def test_anonymous_redirect_and_owned_scan_access(self):
        app.testing=False
        try: self.assertEqual(self.client.get('/history').status_code,302)
        finally: app.testing=True
    def test_security_headers(self):
        response=self.client.get('/health'); self.assertEqual(response.headers['X-Frame-Options'],'DENY'); self.assertIn("default-src 'self'",response.headers['Content-Security-Policy'])
    def test_comparison(self):
        old={'findings':[{'category':'tls','title':'Old','endpoint':'x'},{'category':'web','title':'Same','url':'u'}]}; new={'findings':[{'category':'web','title':'Same','url':'u'},{'category':'cve','title':'New','endpoint':'x'}]}
        result=compare_results(new,old); self.assertEqual((len(result['new']),len(result['resolved']),len(result['unchanged'])),(1,1,1))
    def test_private_webhook_is_rejected(self):
        with patch('scanner.operations.socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaisesRegex(ValueError,'public'): validate_webhook('https://localhost/hook')
    def test_guest_scan_is_isolated_and_removed_on_exit(self):
        app.testing=False
        try:
            first=app.test_client(); second=app.test_client()
            with first.session_transaction() as state: state['guest_id']='guest-one'; state['_csrf']='token'
            with second.session_transaction() as state: state['guest_id']='guest-two'; state['_csrf']='token'
            job=jobs.create('example.test',{'profile':'quick','port_start':1,'port_end':100,'threads':10,'engine':'socket','guest_id':'guest-one'},None)
            self.assertEqual(first.get(f'/scans/{job["id"]}').status_code,200)
            self.assertEqual(second.get(f'/scans/{job["id"]}').status_code,404)
            response=first.post('/guest/end',data={'_csrf':'token'})
            self.assertEqual(response.status_code,302); self.assertIsNone(jobs.get(job['id']))
        finally: app.testing=True

if __name__=='__main__': unittest.main()
