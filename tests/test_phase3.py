import ssl
import unittest
from unittest.mock import Mock, patch

from scanner.cve_lookup import CVELookup, applicability, cpe_for, version_in_match
from scanner.nmap_scanner import NmapScanner
from scanner.port_scanner import identify_service
from scanner.tls_scanner import inspect_tls
from scanner.web_scanner import WebScanner


class IdentityTests(unittest.TestCase):
    def test_service_identity_includes_cpe(self):
        result = identify_service(22, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu')
        self.assertEqual(result['product'], 'OpenSSH')
        self.assertEqual(result['cpe'], 'cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*')

    def test_supported_cpe_mapping(self):
        self.assertEqual(cpe_for('Apache httpd', '2.4.62'), 'cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*')
        self.assertIsNone(cpe_for('Unknown', '1.0'))

    def test_version_ranges(self):
        self.assertTrue(version_in_match('1.24.0', {'criteria': 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*', 'versionStartIncluding': '1.20.0', 'versionEndExcluding': '1.25.0'}))
        self.assertFalse(version_in_match('1.25.0', {'criteria': 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*', 'versionEndExcluding': '1.25.0'}))
        self.assertTrue(version_in_match('9.6p1', {'criteria': 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', 'versionStartIncluding': '9.6p1', 'versionEndExcluding': '9.7'}))

    def test_nvd_applicability(self):
        service = {'product': 'nginx', 'version': '1.24.0', 'cpe': cpe_for('nginx', '1.24.0')}
        cve = {'configurations': [{'nodes': [{'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*', 'versionEndIncluding': '1.24.0'}]}]}]}
        self.assertEqual(applicability(cve, service), 'applicable')
        service['version'] = '1.25.0'
        self.assertEqual(applicability(cve, service), 'unverified')

    def test_lookup_marks_applicable_and_adds_remediation(self):
        cve = {'id': 'CVE-TEST', 'descriptions': [{'lang': 'en', 'value': 'Test'}],
               'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 9.8, 'vectorString': 'CVSS:3.1/AV:N'}}]},
               'configurations': [{'nodes': [{'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'}]}]}]}
        response = Mock(status_code=200); response.json.return_value = {'vulnerabilities': [{'cve': cve}]}
        with patch('scanner.cve_lookup.requests.get', return_value=response):
            result = CVELookup().lookup_services([{'port': 80, 'product': 'nginx', 'version': '1.24.0'}])
        item = result[80]['candidates'][0]
        self.assertEqual((item['status'], item['severity'], item['confidence']), ('applicable', 'critical', 'high'))
        self.assertIn('upgrade nginx', item['remediation'])


class ConfigurationTests(unittest.TestCase):
    def test_missing_headers_are_observed_findings(self):
        response = Mock(status_code=200, text='page', headers={'Content-Type': 'text/html'})
        scanner = WebScanner(); self.addCleanup(scanner.session.close)
        with patch.object(scanner.session, 'get', return_value=response):
            result = scanner.scan_http('https://example.test/')
        titles = {item['title'] for item in result['findings']}
        self.assertIn('HSTS is missing', titles)
        self.assertTrue(all(item['remediation'] for item in result['findings']))
        self.assertTrue(all(item['status'] == 'observed' for item in result['findings'] if 'missing' in item['title'].lower()))

    def test_deprecated_negotiated_tls_is_reported(self):
        raw1, raw2, secure1, secure2, context1, context2 = (Mock() for _ in range(6))
        raw1.__enter__ = Mock(return_value=raw1); raw1.__exit__ = Mock(return_value=False)
        raw2.__enter__ = Mock(return_value=raw2); raw2.__exit__ = Mock(return_value=False)
        secure1.__enter__ = Mock(return_value=secure1); secure1.__exit__ = Mock(return_value=False)
        secure2.__enter__ = Mock(return_value=secure2); secure2.__exit__ = Mock(return_value=False)
        context1.wrap_socket.return_value = secure1; context2.wrap_socket.return_value = secure2
        secure2.version.return_value = 'TLSv1'; secure2.cipher.return_value = ('OLD-CIPHER', '', 0); secure2.getpeercert.return_value = None
        with patch('scanner.tls_scanner.socket.create_connection', side_effect=[raw1, raw2]), patch('scanner.tls_scanner.ssl.create_default_context', side_effect=[context1, context2]):
            result = inspect_tls('https://example.test:443/')
        self.assertTrue(any(item['title'] == 'Deprecated TLS protocol negotiated' for item in result['findings']))


class NmapTests(unittest.TestCase):
    def test_nmap_xml_maps_to_shared_service_model(self):
        xml = '''<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" version="1.24.0" tunnel="ssl"><cpe>cpe:/a:nginx:nginx:1.24.0</cpe></service></port></ports></host></nmaprun>'''
        completed = Mock(returncode=0, stdout=xml)
        with patch('scanner.nmap_scanner.available', return_value=True), patch('scanner.nmap_scanner.subprocess.run', return_value=completed) as run:
            services = NmapScanner('127.0.0.1', 443, 443).scan()
        self.assertEqual((services[0]['service'], services[0]['confidence']), ('https', 'nmap probe'))
        self.assertIn('--', run.call_args.args[0])
        self.assertEqual(run.call_args.args[0][-1], '127.0.0.1')


if __name__ == '__main__':
    unittest.main()
