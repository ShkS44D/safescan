import socket
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import requests
from app import app
from scanner.cve_lookup import CVELookup
from scanner.os_fingerprint import OSFingerprint
from scanner.port_scanner import PortScanner, identify_service
from scanner.web_scanner import WebScanner, XSS_TEST, query_url
from utils.helpers import parse_target, validate_scan_options, web_endpoints


def response(text='ordinary page', status=200, content_type='text/html'):
    return Mock(text=text, status_code=status, headers={'Content-Type': content_type})


class InputTests(unittest.TestCase):
    def test_target_forms(self):
        for raw, host in [('example.com/path', 'example.com'), ('https://EXAMPLE.com:8443/a', 'example.com'),
                          ('::1', '::1'), ('[::1]:8080', '::1'), ('https://[::1]:8443/', '::1')]:
            self.assertEqual(parse_target(raw)['host'], host)
        self.assertEqual(parse_target('https://example.com:8443')['port'], 8443)

    def test_invalid_targets(self):
        for raw in ('', 'a b', 'http://', 'http://[::1', 'ftp://example.com', 'http://user:pass@example.com',
                    'example.com:70000', '-bad.example', '999.999.999.999', 'example.com:0'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_target(raw)

    def test_ranges(self):
        self.assertEqual(validate_scan_options('1', '65535', '200'), (1, 65535, 200))
        for values in [('a', '2', '1'), ('', '2', '1'), (0, 1, 1), (2, 1, 1), (1, 65536, 1), (1, 2, 0), (1, 2, 201)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                validate_scan_options(*values)

    def test_invalid_post_never_starts_scan_and_preserves_form(self):
        app.testing = True
        with patch('app.jobs.create') as create:
            result = app.test_client().post('/scans', data={'target': 'example.com', 'profile': 'custom', 'use_custom': '1', 'port_start': 'abc', 'port_end': '2', 'threads': '1'})
        self.assertEqual(result.status_code, 400)
        self.assertIn(b'example.com', result.data)
        create.assert_not_called()

    def test_endpoint_selection(self):
        services = [{'port': port, 'service': 'unknown'} for port in (22, 80, 443, 8000, 8080, 8443)]
        self.assertEqual(web_endpoints(parse_target('::1'), services),
                         ['http://[::1]:80/', 'https://[::1]:443/', 'http://[::1]:8000/', 'http://[::1]:8080/', 'https://[::1]:8443/'])
        self.assertEqual(web_endpoints(parse_target('https://example.com:9443/a'), [{'port': 9443}]), ['https://example.com:9443/'])


class PortTests(unittest.TestCase):
    def test_dns_failure_is_validation_error(self):
        with patch('scanner.port_scanner.socket.getaddrinfo', side_effect=socket.gaierror()), patch('scanner.port_scanner.socket.socket') as sock:
            with self.assertRaisesRegex(ValueError, 'resolve'):
                PortScanner('missing.invalid').scan()
            sock.assert_not_called()

    def test_local_banner_service(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            server.settimeout(3)
            port = server.getsockname()[1]

            def serve():
                connection, _ = server.accept()
                with connection:
                    connection.sendall(b'SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n')

            worker = threading.Thread(target=serve)
            worker.start()
            scanner = PortScanner('127.0.0.1', port, port, 1)
            services = scanner.scan()
            worker.join(3)
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]['service'], 'ssh')
        self.assertEqual(services[0]['version'], '9.6p1')
        self.assertEqual(services[0]['confidence'], 'observed')
        self.assertGreaterEqual(services[0]['latency_ms'], 0)
        self.assertIn('OpenSSH', scanner.service_banners[port])

    def test_ipv6_address_and_one_resolution(self):
        sock = Mock()
        sock.connect_ex.return_value = 0
        sock.recv.return_value = b''
        with patch('scanner.port_scanner.socket.getaddrinfo', return_value=[(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 0, 0, 0))]) as dns, patch('scanner.port_scanner.socket.socket', return_value=sock) as factory:
            results = PortScanner('::1', 22, 22, 1).scan()
        dns.assert_called_once()
        factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        sock.connect_ex.assert_called_once_with(('::1', 22, 0, 0))
        self.assertEqual(results[0]['confidence'], 'port hint')

    def test_http_product_detection(self):
        result = identify_service(443, 'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0', True)
        self.assertEqual((result['service'], result['product'], result['version']), ('https', 'nginx', '1.24.0'))

    def test_custom_https_performs_tls_before_http(self):
        plain, secure, context = Mock(), Mock(), Mock()
        plain.connect_ex.return_value = 0
        secure.recv.return_value = b'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n'
        context.wrap_socket.return_value = secure
        scanner = PortScanner('example.test', 9443, 9443, 1, web_scheme='https', web_port=9443)
        scanner.address = (socket.AF_INET, '127.0.0.1')
        with patch('scanner.port_scanner.socket.socket', return_value=plain), patch('scanner.port_scanner.ssl.create_default_context', return_value=context):
            result = scanner._scan_port(9443)
        plain.sendall.assert_not_called()
        context.wrap_socket.assert_called_once_with(plain, server_hostname='example.test')
        self.assertIn(b'Host: example.test:9443', secure.sendall.call_args.args[0])
        self.assertEqual(result['service'], 'https')
        self.assertTrue(result['tls'])
        secure.close.assert_called_once()

    def test_failed_probe_preserves_open_port(self):
        sock = Mock()
        sock.connect_ex.return_value = 0
        sock.recv.side_effect = OSError('probe failed')
        scanner = PortScanner('127.0.0.1', 22, 22, 1)
        scanner.address = (socket.AF_INET, '127.0.0.1')
        with patch('scanner.port_scanner.socket.socket', return_value=sock):
            result = scanner._scan_port(22)
        self.assertEqual(result['state'], 'open')
        self.assertIsNotNone(result['probe_error'])

    def test_os_no_stale_banners_or_active_probe(self):
        scanner = OSFingerprint()
        with patch.object(scanner, '_scapy_ttl_fingerprint') as active:
            self.assertIn('Linux', scanner.fingerprint('host', banners={22: 'OpenSSH Ubuntu'})['result'])
            self.assertIn('Unknown', scanner.fingerprint('other')['result'])
            self.assertIn('Unknown', scanner.fingerprint('other', banners={80: 'nginx'})['result'])
        active.assert_not_called()


class WebTests(unittest.TestCase):
    def scan(self, responder):
        scanner = WebScanner()
        self.addCleanup(scanner.session.close)
        with patch.object(scanner.session, 'get', side_effect=responder):
            return scanner.scan_http('https://example.test:8443/')

    def test_ordinary_response_does_not_produce_quote_findings(self):
        result = self.scan(lambda *a, **k: response())
        self.assertFalse(any('reflected' in item['title'].lower() or 'sql' in item['title'].lower() for item in result['findings']))
        self.assertEqual(result['status'], 'complete')

    def test_baseline_sql_error_not_reported_as_injection(self):
        result = self.scan(lambda *a, **k: response('warning: mysql'))
        self.assertFalse(any('sql' in item['title'].lower() for item in result['findings']))

    def test_new_sql_error_is_unverified(self):
        result = self.scan(lambda url, **k: response('warning: mysql' if 'q=' in url else 'hello'))
        self.assertTrue(result['findings'])
        sql = [f for f in result['findings'] if f['title'] == 'Possible SQL error disclosure']
        self.assertTrue(sql and all(f['status'] == 'unverified' for f in sql))

    def test_html_reflection_and_escaping(self):
        def reflect(url, **kwargs):
            return response(parse_qs(urlsplit(url).query).get('xss', ['hello'])[0])
        result = self.scan(reflect)
        self.assertTrue(any(f['title'] == 'Potential unescaped HTML reflection' for f in result['findings']))
        escaped = self.scan(lambda url, **k: response(XSS_TEST.replace('<', '&lt;').replace('>', '&gt;')))
        self.assertFalse(any('reflection' in f['title'].lower() for f in escaped['findings']))

    def test_timeout_is_failure_not_clean_scan(self):
        result = self.scan(Mock(side_effect=requests.Timeout()))
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['errors'][0]['reason'], 'Timeout')

    def test_redirect_not_followed(self):
        responder = Mock(return_value=response(status=302))
        result = self.scan(responder)
        self.assertEqual(result['status'], 'skipped')
        self.assertEqual(responder.call_count, 1)
        self.assertFalse(responder.call_args.kwargs['allow_redirects'])

    def test_query_encoding(self):
        url = query_url('https://example.test/?a=one&q=old#fragment', 'q', "' & #")
        self.assertEqual(parse_qs(urlsplit(url).query), {'a': ['one'], 'q': ["' & #"]})
        self.assertEqual(urlsplit(url).fragment, '')


class CVETests(unittest.TestCase):
    def test_unknown_product_skips_network(self):
        with patch('scanner.cve_lookup.requests.get') as get:
            result = CVELookup().lookup_services([{'port': 80, 'banner': 'HTTP/1.1 200 OK'}])
        get.assert_not_called()
        self.assertEqual(result[80]['status'], 'skipped')

    def test_candidates_metrics_and_cache(self):
        reply = Mock(status_code=200)
        reply.json.return_value = {'vulnerabilities': [{'cve': {'id': 'CVE-TEST', 'descriptions': [{'lang': 'en', 'value': 'Example'}], 'metrics': {'cvssMetricV30': [{'cvssData': {'baseScore': 7.5}}]}}}]}
        with patch('scanner.cve_lookup.requests.get', return_value=reply) as get:
            result = CVELookup().lookup_services([{'port': p, 'product': 'nginx', 'version': '1.24.0'} for p in (80, 443)])
        get.assert_called_once()
        self.assertIn('cpe:2.3:a:nginx:nginx:1.24.0', get.call_args.kwargs['params']['virtualMatchString'])
        self.assertEqual(result[80]['candidates'][0]['status'], 'unverified')
        self.assertEqual(result[80]['candidates'][0]['score'], 7.5)

    def test_rate_limit_is_bounded_and_reported(self):
        with patch('scanner.cve_lookup.requests.get', return_value=Mock(status_code=429)) as get, patch('scanner.cve_lookup.time.sleep'):
            result = CVELookup().lookup_services([{'port': 80, 'product': 'nginx', 'version': '1.24.0'}])
        self.assertEqual(get.call_count, 3)
        self.assertEqual(result[80]['status'], 'failed')


class IntegrationTests(unittest.TestCase):
    def test_default_profile_is_fast(self):
        app.testing = True
        with patch('app.jobs.create', return_value={'id': 'fast123'}) as create, patch('app.submit'):
            result = app.test_client().post('/scans', data={'target': 'example.test'})
        self.assertEqual(result.status_code, 302)
        config = create.call_args.args[1]
        self.assertEqual((config['profile'], config['threads']), ('fast', 200))

    def test_post_creates_background_job_and_redirects(self):
        app.testing = True
        job = {'id': 'abc123'}
        with patch('app.jobs.create', return_value=job) as create, patch('app.submit') as submit:
            result = app.test_client().post('/scans', data={'target': 'https://example.test:8443/a', 'profile': 'quick'})
        self.assertEqual(result.status_code, 302)
        self.assertTrue(result.headers['Location'].endswith('/scans/abc123'))
        config = create.call_args.args[1]
        self.assertEqual((config['port_start'], config['port_end'], config['scheme'], config['url_port']), (1, 100, 'https', 8443))
        submit.assert_called_once_with('abc123')


if __name__ == '__main__':
    unittest.main()
