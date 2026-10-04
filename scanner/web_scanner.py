from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
import requests

COMMON_DIRS = ['admin', 'login', 'dashboard', '.git', 'config', 'backup', 'wp-admin', 'uploads']
SQLI_TESTS = ["'", '"', "' OR '1'='1", '" OR "1"="1', "';--"]
XSS_TEST = '<safescan-probe>reflection-check</safescan-probe>'
SQLI_ERROR_PATTERNS = ['you have an error in your sql syntax', 'warning: mysql',
                       'unclosed quotation mark after the character string', 'sqlite error']


def query_url(url, key, value):
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != key]
    query.append((key, value))
    return urlunsplit(parts._replace(query=urlencode(query), fragment=''))


class WebScanner:
    def __init__(self, timeout=8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SafeScan/2.0'})

    def scan_http(self, target):
        results = {'target': target, 'status': 'complete', 'headers': {}, 'robots': None,
                   'dirs': [], 'findings': [], 'errors': []}

        def get(url):
            try:
                # Report redirects without silently moving probes to another endpoint.
                return self.session.get(url, timeout=self.timeout, allow_redirects=False)
            except requests.RequestException as exc:
                results['errors'].append({'url': url, 'reason': type(exc).__name__})
                results['status'] = 'partial'
                return None

        baseline = get(target)
        if baseline is None:
            results['status'] = 'failed'
            return results
        results['headers'] = dict(baseline.headers)
        results['http_status'] = baseline.status_code
        if not 200 <= baseline.status_code < 300:
            results['status'] = 'skipped'
            results['errors'].append({'url': target, 'reason': f'HTTP {baseline.status_code}; endpoint probes skipped.'})
            return results
        robots = get(urljoin(target, '/robots.txt'))
        if robots is not None and robots.status_code == 200:
            results['robots'] = robots.text[:2000]
        for directory in COMMON_DIRS:
            url = urljoin(target, '/' + directory)
            response = get(url)
            if response is not None and response.status_code in (200, 401, 403):
                results['dirs'].append({'path': directory, 'url': url, 'status': response.status_code})

        def finding(title, evidence, url, payload=None, confidence='low', severity='low', remediation='Review the evidence and confirm manually.', status='unverified'):
            results['findings'].append({'title': title, 'evidence': evidence, 'url': url,
                                        'payload': payload, 'confidence': confidence,
                                        'severity': severity, 'remediation': remediation,
                                        'category': 'web', 'status': status})

        security_headers = {name.lower(): value for name, value in baseline.headers.items()}
        checks = (('content-security-policy', 'Content Security Policy is missing', 'medium',
                   'Define a restrictive Content-Security-Policy appropriate for this application.'),
                  ('x-content-type-options', 'MIME sniffing protection is missing', 'low',
                   'Return X-Content-Type-Options: nosniff.'),
                  ('x-frame-options', 'Clickjacking protection header is missing', 'low',
                   'Set frame-ancestors in CSP or X-Frame-Options where framing is not required.'))
        for header, title, level, remediation in checks:
            if header not in security_headers:
                finding(title, f'{header} was absent from the baseline response.', target,
                        confidence='high', severity=level, remediation=remediation, status='observed')
        if urlsplit(target).scheme == 'https' and 'strict-transport-security' not in security_headers:
            finding('HSTS is missing', 'strict-transport-security was absent from the HTTPS response.', target,
                    confidence='high', severity='medium', remediation='Enable HSTS after confirming all subdomains support HTTPS.', status='observed')

        baseline_body = baseline.text.lower()
        for payload in SQLI_TESTS:
            url = query_url(target, 'q', payload)
            response = get(url)
            if response is None:
                continue
            body = response.text.lower()
            for pattern in SQLI_ERROR_PATTERNS:
                if pattern in body and pattern not in baseline_body:
                    finding('Possible SQL error disclosure', pattern, url, payload, severity='medium', remediation='Use parameterized queries and disable detailed database errors in responses.')
            # Quotes alone are too common to provide meaningful reflection evidence.
            if len(payload) > 2 and payload in response.text and payload not in baseline.text:
                finding('Input reflected in response', payload, url, payload, severity='informational', remediation='Review the reflection context and apply context-aware output encoding.')
        url = query_url(target, 'xss', XSS_TEST)
        response = get(url)
        if response is not None and XSS_TEST in response.text and XSS_TEST not in baseline.text:
            html = 'text/html' in response.headers.get('Content-Type', '').lower()
            finding('Potential unescaped HTML reflection' if html else 'Input reflected in response', XSS_TEST, url, XSS_TEST,
                    severity='medium' if html else 'informational', remediation='Apply context-aware output encoding and a restrictive Content Security Policy.')
        return results
