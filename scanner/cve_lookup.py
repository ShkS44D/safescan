import re
import time
import requests

PRODUCT_CPE = {'openssh': ('openbsd', 'openssh'), 'nginx': ('nginx', 'nginx'),
               'apache httpd': ('apache', 'http_server'), 'microsoft iis': ('microsoft', 'internet_information_services'),
               'redis': ('redis', 'redis'), 'postgresql': ('postgresql', 'postgresql'), 'mysql': ('oracle', 'mysql')}


def cpe_for(product, version):
    identity = PRODUCT_CPE.get((product or '').lower())
    return f'cpe:2.3:a:{identity[0]}:{identity[1]}:{version}:*:*:*:*:*:*:*' if identity and version else None


def version_key(value):
    return tuple((0, int(token)) if token.isdigit() else (1, token.lower())
                 for token in re.findall(r'\d+|[a-zA-Z]+', value or ''))


def version_in_match(version, match):
    criteria = match.get('criteria', '').split(':')
    exact, current = criteria[5] if len(criteria) > 5 else '*', version_key(version)
    if exact not in ('*', '-') and version_key(exact) != current:
        return False
    bounds = (('versionStartIncluding', lambda a, b: a >= b), ('versionStartExcluding', lambda a, b: a > b),
              ('versionEndIncluding', lambda a, b: a <= b), ('versionEndExcluding', lambda a, b: a < b))
    return all(key not in match or compare(current, version_key(match[key])) for key, compare in bounds)


def applicability(cve, service):
    expected = (service.get('cpe') or cpe_for(service.get('product'), service.get('version')) or '').split(':')
    if len(expected) < 6:
        return 'unverified'

    def matches(nodes):
        for node in nodes or []:
            for item in node.get('cpeMatch', []):
                candidate = item.get('criteria', '').split(':')
                if item.get('vulnerable') and len(candidate) >= 6 and candidate[2:5] == expected[2:5] and version_in_match(service['version'], item):
                    return True
            if matches(node.get('nodes')):
                return True
        return False
    return 'applicable' if matches(cve.get('configurations')) else 'unverified'


def severity(score):
    if score is None: return 'unknown'
    if score >= 9: return 'critical'
    if score >= 7: return 'high'
    if score >= 4: return 'medium'
    if score > 0: return 'low'
    return 'informational'


class CVELookup:
    NVD_BASE = 'https://services.nvd.nist.gov/rest/json'

    def __init__(self, api_key=None, rate_limit_sleep=6, max_attempts=3):
        self.api_key, self.rate_limit_sleep, self.max_attempts = api_key, rate_limit_sleep, max_attempts

    def _nvd_get(self, params):
        for attempt in range(self.max_attempts):
            try:
                response = requests.get(f'{self.NVD_BASE}/cves/2.0', params=params,
                                        headers={'apiKey': self.api_key} if self.api_key else {}, timeout=10)
                if response.status_code == 200: return response.json(), None
                if response.status_code != 429: return None, f'NVD returned HTTP {response.status_code}.'
            except (requests.RequestException, ValueError): return None, 'NVD lookup could not be completed.'
            if attempt + 1 < self.max_attempts: time.sleep(self.rate_limit_sleep * (2 ** attempt))
        return None, 'NVD rate limit reached; retry later.'

    def lookup_services(self, services):
        results, cache = {}, {}
        for service in services:
            port = service['port']
            cpe = service.get('cpe') or cpe_for(service.get('product'), service.get('version'))
            if not cpe:
                results[port] = {'status': 'skipped', 'message': 'No normalized product and version identity; lookup skipped.', 'cpe': None, 'candidates': []}
                continue
            if cpe not in cache:
                if cache: time.sleep(self.rate_limit_sleep)
                data, error = self._nvd_get({'virtualMatchString': cpe, 'resultsPerPage': 50})
                candidates = []
                for item in (data or {}).get('vulnerabilities', []):
                    cve = item.get('cve', {}); metrics = cve.get('metrics', {}); score = vector = None
                    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                        if metrics.get(key):
                            cvss = metrics[key][0].get('cvssData', {}); score, vector = cvss.get('baseScore'), cvss.get('vectorString'); break
                    status = applicability(cve, service)
                    candidates.append({'id': cve.get('id'), 'desc': next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), ''),
                                       'score': score, 'severity': severity(score), 'vector': vector, 'status': status,
                                       'confidence': 'high' if status == 'applicable' else 'low',
                                       'remediation': f'Confirm the affected range for {cve.get("id")} and upgrade {service.get("product")} to a fixed supported release.'})
                cache[cpe] = {'status': 'failed' if error else 'complete', 'cpe': cpe,
                              'message': error or 'CPE-matched results. Applicable means the detected version satisfies an NVD vulnerable CPE range; confirm before remediation.',
                              'candidates': candidates}
            results[port] = cache[cpe]
        return results
