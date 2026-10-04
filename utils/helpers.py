import ipaddress
import re
from urllib.parse import urlsplit


def parse_target(raw):
    raw = raw.strip()
    if not raw or any(c.isspace() for c in raw):
        raise ValueError('Enter a valid IP address, hostname, or HTTP(S) URL.')
    try:
        return {'host': str(ipaddress.ip_address(raw)), 'scheme': None, 'port': None}
    except ValueError:
        pass
    try:
        parsed = urlsplit(raw if '://' in raw else '//' + raw)
        if parsed.scheme and parsed.scheme not in ('http', 'https'):
            raise ValueError()
        if parsed.username is not None or parsed.password is not None:
            raise ValueError()
        host, port = parsed.hostname, parsed.port
        if not host or port == 0:
            raise ValueError()
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            host = host.rstrip('.').encode('idna').decode('ascii').lower()
            if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
                raise ValueError()
            if re.fullmatch(r'[0-9.]+', host):
                raise ValueError()
        return {'host': host, 'scheme': parsed.scheme or None, 'port': port}
    except (ValueError, UnicodeError):
        raise ValueError('Enter a valid IP address, hostname, or HTTP(S) URL without credentials.') from None


def validate_scan_options(start, end, threads):
    try:
        start, end, threads = int(start), int(end), int(threads)
    except (ValueError, TypeError):
        raise ValueError('Ports and threads must be whole numbers.') from None
    if not 1 <= start <= end <= 65535:
        raise ValueError('Ports must be between 1 and 65535, with start no greater than end.')
    if not 1 <= threads <= 200:
        raise ValueError('Threads must be between 1 and 200.')
    return start, end, threads


def web_endpoints(target, services):
    host = target['host']
    authority = f'[{host}]' if ':' in host else host
    explicit_port = target['port'] or (443 if target['scheme'] == 'https' else 80)
    endpoints = []
    for service in services:
        port = service['port']
        scheme = service.get('service') if service.get('service') in ('http', 'https') else None
        if not scheme:
            scheme = {80: 'http', 8000: 'http', 8080: 'http', 443: 'https', 8443: 'https'}.get(port)
        if target['scheme'] and port == explicit_port:
            scheme = target['scheme']
        if scheme:
            endpoints.append(f'{scheme}://{authority}:{port}/')
    return endpoints
