import socket
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def finding(title, severity, evidence, endpoint, remediation, confidence='high'):
    return {'title': title, 'severity': severity, 'confidence': confidence, 'status': 'observed',
            'evidence': evidence, 'endpoint': endpoint, 'url': endpoint, 'remediation': remediation,
            'category': 'tls'}


def inspect_tls(endpoint, timeout=4):
    parsed = urlsplit(endpoint)
    if parsed.scheme != 'https':
        return None
    host, port = parsed.hostname, parsed.port or 443
    result = {'endpoint': endpoint, 'status': 'complete', 'protocol': None, 'cipher': None,
              'certificate': {}, 'trust': 'trusted', 'findings': [], 'errors': []}
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as exc:
        result['trust'] = 'untrusted'
        result['findings'].append(finding('TLS certificate validation failed', 'high',
            exc.verify_message, endpoint, 'Install a certificate trusted by clients with a valid hostname and complete chain.'))
    except (OSError, ssl.SSLError) as exc:
        result.update(status='failed', trust='unknown')
        result['errors'].append(type(exc).__name__)
        return result
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                result['protocol'] = secure.version()
                cipher = secure.cipher()
                result['cipher'] = cipher[0] if cipher else None
                der = secure.getpeercert(binary_form=True)
        if der:
            cert_path = None
            try:
                with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as cert_file:
                    cert_file.write(ssl.DER_cert_to_PEM_cert(der)); cert_path = cert_file.name
                cert = ssl._ssl._test_decode_cert(cert_path)
                result['certificate'] = {'subject': dict(x[0] for x in cert.get('subject', ())),
                                         'issuer': dict(x[0] for x in cert.get('issuer', ())),
                                         'not_before': cert.get('notBefore'), 'not_after': cert.get('notAfter'),
                                         'serial_number': cert.get('serialNumber')}
                if cert.get('notAfter'):
                    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), timezone.utc)
                    days = (expires - datetime.now(timezone.utc)).days
                    result['certificate']['days_remaining'] = days
                    if days < 0:
                        result['findings'].append(finding('TLS certificate expired', 'critical', f'Expired {abs(days)} days ago.', endpoint, 'Renew and deploy the certificate immediately.'))
                    elif days < 30:
                        result['findings'].append(finding('TLS certificate expires soon', 'medium', f'{days} days remaining.', endpoint, 'Renew the certificate before expiration.'))
            finally:
                if cert_path: Path(cert_path).unlink(missing_ok=True)
        if result['protocol'] in ('TLSv1', 'TLSv1.1'):
            result['findings'].append(finding('Deprecated TLS protocol negotiated', 'high', result['protocol'], endpoint, 'Disable TLS 1.0 and 1.1; require TLS 1.2 or newer.'))
    except (OSError, ssl.SSLError, ValueError) as exc:
        result['status'] = 'partial'; result['errors'].append(type(exc).__name__)
    return result
