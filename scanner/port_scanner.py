import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.helpers import validate_scan_options


def identify_service(port, banner, tls=False):
    result = {'service': 'unknown', 'product': None, 'version': None, 'cpe': None, 'confidence': 'unknown'}
    if banner.startswith('SSH-'):
        result.update(service='ssh', confidence='observed')
    elif banner.startswith('HTTP/'):
        result.update(service='https' if tls else 'http', confidence='observed')
    signatures = ((r'OpenSSH[_/]([\w.]+)', 'OpenSSH', 'openbsd', 'openssh'),
                  (r'\bnginx/([\w.]+)', 'nginx', 'nginx', 'nginx'),
                  (r'\bApache/([\w.]+)', 'Apache httpd', 'apache', 'http_server'),
                  (r'\bMicrosoft-IIS/([\w.]+)', 'Microsoft IIS', 'microsoft', 'internet_information_services'),
                  (r'\bRedis server v=([\w.]+)', 'Redis', 'redis', 'redis'),
                  (r'\bPostgreSQL(?: server)? ([\w.]+)', 'PostgreSQL', 'postgresql', 'postgresql'),
                  (r'\bMySQL(?: server)?[ /-]([\w.]+)', 'MySQL', 'oracle', 'mysql'))
    for pattern, product, vendor, cpe_product in signatures:
        match = re.search(pattern, banner, re.I)
        if match:
            version = match.group(1)
            result.update(product=product, version=version, confidence='observed',
                          cpe=f'cpe:2.3:a:{vendor}:{cpe_product}:{version}:*:*:*:*:*:*:*')
            break
    if result['service'] == 'unknown':
        hint = {22: 'ssh', 80: 'http', 443: 'https', 8000: 'http', 8080: 'http', 8443: 'https'}.get(port)
        if hint:
            result.update(service=hint, confidence='port hint')
    return result


class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=100, timeout=1.0, web_scheme=None, web_port=None):
        self.target = target
        self.start_port, self.end_port, self.threads = validate_scan_options(start_port, end_port, threads)
        self.timeout = timeout
        self.service_banners = {}
        self.address = None
        self.web_scheme = web_scheme
        self.web_port = web_port or (443 if web_scheme == 'https' else 80)

    def _read_banner(self, sock):
        chunks = bytearray()
        deadline = time.monotonic() + self.timeout
        while len(chunks) < 16384 and time.monotonic() < deadline:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                data = sock.recv(min(4096, 16384 - len(chunks)))
            except socket.timeout:
                break
            if not data:
                break
            chunks.extend(data)
            if b'\r\n\r\n' in chunks:
                break
        return chunks.decode(errors='replace').strip()

    def _scan_port(self, port):
        family, ip = self.address
        address = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
        sock = socket.socket(family, socket.SOCK_STREAM)
        tls, banner = False, ''
        try:
            sock.settimeout(self.timeout)
            start = time.monotonic()
            if sock.connect_ex(address) != 0:
                return None
            latency = round((time.monotonic() - start) * 1000, 2)
            probe_error = None
            try:
                scheme = {80: 'http', 8000: 'http', 8080: 'http', 443: 'https', 8443: 'https'}.get(port)
                if self.web_scheme and port == self.web_port:
                    scheme = self.web_scheme
                if scheme == 'https':
                    context = ssl.create_default_context()
                    # Banner discovery accepts untrusted certificates; it does not assess trust.
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=self.target)
                    tls = True
                if scheme:
                    host = f'[{self.target}]' if ':' in self.target else self.target
                    sock.sendall(f'HEAD / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n'.encode())
                banner = self._read_banner(sock)
            except (OSError, ValueError):
                probe_error = 'Service probe failed; TCP connection succeeded.'
            result = {'port': port, 'state': 'open', 'transport': 'tcp', 'address': ip, 'latency_ms': latency, 'banner': banner, 'tls': tls, 'probe_error': probe_error}
            result.update(identify_service(port, banner, tls))
            return result
        except OSError:
            return None
        finally:
            sock.close()

    def scan(self, progress_callback=None, should_cancel=None):
        try:
            addresses = socket.getaddrinfo(self.target, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise ValueError('Could not resolve the target hostname. Check the target and DNS connection.') from None
        if not addresses:
            raise ValueError('No IP address was found for the target.')
        # One resolved address per scan; expose it in every service result.
        self.address = (addresses[0][0], addresses[0][4][0])
        self.service_banners = {}
        ports = range(self.start_port, self.end_port + 1)
        total = len(ports)
        services = []
        executor = ThreadPoolExecutor(max_workers=self.threads)
        futures = [executor.submit(self._scan_port, port) for port in ports]
        try:
            for done, future in enumerate(as_completed(futures), 1):
                if should_cancel and should_cancel():
                    raise ScanCancelled()
                service = future.result()
                if service:
                    services.append(service)
                if progress_callback and (done == total or done % max(1, total // 100) == 0):
                    progress_callback(done, total)
        except ScanCancelled:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            executor.shutdown()
        services.sort(key=lambda service: service['port'])
        self.service_banners = {s['port']: s['banner'] for s in services}
        return services
class ScanCancelled(Exception):
    pass


