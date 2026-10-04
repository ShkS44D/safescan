import shutil
import subprocess
import xml.etree.ElementTree as ET

from scanner.cve_lookup import cpe_for
from scanner.port_scanner import ScanCancelled


def available():
    return shutil.which('nmap') is not None


class NmapScanner:
    def __init__(self, target, start_port, end_port, timeout=300):
        self.target, self.start_port, self.end_port, self.timeout = target, start_port, end_port, timeout
        self.service_banners = {}

    def scan(self, progress_callback=None, should_cancel=None):
        if not available():
            raise ValueError('Nmap is not installed or is not available on PATH.')
        if should_cancel and should_cancel(): raise ScanCancelled()
        command = ['nmap', '-Pn', '-sV', '--version-light', '-p', f'{self.start_port}-{self.end_port}', '-oX', '-', '--', self.target]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired:
            raise ValueError('Nmap exceeded the scan time limit.') from None
        if should_cancel and should_cancel(): raise ScanCancelled()
        if completed.returncode not in (0, 1):
            raise ValueError('Nmap service discovery failed.')
        try:
            root = ET.fromstring(completed.stdout)
        except ET.ParseError:
            raise ValueError('Nmap returned invalid scan output.') from None
        address_node = root.find('.//address')
        address = address_node.get('addr') if address_node is not None else self.target
        services = []
        for port in root.findall('.//port'):
            if port.find('state').get('state') != 'open': continue
            info = port.find('service'); product = info.get('product') or None; version = info.get('version') or None
            banner = ' '.join(value for value in (product, version, info.get('extrainfo')) if value)
            number = int(port.get('portid'))
            service_name = info.get('name', 'unknown')
            if info.get('tunnel') == 'ssl' and service_name in ('http', 'http-alt'):
                service_name = 'https'
            elif service_name == 'http-alt':
                service_name = 'http'
            service = {'port': number, 'state': 'open', 'transport': port.get('protocol', 'tcp'),
                       'address': address or self.target, 'latency_ms': None, 'banner': banner, 'tls': info.get('tunnel') == 'ssl',
                       'probe_error': None, 'service': service_name, 'product': product, 'version': version,
                       'cpe': info.findtext('cpe') or cpe_for(product, version), 'confidence': 'nmap probe'}
            services.append(service); self.service_banners[number] = banner
        if progress_callback: progress_callback(self.end_port - self.start_port + 1, self.end_port - self.start_port + 1)
        return sorted(services, key=lambda item: item['port'])
