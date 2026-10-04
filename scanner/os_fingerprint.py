# scanner/os_fingerprint.py
import re
from utils.logger import get_logger
try:
    from scapy.all import sr1, IP, TCP, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

logger = get_logger('os_fingerprint')

class OSFingerprint:
    """
    Lightweight OS fingerprinting helper.
    Uses scapy TTL/window heuristics when available, otherwise uses banner heuristics.
    """

    def __init__(self):
        self.heuristics = [
            (r'Ubuntu|Debian|Linux', 'Linux (banner)'),
            (r'Windows', 'Windows (banner)'),
            (r'Microsoft-IIS', 'Windows (IIS)'),
        ]

    def _banner_heuristic(self, banners):
        for port, banner in (banners or {}).items():
            if not banner:
                continue
            for pat, name in self.heuristics:
                try:
                    if re.search(pat, banner, re.I):
                        return f"Heuristic -> {name} (detected on port {port})"
                except re.error:
                    continue
        return "Unknown from banner heuristics"

    def _scapy_ttl_fingerprint(self, target):
        if not SCAPY_AVAILABLE:
            return None
        try:
            conf.verb = 0
            pkt = IP(dst=target)/TCP(dport=80,flags='S')
            resp = sr1(pkt, timeout=2)
            if resp is None:
                return None
            ttl = getattr(resp, 'ttl', None)
            window = getattr(resp, 'window', None)
            if ttl is None:
                return None
            if ttl >= 128:
                return f"Likely Windows (observed TTL={ttl}, window={window})"
            if ttl >= 64:
                return f"Likely Linux/Unix (observed TTL={ttl}, window={window})"
            return f"Unknown (TTL={ttl}, window={window})"
        except Exception as e:
            logger.debug("Scapy TTL fingerprint error: %s", e)
            return None

    def fingerprint(self, target, open_ports=None, banners=None, active=False):
        """
        Return a dict: {'method': 'scapy_ttl'|'banner_heuristic', 'result': <string>}
        - `banners` should be a dict {port: banner_str} provided by the port scanner if available.
        """
        open_ports = open_ports or []
        # Try scapy TTL heuristic first (if available)
        try:
            scapy_guess = self._scapy_ttl_fingerprint(target) if active else None
            if scapy_guess:
                return {'method': 'scapy_ttl', 'result': scapy_guess, 'confidence': 'low'}
        except Exception:
            pass
        # Fallback to banner heuristics
        result = self._banner_heuristic(banners or {})
        return {'method': 'banner_heuristic', 'result': result, 'confidence': 'low' if banners and not result.startswith('Unknown') else 'unknown'}
