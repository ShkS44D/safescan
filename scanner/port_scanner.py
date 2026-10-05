"""Fast TCP connect scanning and conservative service identification."""

from __future__ import annotations

import os
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

# Vercel's Python runtime cannot reliably create 400 native threads. At 160
# workers, a 1,000-port chunk still completes within the function time budget.
SCAN_THREADS = int(os.getenv("SAFESCAN_SCAN_THREADS", "160"))
CONNECT_TIMEOUT = float(os.getenv("SAFESCAN_CONNECT_TIMEOUT", "0.8"))
BANNER_TIMEOUT = float(os.getenv("SAFESCAN_BANNER_TIMEOUT", "1.0"))
BANNER_LIMIT = 200

HTTP_PORTS = {
    80,
    81,
    443,
    3000,
    5000,
    7001,
    8000,
    8008,
    8080,
    8081,
    8088,
    8181,
    8443,
    8888,
    9000,
    9090,
    9200,
    9443,
    10000,
}
TLS_HTTP_PORTS = {443, 8443, 9443}
PORT_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    1883: "mqtt",
    2049: "nfs",
    2375: "docker",
    2379: "etcd",
    3000: "http",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    6443: "kubernetes-api",
    8000: "http",
    8008: "http",
    8080: "http-proxy",
    8081: "http",
    8443: "https",
    8888: "http",
    9000: "http",
    9090: "http",
    9200: "elasticsearch",
    10250: "kubelet",
    11211: "memcached",
    15672: "rabbitmq-management",
    27017: "mongodb",
}

PRODUCT_PATTERNS = (
    (re.compile(r"OpenSSH[_/]([\w.p-]+)", re.IGNORECASE), "OpenSSH", "ssh"),
    (re.compile(r"nginx/([\w.-]+)", re.IGNORECASE), "nginx", "http"),
    (re.compile(r"Apache(?:/| httpd )([\w.-]+)", re.IGNORECASE), "Apache httpd", "http"),
    (re.compile(r"Microsoft-IIS/([\w.-]+)", re.IGNORECASE), "Microsoft IIS", "http"),
    (re.compile(r"lighttpd/([\w.-]+)", re.IGNORECASE), "lighttpd", "http"),
    (re.compile(r"Postfix", re.IGNORECASE), "Postfix", "smtp"),
    (re.compile(r"Exim(?:\s+|/)([\w.-]+)", re.IGNORECASE), "Exim", "smtp"),
    (re.compile(r"vsFTPd(?:\s+|/)([\w.-]+)", re.IGNORECASE), "vsftpd", "ftp"),
    (re.compile(r"ProFTPD(?:\s+|/)([\w.-]+)", re.IGNORECASE), "ProFTPD", "ftp"),
    (re.compile(r"Dovecot", re.IGNORECASE), "Dovecot", "imap"),
    (re.compile(r"Redis server v=([\w.-]+)", re.IGNORECASE), "Redis", "redis"),
)


def sanitize_banner(data: bytes | str) -> str:
    """Return a safe, compact banner excerpt."""
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    text = "".join(character if character.isprintable() else " " for character in text)
    return re.sub(r"\s+", " ", text).strip()[:BANNER_LIMIT]


def guessed_service(port: int) -> str:
    """Return a conventional service name for a port."""
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def identify_service(
    port: int, banner: str, mysql_version: str | None = None
) -> dict[str, str | None]:
    """Prefer observed protocol evidence, then fall back to a port guess."""
    lowered = banner.lower()
    service: str | None = None
    product: str | None = None
    version: str | None = None
    if mysql_version:
        service, product, version = "mysql", "MySQL/MariaDB", mysql_version
    elif banner.startswith("SSH-"):
        service = "ssh"
    elif banner.startswith("HTTP/") or " server:" in f" {lowered}":
        service = "https" if port in TLS_HTTP_PORTS else "http"
    elif banner.startswith("220"):
        service = "smtp" if port in {25, 465, 587} else "ftp"
    elif banner.startswith("+OK"):
        service = "pop3"
    elif re.match(r"^\*\s+(OK|PREAUTH)", banner, re.IGNORECASE):
        service = "imap"
    elif banner.startswith("+PONG") or "noauth" in lowered:
        service, product = "redis", "Redis"

    for pattern, detected_product, detected_service in PRODUCT_PATTERNS:
        match = pattern.search(banner)
        if match:
            product = detected_product
            service = service or detected_service
            version = match.group(1) if match.lastindex else version
            break
    if service in {"http", "https"}:
        server = re.search(r"(?:^|\s)Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
        if server:
            value = server.group(1).strip()
            match = re.match(r"([^/\s]+)(?:/([^\s]+))?", value)
            if match:
                product = product or match.group(1)
                version = version or match.group(2)
    if not service:
        return {
            "service": guessed_service(port),
            "product": None,
            "version": None,
            "confidence": "port-guess",
        }
    return {"service": service, "product": product, "version": version, "confidence": "banner"}


def _address(ip: str, port: int) -> tuple:
    address = socket.getaddrinfo(ip, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)[0]
    return address[0], address[4]


def _receive(sock: socket.socket, limit: int = 4096) -> bytes:
    sock.settimeout(BANNER_TIMEOUT)
    try:
        return sock.recv(limit)
    except (TimeoutError, OSError):
        return b""


def _probe_open_socket(sock: socket.socket, host: str, port: int) -> tuple[bytes, str | None]:
    initial = _receive(sock)
    mysql_version = None
    if initial and len(initial) > 5 and initial[4] == 10:
        mysql_version = initial[5:].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    if port == 6379 and not initial:
        sock.sendall(b"*1\r\n$4\r\nPING\r\n")
        initial = _receive(sock)
    if port in HTTP_PORTS:
        stream = sock
        if port in TLS_HTTP_PORTS:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                stream = context.wrap_socket(sock, server_hostname=host)
            except (OSError, ssl.SSLError):
                return initial, mysql_version
        authority = f"[{host}]" if ":" in host else host
        try:
            stream.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode()
            )
            response = _receive(stream)
            initial = response or initial
        except OSError:
            pass
    return initial, mysql_version


def scan_port(ip: str, host: str, port: int) -> dict[str, object] | None:
    """Connect to one TCP port and return evidence only when it is open."""
    family, destination = _address(ip, port)
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(CONNECT_TIMEOUT)
        if sock.connect_ex(destination) != 0:
            return None
        data, mysql_version = _probe_open_socket(sock, host, port)
        banner = sanitize_banner(data)
        identity = identify_service(port, banner, mysql_version)
        return {"port": port, "state": "open", "banner": banner, **identity}
    except OSError:
        return None
    finally:
        sock.close()


def scan_ports(ip: str, host: str, start: int, end: int) -> list[dict[str, object]]:
    """Connect-scan an inclusive range using a bounded thread pool."""
    workers = min(SCAN_THREADS, end - start + 1)
    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tcp-scan") as executor:
        futures = [executor.submit(scan_port, ip, host, port) for port in range(start, end + 1)]
        for future in as_completed(futures):
            service = future.result()
            if service:
                results.append(service)
    return sorted(results, key=lambda item: int(item["port"]))
