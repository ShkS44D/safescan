"""Stateless Flask application for the SafeScan public TCP port scanner."""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict, deque
from typing import Any

from flask import Flask, jsonify, render_template, request

from scanner.port_scanner import scan_ports
from utils.netguard import normalize_target, require_public_ip, resolve_public_target

RATE_LIMIT_REQUESTS = int(os.getenv("SAFESCAN_RATE_LIMIT_REQUESTS", "150"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("SAFESCAN_RATE_LIMIT_WINDOW", "60"))
MAX_CHUNK_PORTS = 2_000

app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=16_384)
logger = logging.getLogger("safescan")

_rate_events: dict[str, deque[float]] = defaultdict(deque)
_rate_lock = threading.Lock()


def json_error(message: str, status: int) -> tuple[Any, int]:
    """Return a consistent JSON error response."""
    return jsonify({"error": message}), status


def client_ip() -> str:
    """Return the direct peer address without trusting forwarded headers."""
    return request.remote_addr or "unknown"


def within_rate_limit(address: str) -> bool:
    """Apply a best-effort per-process request limit."""
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    with _rate_lock:
        events = _rate_events[address]
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) >= RATE_LIMIT_REQUESTS:
            return False
        events.append(now)
        return True


def require_json() -> tuple[dict[str, Any] | None, tuple[Any, int] | None]:
    """Read a JSON object or return an API error."""
    if not request.is_json:
        return None, json_error("Content-Type must be application/json.", 400)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return None, json_error("Request body must be a JSON object.", 400)
    return body, None


@app.after_request
def security_headers(response):
    """Add browser protections without enabling cross-origin API access."""
    response.headers.update(
        {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": (
                "default-src 'self'; style-src 'self'; script-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                "base-uri 'self'; form-action 'self'"
            ),
        }
    )
    return response


@app.get("/")
def index():
    """Render the scanner interface."""
    return render_template("index.html")


@app.post("/api/resolve")
def resolve_target():
    """Validate a target, resolve it once, and reject unsafe DNS answers."""
    if not within_rate_limit(client_ip()):
        return json_error("Too many requests. Please wait a moment and try again.", 429)
    body, error = require_json()
    if error:
        return error
    try:
        host = normalize_target(body.get("target"))
        ip, ips = resolve_public_target(host)
    except ValueError as exc:
        return json_error(str(exc), 400)
    return jsonify({"host": host, "ip": ip, "ips": ips})


@app.post("/api/scan")
def scan_chunk():
    """Scan one client-selected TCP port chunk."""
    if not within_rate_limit(client_ip()):
        return json_error("Too many requests. Please wait a moment and try again.", 429)
    body, error = require_json()
    if error:
        return error
    if body.get("authorized") is not True:
        return json_error("Confirm that you have permission to scan this target.", 400)
    try:
        ip = require_public_ip(body.get("ip"), allow_private=app.testing)
        host = normalize_target(body.get("host"))
        start = int(body.get("start"))
        end = int(body.get("end"))
    except (TypeError, ValueError) as exc:
        message = str(exc) or "Start and end ports must be whole numbers."
        return json_error(message, 400)
    if not 1 <= start <= end <= 65_535:
        return json_error("Ports must satisfy 1 <= start <= end <= 65535.", 400)
    if end - start + 1 > MAX_CHUNK_PORTS:
        return json_error("A scan request can contain at most 2,000 ports.", 400)
    try:
        services = scan_ports(ip=ip, host=host, start=start, end=end)
    except Exception:
        logger.exception("Port scan chunk failed for client %s", client_ip())
        return json_error("The scan chunk could not be completed.", 500)
    return jsonify({"start": start, "end": end, "scanned": end - start + 1, "open": services})


@app.get("/health")
def health():
    """Return service health."""
    return jsonify({"status": "ok"})


@app.errorhandler(404)
def not_found(_error):
    return json_error("Not found.", 404)


@app.errorhandler(405)
def method_not_allowed(_error):
    return json_error("Method not allowed.", 405)


@app.errorhandler(500)
def internal_error(_error):
    return json_error("The request could not be completed.", 500)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host=os.getenv("SAFESCAN_HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")))
