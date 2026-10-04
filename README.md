# SafeScan

SafeScan is an evidence-first network exposure assessment platform for authorized security testing. It provides account-isolated scan history, TCP discovery, service and CPE identification, web/TLS checks, version-aware NVD matching, recurring assessments, change comparison, webhook notifications, and HTML/JSON/PDF reporting.

## Production setup

1. Copy `.env.example` to `.env` and set a long random `SAFESCAN_SECRET_KEY`.
2. Install dependencies with `pip install -r requirements.txt`.
3. Run behind HTTPS with `waitress-serve --host=127.0.0.1 --port=5000 app:app`, or build the included Docker image.
4. Set `SAFESCAN_SECURE_COOKIES=1` whenever HTTPS is enabled.
5. Optionally set `NVD_API_KEY` and install Nmap for stronger service detection.

The bundled SQLite database is appropriate for a single-node deployment. Use one application process so the built-in scheduler and worker remain coordinated. A distributed deployment should replace the local job runner and database with a shared queue and managed database.

## Security model

- Every assessment and report is scoped to its owner.
- Passwords use PBKDF2-HMAC-SHA256 with 600,000 iterations and unique salts.
- State changes require CSRF tokens; login and scan creation are throttled.
- Webhook destinations must use HTTPS and resolve only to public addresses.
- Responses include a restrictive content security policy and standard browser hardening headers.
- Users must affirm authorization before starting an assessment.

A Flask prototype for TCP service discovery, banner-based OS estimates, unverified NVD CVE candidates, and basic web observations.

## Run

Python 3.10 or newer:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000. On macOS/Linux, activate with `source .venv/bin/activate`.
Optionally set `NVD_API_KEY` in the environment before starting the application.

## Phase 1 behavior

- Validates IPv4, IPv6, hostnames, HTTP(S) URLs, port ranges, and a concurrency limit of 1–200. Invalid input returns HTTP 400 and preserves form values.
- Resolves the target once for the TCP scan and scans the first returned address. DNS failure stops the scan with an actionable error.
- Returns structured open-service records: address, port, transport, state, latency, banner, TLS handshake status, service, product/version, confidence, and probe errors.
- Distinguishes observed protocols from port-number hints. Recognizes OpenSSH, nginx, Apache httpd, and Microsoft IIS version strings; banners are claims, not authenticated identities.
- Passes the current scan's banners to OS estimation. Generic Apache/nginx/OpenSSH banners do not establish an OS. Active Scapy TTL probing is disabled in the web workflow.
- Probes HTTP on 80/8000/8080 and HTTPS on 443/8443, plus an explicitly supplied HTTP(S) URL port. Each open web endpoint receives its own results. URL paths are ignored and the explicit port must be inside the selected scan range.
- Performs TLS before HTTP on HTTPS endpoints. TLS banner discovery accepts untrusted certificates; web requests validate certificates and report failures. Neither is a full TLS security assessment.
- Reports SQL error patterns only when absent from the baseline. Reflections are observations, never confirmed SQL injection or executable XSS. HTML reflection uses an inert custom tag.
- Encodes query parameters correctly. Redirects are reported without following them; non-2xx baseline responses skip input probes.
- Searches NVD only when a recognized product and version are available. Candidate CVEs remain unverified keyword results, not confirmed affected versions. Missing identity, API failure, and zero candidates have different states. Rate-limit retries are bounded and repeated product queries reuse a per-scan cache.
- Renders evidence as escaped text and shows partial/failed/skipped web checks separately from completed checks.

## Phase 2 workflow

- `POST /scans` validates a scan request, stores it in SQLite, dispatches it to a two-worker background pool, and redirects immediately to a progress page.
- Progress is persisted by phase and percentage. The page polls a small JSON endpoint and refreshes into the final result when work finishes.
- A running scan can be cancelled. Pending port tasks are cancelled and the terminal state is retained in history.
- History persists in `data/scans.db`. A scan interrupted by an application restart is marked failed; queued work is submitted again at startup.
- Results use separate overview, service, web, CVE-candidate, and raw-evidence views. The layout is responsive and tables scroll on narrow screens.
- Completed scans export as JSON or a standalone printable HTML report. The HTML report can be printed or saved as PDF from a browser.
- Scan profiles provide quick (1–100), standard (1–1024), full (1–65535), and custom ranges.

The background pool is intentionally local and lightweight. It is suitable for this prototype and a single application process. A multi-process or distributed deployment should replace it with a durable task queue.

## Phase 3 assessment

- Banner signatures normalize OpenSSH, nginx, Apache httpd, Microsoft IIS, Redis, PostgreSQL, and MySQL into product, version, and CPE 2.3 identities.
- NVD requests use `virtualMatchString` with the normalized CPE. Returned configurations are inspected for matching vendor/product and exact or bounded vulnerable versions.
- CVEs are marked `applicable` only when the observed version satisfies an NVD vulnerable CPE match. Other returned entries remain `unverified`.
- Findings use a shared model containing severity, confidence, status, evidence, affected endpoint, category, and remediation.
- HTTP checks cover CSP, HSTS, MIME sniffing protection, clickjacking protection, SQL error disclosure, and input/HTML reflection.
- HTTPS endpoints receive a TLS trust, negotiated protocol, cipher, certificate expiration, and deprecated-protocol assessment.
- Nmap service discovery is an optional engine. It appears unavailable in the interface when `nmap` is not installed on `PATH`; the built-in scanner remains the default.
- Dashboard and exported reports include severity counts, applicable CVEs, CPE evidence, TLS results, and remediation guidance.

## Tests

```powershell
python -m unittest discover -s tests -v
```

Tests use mocked web/NVD responses and a temporary loopback TCP server. No external targets are scanned.

## Current limitations

Only open TCP services are returned by the built-in engine; connection failures are not classified as closed versus filtered. One resolved address is scanned; web and TLS checks resolve the hostname independently. Directory responses may be wildcard/custom error pages. CPE mappings cover a limited product set, and NVD applicability does not prove exploitability or account for vendor backports. Job execution is local to one process and provides no distributed worker guarantees.

The current app has no authentication or target restrictions and its development server binds to all interfaces. Use it in a controlled environment against systems you are authorized to assess. Public deployment hardening belongs to the later deployment phase.
