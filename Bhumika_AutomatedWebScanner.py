"""Automated Web Scanner: defensive HTTP security-header and CORS review.

Use only on websites you own or have explicit permission to assess.
This is a basic configuration checker, not a full penetration test.
"""
import argparse
import ipaddress
import json
import socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

HEADERS = {
    "Content-Security-Policy": (
        "Controls allowed content sources.",
        "Define a restrictive policy suited to the application.",
    ),
    "Strict-Transport-Security": (
        "Encourages HTTPS on future visits.",
        "Enable after confirming HTTPS works throughout the domain.",
    ),
    "X-Content-Type-Options": (
        "Helps prevent MIME sniffing.",
        "Set to nosniff.",
    ),
    "X-Frame-Options": (
        "Can help reduce clickjacking risk.",
        "Use DENY or SAMEORIGIN when appropriate; review CSP frame-ancestors.",
    ),
    "Referrer-Policy": (
        "Controls referrer information sent by browsers.",
        "Choose a privacy-conscious policy suited to the site.",
    ),
    "Permissions-Policy": (
        "Restricts selected browser features.",
        "Limit features the application does not need.",
    ),
}

TIMEOUT = 8
MAX_REDIRECTS = 3
MAX_CONTENT_LENGTH = 1_000_000


class ScanError(ValueError):
    """Raised when a URL is invalid, unsafe, or cannot be scanned."""


def validate_url(url):
    """Validate a URL and reject local, private, and non-public destinations."""
    if not isinstance(url, str) or not url.strip():
        raise ScanError("Enter a URL.")

    cleaned = url.strip()
    parsed = urlparse(cleaned)

    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ScanError("Only complete HTTP/HTTPS URLs are allowed.")
    if parsed.username or parsed.password:
        raise ScanError("URLs containing embedded credentials are not allowed.")

    host = parsed.hostname.rstrip(".")
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        raise ScanError("Localhost is blocked.")

    try:
        # A literal IP address does not need DNS resolution.
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = {ipaddress.ip_address(info[4][0]) for info in infos}
        except (socket.gaierror, ValueError, OSError) as exc:
            raise ScanError(f"Hostname resolution failed: {exc}") from exc

    if not addresses or any(not address.is_global for address in addresses):
        raise ScanError(
            "Private, local, link-local, and reserved addresses are blocked."
        )
    return cleaned


def fetch_response(url):
    """Fetch one response, validating each redirect destination."""
    current = validate_url(url)
    session = requests.Session()
    session.headers["User-Agent"] = "AutomatedWebScanner/1.0 (authorized audit)"

    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = session.get(
                current,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as exc:
            session.close()
            raise ScanError(f"Request failed: {exc}") from exc

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                session.close()
                raise ScanError("Redirect had no Location header.")
            try:
                current = validate_url(urljoin(current, location))
            except ScanError:
                session.close()
                raise
            continue

        content_length = response.headers.get("Content-Length")
        if content_length and content_length.isdigit():
            if int(content_length) > MAX_CONTENT_LENGTH:
                response.close()
                session.close()
                raise ScanError("Response exceeds the 1 MB configured limit.")
        # The body is not consumed; stream=True avoids downloading it.
        response.close()
        session.close()
        # Return a small response-like object containing only what this tool uses.
        return {
            "status_code": response.status_code,
            "headers": response.headers,
        }, current

    session.close()
    raise ScanError("Too many redirects.")


def analyze_headers(headers, final_url):
    """Create observations and recommendations for selected headers."""
    normalized = {key.lower(): value.strip() for key, value in headers.items()}
    findings = []
    is_https = urlparse(final_url).scheme.lower() == "https"

    for name, (purpose, recommendation) in HEADERS.items():
        value = normalized.get(name.lower())
        if name == "Strict-Transport-Security" and not is_https:
            status = "Not applicable"
            detail = "HSTS is meaningful when served over HTTPS."
        elif value:
            status = "Present"
            detail = "Observed value: " + value[:250]
        else:
            status = "Missing"
            detail = "Header was not observed in this response."

        findings.append({
            "category": "Security header",
            "name": name,
            "status": status,
            "purpose": purpose,
            "observed_value": value,
            "recommendation": recommendation,
            "detail": detail,
        })

    origin = normalized.get("access-control-allow-origin")
    credentials = normalized.get("access-control-allow-credentials")
    methods = normalized.get("access-control-allow-methods")

    if origin == "*" and credentials and credentials.lower() == "true":
        cors_status = "Review combination"
        cors_detail = (
            "Wildcard origin and credentials=true observed. Browsers reject this "
            "combination for credentialed CORS responses; review related endpoints."
        )
    elif origin == "*":
        cors_status = "Review wildcard"
        cors_detail = "Confirm that public cross-origin access is intended."
    elif origin:
        cors_status = "Origin configured"
        cors_detail = "Observed origin: " + origin[:250]
    else:
        cors_status = "Not observed"
        cors_detail = "No Access-Control-Allow-Origin header in this response."

    findings.extend([
        {
            "category": "CORS",
            "name": "Access-Control-Allow-Origin",
            "status": cors_status,
            "purpose": "Controls which origins may read responses in browsers.",
            "observed_value": origin,
            "recommendation": (
                "Allow only trusted origins required by the application; "
                "do not reflect arbitrary origins."
            ),
            "detail": cors_detail,
        },
        {
            "category": "CORS",
            "name": "Access-Control-Allow-Credentials",
            "status": "Present" if credentials else "Not observed",
            "purpose": "Indicates whether credentials may be included in CORS requests.",
            "observed_value": credentials,
            "recommendation": (
                "Enable only when needed and use explicit trusted origins."
            ),
            "detail": (
                "Observed: " + credentials
                if credentials else "Header not observed."
            ),
        },
        {
            "category": "CORS",
            "name": "Access-Control-Allow-Methods",
            "status": "Present" if methods else "Not observed",
            "purpose": "Lists methods allowed for cross-origin requests.",
            "observed_value": methods,
            "recommendation": "Allow only methods required by the application.",
            "detail": "Observed: " + methods if methods else "Header not observed.",
        },
    ])
    return findings


def scan_website(url):
    """Scan a single authorized URL and return a JSON-serializable report."""
    response, final_url = fetch_response(url)
    return {
        "project": "Automated Web Scanner",
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url,
        "final_url": final_url,
        "http_status_code": response["status_code"],
        "findings": analyze_headers(response["headers"], final_url),
        "notice": (
            "Configuration observations only, not proof of a vulnerability. "
            "Scan authorized sites only."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Review security headers and CORS on an authorized website."
    )
    parser.add_argument("url", help="Authorized public HTTP/HTTPS website")
    parser.add_argument("--output", default="scan_report.json")
    args = parser.parse_args()

    try:
        report = scan_website(args.url)
    except ScanError as exc:
        raise SystemExit(f"Scan stopped: {exc}") from exc

    with open(args.output, "w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2)
    print("Report saved to", args.output)


if __name__ == "__main__":
    main()
