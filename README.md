# Automated Web Scanner

## Project description
Automated Web Scanner is a defensive Python tool that reviews selected HTTP security headers and CORS response headers for a website you own or have permission to assess. It reports observations and recommendations and can save findings as JSON.

## Dataset
No dataset is required. The scanner reviews live HTTP response headers from an authorized target. For unit tests, use mocked HTTP responses rather than scanning third-party websites.

## Technologies used
- Python 3
- `requests` for HTTP requests
- `streamlit` for a dashboard (optional; not included in this submission)
- `pytest` for testing
- JSON for report export

## Main file
- `Bhumika_AutomatedWebScanner.py` — scanner and analysis logic
- `requirements.txt` — Python dependencies
- `Bhumika_AutomatedWebScanner_ProjectReport.docx` — project report

## Setup

Create and activate a virtual environment.

**Windows**
```bash
python -m venv .venv
.venv\\Scripts\\activate
```

**macOS/Linux**
```bash
python -m venv .venv
source .venv/bin/activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## Run the scanner
Only scan a website you own or have explicit permission to assess.

```bash
python Bhumika_AutomatedWebScanner.py https://example.com --output scan_report.json
```

The output JSON includes the scan timestamp, requested URL, final URL, HTTP status code, findings, observed header values, recommendations, and a limitation notice.

## Checks performed
- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Access-Control-Allow-Origin
- Access-Control-Allow-Credentials
- Access-Control-Allow-Methods

## Safety and limitations
Scan only systems you own or have explicit permission to assess. Findings are indicators, not proof of a vulnerability. This is not a full penetration test and does not crawl every route, authenticate, or test application logic. Headers can vary by path, method, session, CDN, or server configuration. DNS validation alone is not a complete defense against DNS rebinding unless the connection is pinned to the validated address.

## References
- MDN HTTP headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- MDN CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- Python documentation: https://docs.python.org/3/
- Requests documentation: https://requests.readthedocs.io/
- Streamlit documentation: https://docs.streamlit.io/
