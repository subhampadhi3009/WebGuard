# WebGuard — Automated Web Security Scanner

**Author:** Subham Padhi | Cybersecurity Bootcamp Project

WebGuard is a Python-based passive web security scanner with an embedded
dark-themed web dashboard. Enter a public URL, click **Start Scan**, and
receive an instant security assessment of the site's HTTP response headers,
HTTPS configuration, and CORS settings — complete with explanations,
remediation guidance, a transparent A–F security score, and a downloadable
JSON report.

---

## Features

| Feature | Detail |
|---|---|
| **HTTPS check** | Verifies the final URL uses HTTPS |
| **Strict-Transport-Security** | Checks for HSTS header and reports the value |
| **Content-Security-Policy** | Detects presence of CSP (XSS mitigation) |
| **X-Content-Type-Options** | Checks for `nosniff` directive |
| **X-Frame-Options** | Validates `DENY` or `SAMEORIGIN` (clickjacking protection) |
| **Referrer-Policy** | Checks for a privacy-preserving referrer policy |
| **Permissions-Policy** | Detects optional browser feature restriction header |
| **CORS analysis** | Flags wildcard `Access-Control-Allow-Origin` for review |
| **Security score** | Transparent 0–100 score, graded A through F |
| **JSON export** | One-click download of the actual scan result |
| **SSRF protection** | Blocks private/loopback/reserved IP addresses and unsafe redirect destinations |
| **Response-body limit** | Reads at most 64 KB of the response body via streaming |
| **Single-file application** | HTML, CSS, and JavaScript are embedded in the Python file |

---

## Technologies

| Layer | Technology |
|---|---|
| Language | Python 3.10 or later |
| Web framework | Flask 3.1.1 |
| HTTP client | Requests >= 2.32.4 |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Report format | JSON (client-side export) |

---

## Prerequisites

- Python 3.10 or later — download from https://www.python.org/downloads/
- `pip` (included with Python)
- Internet connection (to scan public websites)

---

## Installation and setup (Windows)

Open **PowerShell** or **Command Prompt** in the project folder.

### Step 1 — (Recommended) Create a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\activate
```

### Step 2 — Install dependencies

```powershell
pip install -r requirements.txt
```

### Step 3 — Start the application

```powershell
python SubhamPadhi_WebGuard.py
```

You should see:

```
=======================================================
  WebGuard — Web Security Scanner  |  Subham Padhi
=======================================================
  Dashboard: http://127.0.0.1:5000
  Press Ctrl+C to stop the server.
=======================================================
```

### Step 4 — Open the dashboard

Go to **http://127.0.0.1:5000** in your browser.

Press `Ctrl+C` in the terminal to stop the server.

---

## Usage

1. Type a public website URL in the input field (e.g. `https://example.com`).
   You can omit `https://` — it will be added automatically.
2. Click **Start Scan** or press **Enter**.
3. Wait up to 10 seconds while the scanner fetches the site's response headers.
4. Review the security score, status badges, and expandable findings.
5. Click any check row to read the explanation and recommendation.
6. Click **Download JSON Report** to save the full scan result.

> **Important:** Only scan websites you own or have explicit permission to test.
> WebGuard makes a single, read-only HTTP GET request. It does not exploit,
> brute-force, or modify anything on the target.

---

## Running the automated test suite

The test files are temporary development files and are not part of the final
submission. If they are present in the same directory, run:

```powershell
python -m unittest _test_step4_audit _test_webguard -v
```

Expected output (last two lines):

```
Ran 146 tests in ~0.1s
OK
```

All 146 tests use mock HTTP responses — no real websites are scanned.

---

## Project structure

```
SubhamPadhi_WebGuard.py       ← Complete application (HTML/CSS/JS embedded)
requirements.txt               ← Python dependencies
SubhamPadhi_ProjectReport.docx ← Project report
README.md                      ← This file
```

---

## Security notes and limitations

**What the scanner does:**
- Makes one passive, read-only HTTP GET request per scan
- Inspects response headers only — no JavaScript execution, no form submission
- Blocks all private, loopback, link-local, and reserved IP addresses (SSRF protection)
- Re-validates every redirect destination before following it
- Enforces a 10-second request timeout and a 64 KB response-body limit

**Honest limitations:**
- **DNS rebinding (TOCTOU):** There is a small window between DNS resolution and the TCP connection. An attacker controlling DNS could return a public IP during the check and a private IP for the actual connection. Closing this fully requires socket-level IP binding, which is not implemented here.
- **Passive CORS only:** Wildcard `Access-Control-Allow-Origin` is flagged for review. Whether it is actually a risk depends on whether the endpoint serves authenticated data — something a passive scanner cannot determine.
- **Header presence, not semantic analysis:** The scanner checks whether recommended headers are present. It does not parse CSP policies in detail or evaluate HSTS max-age values.
- **Local development only:** The server binds to `127.0.0.1` only. Do not deploy on a public or shared network.

---

## Reference links

- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN HTTP Headers reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- Flask documentation: https://flask.palletsprojects.com/
- Python Requests library: https://requests.readthedocs.io/
- Python ipaddress module: https://docs.python.org/3/library/ipaddress.html

---

## Disclaimer

WebGuard is a learning project for authorized, defensive security testing only.
Only scan websites you own or have explicit written permission to test.
The author accepts no responsibility for any misuse.
