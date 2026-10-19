"""
WebGuard — Automated Web Security Scanner

Features:
  - URL validation with SSRF protection
  - HTTPS and HTTP security-header checks
  - Security scoring (grades A through F)
  - Response-body limit and redirect validation
  - Web dashboard with JSON report export

How to run:
    pip install -r requirements.txt
    python SubhamPadhi_WebGuard.py
"""

import ipaddress
import socket
import urllib.parse
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template_string, request

# ---------------------------------------------------------------------------
# Flask application instance
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ---------------------------------------------------------------------------
# SECTION 1 — SSRF protection helpers
# ---------------------------------------------------------------------------
# SSRF (Server-Side Request Forgery) is an attack where an outsider tricks
# your server into fetching an internal resource — e.g. http://127.0.0.1
# or http://192.168.1.1/admin.  Because WebGuard runs on YOUR machine and
# makes HTTP requests on your behalf, we must refuse any URL that resolves
# to a private or loopback address.
#
# Plan:
#   1. Parse the URL and extract the hostname.
#   2. Resolve the hostname to an IP address via DNS.
#   3. Check that IP against Python's ipaddress library.
#   4. If it is private / loopback / link-local / reserved → reject it.
# ---------------------------------------------------------------------------

# Maximum response body we read from the target (64 KB).
# This prevents a slow/huge response from hanging or exhausting memory.
MAX_RESPONSE_BYTES = 65_536  # 64 KB

# How many seconds before we give up on a connection or read.
REQUEST_TIMEOUT = 10  # seconds


def _is_ip_restricted(ip_str: str) -> bool:
    """
    Return True if the IP address string belongs to a range that should
    never be reachable from a public scanner.

    Covers: loopback (127.x), private RFC-1918, link-local (169.254.x),
    IPv6 loopback/link-local, and IANA-reserved blocks.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        # Unparseable — treat as restricted to be safe.
        return True

    return (
        addr.is_loopback        # 127.0.0.1, ::1
        or addr.is_private      # 10.x, 172.16-31.x, 192.168.x, fc00::/7
        or addr.is_link_local   # 169.254.x.x, fe80::/10
        or addr.is_reserved     # 0.0.0.0/8, 240.0.0.0/4, etc.
        or addr.is_multicast    # 224.x – 239.x
        or addr.is_unspecified  # 0.0.0.0, ::
    )


def _resolve_and_check(hostname: str) -> str | None:
    """
    Resolve *hostname* to an IP address and check it is not restricted.

    Returns the resolved IP string on success.
    Returns None if DNS fails or the IP is restricted.

    Why do this?  A hostname like "evil.example.com" could be set up in DNS
    to point to 192.168.1.1.  Checking the IP *after* DNS resolution catches
    that trick.
    """
    try:
        # getaddrinfo returns a list of (family, type, proto, canonname, sockaddr)
        # We only need the first result's IP address.
        results = socket.getaddrinfo(hostname, None)
        if not results:
            return None
        ip_str = results[0][4][0]
    except socket.gaierror:
        # DNS lookup failed (host does not exist or no network).
        return None

    if _is_ip_restricted(ip_str):
        return None  # Blocked — private or loopback

    return ip_str


# ---------------------------------------------------------------------------
# SECTION 2 — URL validation
# ---------------------------------------------------------------------------
# We accept only absolute URLs that begin with http:// or https://.
# Anything else (ftp://, file://, a bare domain, etc.) is rejected.
# ---------------------------------------------------------------------------

def validate_url(raw: str) -> tuple[bool, str, str]:
    """
    Validate a raw URL string entered by the user.

    Returns a 3-tuple: (is_valid, cleaned_url, error_message)
      - is_valid     : True if the URL passes all checks.
      - cleaned_url  : The normalised URL to use for scanning.
      - error_message: Human-readable reason if is_valid is False, else "".

    Checks performed:
      1. Not empty.
      2. Scheme is http or https.
      3. Has a non-empty hostname.
      4. Hostname resolves via DNS to a public IP address.
    """
    raw = raw.strip()
    if not raw:
        return False, "", "Please enter a URL."

    # Reject any URL that already contains a scheme other than http/https.
    # We check for "://" BEFORE prepending so that "ftp://example.com" or
    # "file:///etc/passwd" are caught here rather than being silently wrapped
    # in "https://ftp://..." which would parse as scheme=https.
    if "://" in raw and not raw.startswith(("http://", "https://")):
        return False, "", "Only http:// and https:// URLs are allowed."

    # If the user typed "example.com" without any scheme, add https://
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        return False, "", "The URL could not be parsed. Please check the format."

    if parsed.scheme not in ("http", "https"):
        return False, "", "Only http:// and https:// URLs are allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "", "The URL does not contain a valid hostname."

    # Resolve DNS and verify the IP is public.
    ip = _resolve_and_check(hostname)
    if ip is None:
        return (
            False, "",
            f"'{hostname}' could not be reached or resolves to a private / "
            "restricted address.  WebGuard only scans public internet hosts."
        )

    return True, raw, ""


# ---------------------------------------------------------------------------
# SECTION 3 — Security checks
# ---------------------------------------------------------------------------
# Each check is a small function that looks at the response and returns a
# dictionary describing the result.  Every dictionary has the same shape so
# the frontend can render them uniformly:
#
#   {
#     "id"        : "unique-key",
#     "name"      : "Human-readable check name",
#     "status"    : "pass" | "review" | "info",
#     "value"     : "The actual header value (or 'Not present')",
#     "detail"    : "What this header does and why it matters",
#     "remediation": "What the site owner could do to improve this"
#   }
#
# Status meanings:
#   pass   → The header is present and looks reasonable.
#   review → Something worth noting — not proof of a vulnerability.
#   info   → Informational only — no judgement implied.
# ---------------------------------------------------------------------------

def _hdr(headers: dict, name: str) -> str | None:
    """
    Case-insensitive header lookup.
    HTTP headers are case-insensitive (RFC 7230), but Python dicts are not.
    The Requests library already normalises headers, but we use this helper
    for clarity and safety.
    """
    return headers.get(name) or headers.get(name.lower())


def check_https(url: str) -> dict:
    """Check whether the URL uses HTTPS."""
    uses_https = url.startswith("https://")
    return {
        "id": "https",
        "name": "HTTPS",
        "status": "pass" if uses_https else "review",
        "value": "https://" if uses_https else "http://",
        "detail": (
            "HTTPS encrypts data between the browser and the server, "
            "preventing eavesdropping and tampering.  HTTP sends data in "
            "plain text — anyone on the same network can read it."
        ),
        "remediation": (
            ""
            if uses_https
            else "Configure the server to redirect HTTP to HTTPS and obtain "
                 "a TLS certificate (free options: Let's Encrypt)."
        ),
    }


def check_hsts(headers: dict) -> dict:
    """
    Strict-Transport-Security (HSTS) tells browsers to ALWAYS use HTTPS
    for this domain, even if the user types http://.
    """
    value = _hdr(headers, "Strict-Transport-Security")
    if value:
        status = "pass"
        detail_extra = f"Header value: {value}"
    else:
        status = "review"
        detail_extra = "Header is not present."

    return {
        "id": "hsts",
        "name": "Strict-Transport-Security (HSTS)",
        "status": status,
        "value": value or "Not present",
        "detail": (
            "HSTS prevents SSL-stripping attacks by instructing browsers to "
            "refuse plain HTTP connections.  "
            + detail_extra
        ),
        "remediation": (
            ""
            if value
            else "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ),
    }


def check_csp(headers: dict) -> dict:
    """
    Content-Security-Policy limits which scripts, styles, and resources the
    browser is allowed to load.  It is the primary defence against XSS.
    """
    value = _hdr(headers, "Content-Security-Policy")
    return {
        "id": "csp",
        "name": "Content-Security-Policy (CSP)",
        "status": "pass" if value else "review",
        "value": value or "Not present",
        "detail": (
            "CSP tells the browser exactly which sources are trusted for "
            "scripts, images, styles, and other resources.  Without CSP, "
            "injected scripts can run freely (cross-site scripting / XSS)."
        ),
        "remediation": (
            ""
            if value
            else "Define a Content-Security-Policy header.  Start with a "
                 "restrictive policy and relax it only as needed.  "
                 "Reference: https://content-security-policy.com/"
        ),
    }


def check_xcto(headers: dict) -> dict:
    """
    X-Content-Type-Options: nosniff stops browsers from guessing a file's
    type.  Without it, a browser might treat a text file as JavaScript.
    """
    value = _hdr(headers, "X-Content-Type-Options")
    correct = value and value.strip().lower() == "nosniff"
    return {
        "id": "xcto",
        "name": "X-Content-Type-Options",
        "status": "pass" if correct else "review",
        "value": value or "Not present",
        "detail": (
            "Prevents MIME-type sniffing.  When set to 'nosniff', the browser "
            "trusts the Content-Type the server declares and will not try to "
            "guess a different type.  This reduces the risk of content-type "
            "confusion attacks."
        ),
        "remediation": (
            ""
            if correct
            else "Add the header: X-Content-Type-Options: nosniff"
        ),
    }


def check_xfo(headers: dict) -> dict:
    """
    X-Frame-Options controls whether the page can be embedded in an
    <iframe>.  Clickjacking attacks load a page invisibly inside an iframe.
    """
    value = _hdr(headers, "X-Frame-Options")
    good_values = {"deny", "sameorigin"}
    correct = value and value.strip().lower() in good_values
    return {
        "id": "xfo",
        "name": "X-Frame-Options",
        "status": "pass" if correct else "review",
        "value": value or "Not present",
        "detail": (
            "Prevents the page from being embedded in an <iframe> on another "
            "origin.  Attackers use invisible iframes to trick users into "
            "clicking things on the real page (clickjacking).  "
            "Note: CSP's frame-ancestors directive is the modern replacement."
        ),
        "remediation": (
            ""
            if correct
            else "Add the header: X-Frame-Options: DENY  (or SAMEORIGIN if "
                 "you legitimately embed the page on the same domain)"
        ),
    }


def check_referrer_policy(headers: dict) -> dict:
    """
    Referrer-Policy controls how much URL information is sent to other sites
    when the user follows a link away from this page.
    """
    value = _hdr(headers, "Referrer-Policy")
    # These values give good privacy with minimal breakage.
    strong_values = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "same-origin",
    }
    correct = value and value.strip().lower() in strong_values
    return {
        "id": "referrer",
        "name": "Referrer-Policy",
        "status": "pass" if correct else "review",
        "value": value or "Not present",
        "detail": (
            "Controls how much referrer information (the URL the user came "
            "from) is shared with other sites.  Overly broad policies can "
            "leak sensitive URL parameters to third parties."
        ),
        "remediation": (
            ""
            if correct
            else "Add the header: Referrer-Policy: strict-origin-when-cross-origin"
        ),
    }


def check_permissions_policy(headers: dict) -> dict:
    """
    Permissions-Policy (formerly Feature-Policy) restricts which browser
    features a page and its iframes are allowed to use (camera, microphone, etc).
    """
    value = _hdr(headers, "Permissions-Policy")
    return {
        "id": "permissions",
        "name": "Permissions-Policy",
        "status": "pass" if value else "info",
        "value": value or "Not present",
        "detail": (
            "Allows the site owner to control which powerful browser APIs "
            "(camera, microphone, geolocation, etc.) the page — and embedded "
            "iframes — may use.  Its absence is informational; not every site "
            "needs to restrict these features explicitly."
        ),
        "remediation": (
            ""
            if value
            else "Consider adding Permissions-Policy to restrict features you "
                 "do not use, e.g.: Permissions-Policy: geolocation=(), camera=()"
        ),
    }


def check_cors(headers: dict) -> dict:
    """
    CORS (Cross-Origin Resource Sharing) lets a server say which other
    origins are allowed to read its responses via JavaScript.

    A wildcard  Access-Control-Allow-Origin: *  means ANY website's JS can
    read the response.  That is fine for public APIs but risky for pages
    that carry user-specific data.

    Important limitation: we can only see what headers the server returns on
    a normal GET request.  A full CORS audit would require sending preflight
    OPTIONS requests and testing authenticated endpoints — beyond the scope
    of a passive scanner.
    """
    acao = _hdr(headers, "Access-Control-Allow-Origin")
    acac = _hdr(headers, "Access-Control-Allow-Credentials")

    if acao is None:
        return {
            "id": "cors",
            "name": "CORS — Access-Control-Allow-Origin",
            "status": "info",
            "value": "Not present",
            "detail": (
                "No CORS headers were found on this response.  This is normal "
                "for pages that are not designed to be accessed by cross-origin "
                "JavaScript.  A missing header does not indicate a problem."
            ),
            "remediation": "",
        }

    # Wildcard + credentials is explicitly forbidden by the spec, but some
    # misconfigurations come close (e.g. reflecting the Origin header + credentials).
    is_wildcard = acao.strip() == "*"
    has_credentials = acac and acac.strip().lower() == "true"

    if is_wildcard and has_credentials:
        status = "review"
        detail_extra = (
            "WARNING: Access-Control-Allow-Origin: * combined with "
            "Access-Control-Allow-Credentials: true is forbidden by the CORS "
            "spec and would be rejected by browsers, but may indicate a "
            "misconfigured server."
        )
        remediation = (
            "Remove the wildcard and specify explicit trusted origins, "
            "or remove Access-Control-Allow-Credentials."
        )
    elif is_wildcard:
        status = "review"
        detail_extra = (
            "The server allows any origin to read this response.  This is "
            "appropriate for public APIs but should be reviewed for pages "
            "that serve authenticated or user-specific content."
        )
        remediation = (
            "If this endpoint serves authenticated data, replace * with an "
            "explicit list of trusted origins."
        )
    else:
        status = "pass"
        detail_extra = f"Specific origin(s) allowed: {acao}"
        remediation = ""

    return {
        "id": "cors",
        "name": "CORS — Access-Control-Allow-Origin",
        "status": status,
        "value": acao,
        "detail": (
            "Cross-Origin Resource Sharing controls which JavaScript from "
            "other websites may read this server's responses.  "
            + detail_extra
        ),
        "remediation": remediation,
    }


# ---------------------------------------------------------------------------
# SECTION 4 — Score calculation
# ---------------------------------------------------------------------------
# The score is calculated solely from the checks we actually ran.
# Each "pass" contributes its full weight; "review" contributes half;
# "info" earns 0 points but its weight IS still added to 'possible',
# so a site that receives an info check without passing it scores slightly
# lower than if the check were absent.  This rewards sites that actively
# configure optional headers like Permissions-Policy.
#
# This is transparent — the user can see exactly how the number was reached.
# ---------------------------------------------------------------------------

SCORE_WEIGHTS = {
    "https":       20,   # Most important — no HTTPS = serious problem
    "hsts":        15,
    "csp":         15,
    "xcto":        10,
    "xfo":         10,
    "referrer":    10,
    "permissions":  5,   # Nice-to-have; lower weight
    "cors":        15,
}


def calculate_score(checks: list[dict]) -> dict:
    """
    Given the list of check result dicts, return a score summary.

    Returns:
        {
            "score"    : int   (0-100),
            "max"      : int   (total possible from scored checks),
            "grade"    : str   ("A" / "B" / "C" / "D" / "F"),
            "earned"   : int   (points earned),
        }
    """
    earned = 0
    possible = 0

    for chk in checks:
        weight = SCORE_WEIGHTS.get(chk["id"], 0)
        if weight == 0:
            continue  # "info"-only check — skip from scoring

        possible += weight
        if chk["status"] == "pass":
            earned += weight
        elif chk["status"] == "review":
            earned += weight // 2
        # "info" → 0 points either way

    if possible == 0:
        pct = 0
    else:
        pct = round((earned / possible) * 100)

    if pct >= 90:
        grade = "A"
    elif pct >= 75:
        grade = "B"
    elif pct >= 60:
        grade = "C"
    elif pct >= 40:
        grade = "D"
    else:
        grade = "F"

    return {"score": pct, "max": 100, "grade": grade, "earned": earned, "possible": possible}


# ---------------------------------------------------------------------------
# SECTION 5 — Main scanner function
# ---------------------------------------------------------------------------
# This is the function that ties everything together.
# It is called by the Flask route /api/scan (see below).
# ---------------------------------------------------------------------------

def run_scan(url: str) -> dict:
    """
    Fetch the target URL and run all security checks.

    Parameters:
        url : A pre-validated, normalised URL string.

    Returns a dict with:
        "url"       : the target URL
        "timestamp" : ISO-8601 UTC time of the scan
        "status_code": HTTP response status code (or None on error)
        "error"     : error message string (or None on success)
        "checks"    : list of check result dicts
        "score"     : score summary dict
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # -- Build a Session with a custom redirect handler -------------------
    # We use requests.Session so we can hook into redirect handling.
    # By default, requests follows redirects automatically.  We want to
    # re-validate the destination IP after every redirect.
    session = requests.Session()

    # Disable automatic redirects so we can inspect each one manually.
    # We will follow up to 5 redirects ourselves.
    MAX_REDIRECTS = 5

    try:
        response = None
        current_url = url
        for redirect_count in range(MAX_REDIRECTS + 1):
            resp = session.get(
                current_url,
                allow_redirects=False,      # handle manually
                timeout=REQUEST_TIMEOUT,
                stream=True,                # don't download body yet
                headers={"User-Agent": "WebGuard-Scanner/2.0 (educational project)"},
            )

            # If it's a redirect, validate the destination before following.
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if not location:
                    # No Location header — stop following.
                    response = resp
                    break

                # Resolve relative redirect URLs against the current URL.
                next_url = urllib.parse.urljoin(current_url, location)
                parsed_next = urllib.parse.urlparse(next_url)

                if parsed_next.scheme not in ("http", "https"):
                    return _error_result(
                        url, timestamp,
                        "Redirect to a non-HTTP/S URL was blocked for safety."
                    )

                # Re-run SSRF check on the redirect target.
                next_ip = _resolve_and_check(parsed_next.hostname or "")
                if next_ip is None:
                    return _error_result(
                        url, timestamp,
                        "A redirect pointed to a private or restricted address "
                        "and was blocked to prevent SSRF."
                    )

                current_url = next_url
                if redirect_count == MAX_REDIRECTS:
                    return _error_result(
                        url, timestamp,
                        f"Too many redirects (limit: {MAX_REDIRECTS})."
                    )
            else:
                # Not a redirect — this is our final response.
                response = resp
                break

        if response is None:
            return _error_result(url, timestamp, "No response received.")

        # We only need the response headers — the body is irrelevant.
        # However, reading a small amount of the body and then closing the
        # connection is cleaner than an abrupt RST: it lets the server know
        # the client is done.
        #
        # iter_content() yields raw bytes in chunks without buffering the
        # whole body.  We stop as soon as we have read MAX_RESPONSE_BYTES,
        # then call response.close() to release the socket.  This enforces
        # a hard cap regardless of how large the server's response is.
        bytes_read = 0
        for chunk in response.iter_content(chunk_size=4096):
            bytes_read += len(chunk)
            if bytes_read >= MAX_RESPONSE_BYTES:
                break
        response.close()

    except requests.exceptions.ConnectionError:
        return _error_result(
            url, timestamp,
            "Could not connect to the host.  Check the URL and try again."
        )
    except requests.exceptions.Timeout:
        return _error_result(
            url, timestamp,
            f"The request timed out after {REQUEST_TIMEOUT} seconds."
        )
    except requests.exceptions.TooManyRedirects:
        return _error_result(
            url, timestamp,
            "The server returned too many redirects."
        )
    except requests.exceptions.RequestException as exc:
        return _error_result(url, timestamp, f"Request error: {exc}")

    # -- Run all checks on the response headers ---------------------------
    headers = dict(response.headers)

    checks = [
        check_https(current_url),         # Were we redirected to HTTPS?
        check_hsts(headers),
        check_csp(headers),
        check_xcto(headers),
        check_xfo(headers),
        check_referrer_policy(headers),
        check_permissions_policy(headers),
        check_cors(headers),
    ]

    score = calculate_score(checks)

    return {
        "url": url,
        "final_url": current_url,         # may differ if there were redirects
        "timestamp": timestamp,
        "status_code": response.status_code,
        "error": None,
        "checks": checks,
        "score": score,
    }


def _error_result(url: str, timestamp: str, message: str) -> dict:
    """
    Helper: build a uniform error result dict so the frontend always
    receives the same shape regardless of whether the scan succeeded.
    """
    return {
        "url": url,
        "final_url": url,
        "timestamp": timestamp,
        "status_code": None,
        "error": message,
        "checks": [],
        "score": None,
    }


# ---------------------------------------------------------------------------
# SECTION 6 — Flask routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Scan endpoint.  Accepts JSON: { "url": "https://example.com" }
    Returns JSON with the full scan result.

    Why POST?  Scan requests change server state (make outbound HTTP calls)
    and may carry sensitive URL strings — POST is more appropriate than GET.
    """
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()

    # Step 1: validate the URL.
    ok, clean_url, err_msg = validate_url(raw_url)
    if not ok:
        return jsonify({"error": err_msg, "checks": [], "score": None}), 400

    # Step 2: run the scanner.
    result = run_scan(clean_url)

    # Return 200 even when the scan itself found "review" items — those are
    # findings to display, not server errors.  Only return 4xx/5xx when
    # something prevented the scan from completing.
    if result.get("error") and not result.get("checks"):
        return jsonify(result), 502

    return jsonify(result), 200


# ---------------------------------------------------------------------------
# SECTION 7 — HTML template (dashboard)
# ---------------------------------------------------------------------------
# Everything the user sees lives here.  CSS and JavaScript are embedded so
# the final deliverable is a single Python file.
#
# Note on Flask template syntax:
#   render_template_string() uses Jinja2.  The {{ }} and {% %} markers are
#   Jinja2 syntax.  Because our JavaScript also uses { } we must escape any
#   literal JS braces that Jinja2 would otherwise try to interpret.
#   We do this by writing {{- and -}} where needed — or more simply by
#   keeping ALL dynamic data out of the template and loading it via fetch().
#   The template here is 100% static HTML+CSS+JS; there are no Jinja2
#   variables in it, so no escaping is needed.
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>WebGuard — Web Security Scanner</title>
  <style>
    /* ── WebGuard modern dark UI ───────────────────────────────────── */
    :root {
      color-scheme: dark;
      --bg: #07111f;
      --surface: #0d1b2a;
      --surface-raised: #102338;
      --surface-hover: #142b40;
      --border: #203b50;
      --border-strong: #2c526a;
      --text: #e6f4fb;
      --muted: #91aabd;
      --muted-dim: #68859a;
      --cyan: #45d9e8;
      --teal: #28c7a7;
      --danger: #ff7185;
      --warning: #f5c66a;
      --blue: #76baff;
      --shadow: 0 18px 48px rgba(0, 0, 0, 0.22);
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    html { min-height: 100%; background: var(--bg); }
    body {
      font-family: Inter, 'Segoe UI', system-ui, -apple-system, sans-serif;
      background:
        radial-gradient(ellipse at 50% -15%, rgba(27, 126, 157, 0.20), transparent 48%),
        var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    /* ── Top navigation bar ───────────────────────────────────────── */
    header {
      width: 100%; min-height: 66px;
      background: rgba(9, 24, 39, 0.92);
      border-bottom: 1px solid var(--border);
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.14);
      padding: 0 clamp(1rem, 4vw, 2.5rem);
      display: flex; align-items: center; gap: 0.85rem;
      backdrop-filter: blur(14px);
    }
    .logo-icon {
      width: 36px; height: 36px;
      background: linear-gradient(135deg, var(--cyan), var(--teal));
      border-radius: 11px;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.1rem; color: #05202b; font-weight: 800;
      box-shadow: 0 0 22px rgba(69, 217, 232, 0.18);
      flex-shrink: 0;
    }
    header h1 { font-size: 1.12rem; color: var(--text); font-weight: 750; letter-spacing: -0.025em; }
    header span { font-size: 0.82rem; color: var(--muted); margin-left: 0.25rem; }

    /* ── Main content wrapper ─────────────────────────────────────── */
    main { width: 100%; max-width: 940px; padding: 3rem 1.5rem 4rem; flex: 1; }

    /* ── Hero ─────────────────────────────────────────────────────── */
    .hero { text-align: center; margin-bottom: 2.4rem; }
    .hero h2 {
      font-size: clamp(1.7rem, 4vw, 2.35rem); line-height: 1.2;
      color: var(--text); font-weight: 760; letter-spacing: -0.045em;
      margin-bottom: 0.85rem;
    }
    .hero h2::after {
      content: ''; display: block; width: 66px; height: 3px; margin: 1rem auto 0;
      border-radius: 99px; background: linear-gradient(90deg, var(--cyan), var(--teal));
    }
    .hero p { color: var(--muted); font-size: 0.97rem; max-width: 590px; margin: 0 auto; line-height: 1.75; }

    /* ── Scan input card ──────────────────────────────────────────── */
    .scan-card {
      background: linear-gradient(145deg, rgba(16, 35, 56, 0.96), rgba(11, 27, 43, 0.98));
      border: 1px solid var(--border-strong); border-radius: 18px;
      padding: 1.8rem; margin-bottom: 2rem; box-shadow: var(--shadow);
    }
    .scan-card label {
      display: block; font-size: 0.78rem; color: var(--muted);
      margin-bottom: 0.7rem; text-transform: uppercase; letter-spacing: 0.105em; font-weight: 700;
    }
    .input-row { display: flex; gap: 0.75rem; flex-wrap: wrap; }
    .input-row input {
      flex: 1; min-width: 220px; min-height: 48px;
      background: #071522; border: 1px solid #29465b; border-radius: 10px;
      padding: 0.75rem 0.95rem; color: var(--text); font-size: 0.96rem;
      outline: none; transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
    }
    .input-row input:focus { border-color: var(--cyan); background: #081a29; box-shadow: 0 0 0 3px rgba(69, 217, 232, 0.13); }
    .input-row input.error { border-color: var(--danger); box-shadow: 0 0 0 3px rgba(255, 113, 133, 0.12); }
    .input-row input::placeholder { color: #587489; }
    .btn-scan {
      background: linear-gradient(135deg, var(--cyan), var(--teal)); color: #06212a;
      border: 1px solid transparent; border-radius: 10px; min-height: 48px;
      padding: 0.75rem 1.35rem; font-size: 0.93rem; font-weight: 800;
      cursor: pointer; transition: transform 0.18s, box-shadow 0.18s, filter 0.18s; white-space: nowrap;
    }
    .btn-scan:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 8px 22px rgba(40, 199, 167, 0.2); filter: brightness(1.06); }
    .btn-scan:active:not(:disabled) { transform: translateY(0); }
    .btn-scan:focus-visible, .btn-export:focus-visible, .check-summary:focus-visible { outline: 2px solid var(--cyan); outline-offset: 3px; }
    .btn-scan:disabled { background: #203444; color: #688094; cursor: not-allowed; box-shadow: none; }

    /* ── Inline error message under the input ─────────────────────── */
    .input-error { margin-top: 0.65rem; font-size: 0.85rem; color: var(--danger); display: none; }
    .input-error.visible { display: block; }

    /* ── Loading spinner ──────────────────────────────────────────── */
    .loader { display: none; flex-direction: column; align-items: center; padding: 3rem 2rem; gap: 1rem; color: var(--muted); font-size: 0.9rem; }
    .loader.visible { display: flex; }
    .spinner { width: 42px; height: 42px; border: 3px solid #1b394d; border-top-color: var(--cyan); border-right-color: var(--teal); border-radius: 50%; animation: spin 0.8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ── Welcome / empty state ────────────────────────────────────── */
    .empty-state {
      background: rgba(13, 31, 48, 0.8); border: 1px dashed #31536a;
      border-radius: 18px; padding: 3rem 2rem; text-align: center;
    }
    .empty-state .shield { font-size: 3rem; margin-bottom: 1rem; color: var(--cyan); filter: drop-shadow(0 0 16px rgba(69, 217, 232, 0.2)); }
    .empty-state h3 { font-size: 1.13rem; color: var(--text); margin-bottom: 0.65rem; }
    .empty-state p { color: var(--muted); font-size: 0.9rem; line-height: 1.75; max-width: 500px; margin: 0 auto 1.2rem; }
    .feature-list { display: flex; flex-wrap: wrap; gap: 0.6rem; justify-content: center; margin-top: 1rem; }
    .feature-badge { background: #102a3d; border: 1px solid #244a60; border-radius: 999px; padding: 0.36rem 0.85rem; font-size: 0.79rem; color: #a6c6d8; }

    /* ── Error banner (scan-level error) ──────────────────────────── */
    .error-banner { display: none; background: #2a1522; border: 1px solid #80384b; border-radius: 12px; padding: 1rem 1.25rem; color: #ff9aa9; font-size: 0.9rem; line-height: 1.6; }
    .error-banner.visible { display: block; }
    .error-banner strong { display: block; margin-bottom: 0.25rem; color: #ffb7c1; }

    /* ── Results section ──────────────────────────────────────────── */
    .results { display: none; }
    .results.visible { display: block; }
    .summary-row { display: flex; gap: 1rem; flex-wrap: wrap; align-items: stretch; margin-bottom: 1.5rem; }

    /* Score circle */
    .score-card {
      background: linear-gradient(145deg, #10263a, #0b1c2c); border: 1px solid var(--border-strong);
      border-radius: 16px; padding: 1.35rem 1.5rem; display: flex; flex-direction: column;
      align-items: center; justify-content: center; gap: 0.55rem; min-width: 150px; box-shadow: var(--shadow);
    }
    .score-ring { width: 86px; height: 86px; position: relative; }
    .score-ring svg { transform: rotate(-90deg); }
    .score-ring .ring-bg { fill: none; stroke: #1c394c; stroke-width: 8; }
    .score-ring .ring-val { fill: none; stroke-width: 8; stroke-linecap: round; transition: stroke-dashoffset 0.6s ease; }
    .score-number { position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); font-size: 1.35rem; font-weight: 800; color: var(--text); }
    .score-grade { font-size: 1.12rem; font-weight: 800; }
    .score-label { font-size: 0.78rem; color: var(--muted); }

    /* Stat cards */
    .stat-cards { display: flex; gap: 1rem; flex-wrap: wrap; flex: 1; }
    .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 1.1rem 1.25rem; flex: 1; min-width: 110px; box-shadow: 0 10px 26px rgba(0, 0, 0, 0.12); }
    .stat-card .stat-num { font-size: 1.9rem; line-height: 1.2; font-weight: 800; color: var(--text); }
    .stat-card .stat-name { font-size: 0.79rem; color: var(--muted); margin-top: 0.35rem; }
    .scan-meta { font-size: 0.79rem; color: var(--muted-dim); margin-bottom: 1.4rem; display: flex; gap: 1.25rem; flex-wrap: wrap; }
    .scan-meta span b { color: var(--muted); }

    /* ── Findings list ────────────────────────────────────────────── */
    .findings-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.85rem; flex-wrap: wrap; gap: 0.65rem; }
    .findings-header h3 { font-size: 1.02rem; color: var(--text); font-weight: 750; letter-spacing: -0.015em; }
    .btn-export { background: #112b3e; color: #bcebf0; border: 1px solid #2a566a; border-radius: 9px; padding: 0.48rem 1rem; font-size: 0.84rem; font-weight: 650; cursor: pointer; transition: background 0.18s, border-color 0.18s, transform 0.18s; }
    .btn-export:hover { background: #17394d; border-color: var(--cyan); transform: translateY(-1px); }
    .check-list { display: flex; flex-direction: column; gap: 0.7rem; }
    .check-item { background: rgba(13, 29, 45, 0.92); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; transition: border-color 0.2s, background 0.2s; }
    .check-item:hover { border-color: #315a70; }
    .check-summary { display: flex; align-items: center; gap: 0.85rem; padding: 1rem 1.05rem; cursor: pointer; user-select: none; transition: background 0.18s; }
    .check-summary:hover { background: var(--surface-hover); }

    /* Status badges retain their meaning and distinct colors */
    .badge { display: inline-flex; align-items: center; justify-content: center; width: 76px; min-height: 24px; border-radius: 6px; font-size: 0.69rem; font-weight: 800; letter-spacing: 0.055em; flex-shrink: 0; text-transform: uppercase; }
    .badge-pass { background: rgba(40, 199, 167, 0.12); color: #54e0be; border: 1px solid #237b70; }
    .badge-review { background: rgba(245, 198, 106, 0.11); color: var(--warning); border: 1px solid #80683b; }
    .badge-info { background: rgba(118, 186, 255, 0.11); color: var(--blue); border: 1px solid #315f89; }
    .check-name { flex: 1; font-size: 0.91rem; color: var(--text); font-weight: 600; }
    .check-value { font-size: 0.8rem; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .chevron { color: #7597aa; font-size: 0.75rem; transition: transform 0.2s; flex-shrink: 0; }
    .check-item.open .chevron { transform: rotate(90deg); }
    .check-detail { display: none; padding: 0 1.1rem 1.1rem; border-top: 1px solid #1b374a; }
    .check-item.open .check-detail { display: block; }
    .check-detail p { font-size: 0.88rem; color: #a4bdcc; line-height: 1.75; margin-top: 0.7rem; overflow-wrap: anywhere; }
    .check-detail .remediation { margin-top: 0.75rem; padding: 0.75rem 0.9rem; background: rgba(25, 102, 121, 0.15); border-left: 3px solid var(--cyan); border-radius: 0 9px 9px 0; font-size: 0.85rem; color: #a7eaf0; line-height: 1.65; }
    .check-detail .remediation::before { content: '💡 Recommendation: '; font-weight: 750; color: var(--cyan); }

    /* ── Footer ───────────────────────────────────────────────────── */
    footer { width: 100%; text-align: center; padding: 1.1rem; font-size: 0.78rem; color: var(--muted-dim); border-top: 1px solid var(--border); background: rgba(7, 17, 31, 0.72); }

    /* ── Responsive ───────────────────────────────────────────────── */
    @media (max-width: 640px) {
      header { min-height: 62px; }
      header span { font-size: 0.74rem; }
      main { padding: 2.2rem 1rem 3rem; }
      .hero { margin-bottom: 1.8rem; }
      .hero h2 { font-size: 1.65rem; }
      .scan-card { padding: 1.25rem 1rem; border-radius: 14px; }
      .input-row { flex-direction: column; }
      .input-row input { min-width: 0; width: 100%; }
      .btn-scan { width: 100%; }
      .summary-row { gap: 0.75rem; }
      .score-card { flex: 1 1 100%; }
      .stat-cards { gap: 0.65rem; }
      .stat-card { min-width: calc(50% - 0.4rem); padding: 0.9rem; }
      .check-summary { gap: 0.55rem; padding: 0.85rem 0.75rem; }
      .badge { width: 68px; font-size: 0.65rem; }
      .check-name { font-size: 0.84rem; }
      .check-value { display: none; }
      .empty-state { padding: 2.2rem 1rem; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
    }
</style>
</head>
<body>

  <!-- ── Top navigation bar ────────────────────────────────────────── -->
  <header>
    <div class="logo-icon">W</div>
    <h1>WebGuard</h1>
    <span>Web Security Scanner</span>
  </header>

  <!-- ── Main content ──────────────────────────────────────────────── -->
  <main>

    <div class="hero">
      <h2>Automated Web Security Scanner</h2>
      <p>
        Enter any public website URL to check its HTTP security headers,
        HTTPS configuration, and CORS settings. Get a clear security score
        and actionable recommendations.
      </p>
    </div>

    <!-- URL input card -->
    <div class="scan-card">
      <label for="urlInput">Target Website URL</label>
      <div class="input-row">
        <input
          type="text"
          id="urlInput"
          placeholder="https://example.com"
          autocomplete="off"
          spellcheck="false"
        />
        <button class="btn-scan" id="scanBtn" disabled>
          Start Scan
        </button>
      </div>
      <div class="input-error" id="inputError"></div>
    </div>

    <!-- Loading state -->
    <div class="loader" id="loader">
      <div class="spinner"></div>
      <span>Scanning — this may take up to 10 seconds…</span>
    </div>

    <!-- Scan-level error banner -->
    <div class="error-banner" id="errorBanner">
      <strong>Scan failed</strong>
      <span id="errorMsg"></span>
    </div>

    <!-- Welcome / empty state -->
    <div class="empty-state" id="emptyState">
      <div class="shield">&#x1F6E1;</div>
      <h3>Enter a URL above and click Start Scan</h3>
      <p>
        WebGuard makes a single, read-only HTTP request to the URL you provide
        and inspects the security-related response headers.  No data is stored.
        Only scan websites you own or have permission to test.
      </p>
      <div class="feature-list">
        <span class="feature-badge">HTTPS check</span>
        <span class="feature-badge">Content-Security-Policy</span>
        <span class="feature-badge">Strict-Transport-Security</span>
        <span class="feature-badge">X-Content-Type-Options</span>
        <span class="feature-badge">X-Frame-Options</span>
        <span class="feature-badge">Referrer-Policy</span>
        <span class="feature-badge">Permissions-Policy</span>
        <span class="feature-badge">CORS headers</span>
        <span class="feature-badge">Security score</span>
        <span class="feature-badge">JSON export</span>
      </div>
    </div>

    <!-- Results (hidden until a scan completes) -->
    <div class="results" id="results">

      <!-- Summary row -->
      <div class="summary-row">
        <div class="score-card">
          <div class="score-ring" id="scoreRing">
            <svg viewBox="0 0 80 80" width="80" height="80">
              <circle class="ring-bg"  cx="40" cy="40" r="34"/>
              <circle class="ring-val" cx="40" cy="40" r="34" id="ringArc"
                      stroke-dasharray="213.6" stroke-dashoffset="213.6"/>
            </svg>
            <div class="score-number" id="scoreNumber">--</div>
          </div>
          <div class="score-grade" id="scoreGrade">--</div>
          <div class="score-label">Security Score</div>
        </div>

        <div class="stat-cards">
          <div class="stat-card">
            <div class="stat-num" id="statPass"   style="color:#3fb950">--</div>
            <div class="stat-name">Passed</div>
          </div>
          <div class="stat-card">
            <div class="stat-num" id="statReview" style="color:#e3b341">--</div>
            <div class="stat-name">Review</div>
          </div>
          <div class="stat-card">
            <div class="stat-num" id="statInfo"   style="color:#79c0ff">--</div>
            <div class="stat-name">Info</div>
          </div>
          <div class="stat-card">
            <div class="stat-num" id="statTotal"  >--</div>
            <div class="stat-name">Total Checks</div>
          </div>
        </div>
      </div>

      <!-- Scan metadata -->
      <div class="scan-meta" id="scanMeta"></div>

      <!-- Findings list -->
      <div class="findings-header">
        <h3>Security Checks</h3>
        <button class="btn-export" id="exportBtn">&#x2B07; Download JSON Report</button>
      </div>
      <div class="check-list" id="checkList"></div>

    </div><!-- /results -->

  </main>

  <footer>
    WebGuard &mdash; Cybersecurity Bootcamp Project &mdash; For authorized, defensive testing only
  </footer>

  <script>
    // ── DOM references ────────────────────────────────────────────────
    const urlInput   = document.getElementById('urlInput');
    const scanBtn    = document.getElementById('scanBtn');
    const inputError = document.getElementById('inputError');
    const loader     = document.getElementById('loader');
    const errorBanner= document.getElementById('errorBanner');
    const errorMsg   = document.getElementById('errorMsg');
    const emptyState = document.getElementById('emptyState');
    const results    = document.getElementById('results');
    const exportBtn  = document.getElementById('exportBtn');

    // Store the last scan result so we can export it to JSON.
    let lastResult = null;

    // ── Enable / disable the button based on input content ───────────
    urlInput.addEventListener('input', function () {
      const trimmed = urlInput.value.trim();
      scanBtn.disabled = trimmed.length === 0;
      if (trimmed.length > 0) {
        urlInput.classList.remove('error');
        inputError.classList.remove('visible');
      }
    });

    // Also allow pressing Enter to start a scan.
    urlInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !scanBtn.disabled) startScan();
    });

    // ── Start scan ────────────────────────────────────────────────────
    scanBtn.addEventListener('click', startScan);

    function startScan() {
      const url = urlInput.value.trim();
      if (!url) return;

      // Reset UI to loading state.
      setUI('loading');

      // POST the URL to the Flask /api/scan endpoint.
      // fetch() is the modern browser API for making HTTP requests.
      fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      })
      .then(function (response) {
        // response.json() reads the body and parses it as JSON.
        return response.json().then(function (data) {
          return { status: response.status, data: data };
        });
      })
      .then(function (obj) {
        if (obj.data.error && obj.data.checks.length === 0) {
          // The scan failed entirely — show the error banner.
          setUI('error', obj.data.error);
        } else {
          // We have real results — render them.
          lastResult = obj.data;
          renderResults(obj.data);
          setUI('results');
        }
      })
      .catch(function (err) {
        // Network error (Flask server not running, etc.)
        setUI('error', 'Could not reach the WebGuard server. Is it running?');
      });
    }

    // ── UI state machine ──────────────────────────────────────────────
    // Centralising show/hide logic here keeps the code tidy.
    function setUI(state, message) {
      loader.classList.remove('visible');
      errorBanner.classList.remove('visible');
      emptyState.style.display  = 'none';
      results.classList.remove('visible');

      if (state === 'loading') {
        loader.classList.add('visible');
        scanBtn.disabled = true;
      } else if (state === 'error') {
        errorMsg.textContent = message || 'An unexpected error occurred.';
        errorBanner.classList.add('visible');
        scanBtn.disabled = false;
      } else if (state === 'results') {
        results.classList.add('visible');
        scanBtn.disabled = false;
      } else {
        // 'empty'
        emptyState.style.display = '';
      }
    }

    // ── Render results ────────────────────────────────────────────────
    function renderResults(data) {
      const checks = data.checks || [];
      const score  = data.score  || {};

      // -- Score ring ---------------------------------------------------
      // The SVG circle has circumference 2 * pi * 34 ≈ 213.6 px.
      // We animate stroke-dashoffset from full (hidden) to the earned pct.
      const pct    = score.score || 0;
      const offset = 213.6 * (1 - pct / 100);
      const arc    = document.getElementById('ringArc');
      const gradeColor = gradeToColor(score.grade);

      arc.style.stroke = gradeColor;
      // Defer the offset change so the CSS transition fires.
      setTimeout(function () { arc.style.strokeDashoffset = offset; }, 50);

      document.getElementById('scoreNumber').textContent = pct;
      const gradeEl = document.getElementById('scoreGrade');
      gradeEl.textContent = score.grade || '--';
      gradeEl.style.color = gradeColor;

      // -- Stat cards ---------------------------------------------------
      let nPass = 0, nReview = 0, nInfo = 0;
      checks.forEach(function (c) {
        if (c.status === 'pass')   nPass++;
        else if (c.status === 'review') nReview++;
        else if (c.status === 'info')   nInfo++;
      });
      document.getElementById('statPass').textContent   = nPass;
      document.getElementById('statReview').textContent = nReview;
      document.getElementById('statInfo').textContent   = nInfo;
      document.getElementById('statTotal').textContent  = checks.length;

      // -- Scan metadata ------------------------------------------------
      const meta = document.getElementById('scanMeta');
      meta.innerHTML =
        '<span><b>Target:</b> ' + escHtml(data.url) + '</span>' +
        (data.final_url !== data.url ? '<span><b>Final URL:</b> ' + escHtml(data.final_url) + '</span>' : '') +
        '<span><b>HTTP Status:</b> ' + (data.status_code || 'N/A') + '</span>' +
        '<span><b>Scanned at:</b> ' + formatTime(data.timestamp) + '</span>';

      // -- Check list ---------------------------------------------------
      const list = document.getElementById('checkList');
      list.innerHTML = '';
      checks.forEach(function (chk) {
        list.appendChild(buildCheckItem(chk));
      });
    }

    // Build a single expandable check row.
    function buildCheckItem(chk) {
      const item = document.createElement('div');
      item.className = 'check-item';

      const summary = document.createElement('div');
      summary.className = 'check-summary';
      summary.innerHTML =
        '<span class="badge badge-' + chk.status + '">' + chk.status.toUpperCase() + '</span>' +
        '<span class="check-name">'  + escHtml(chk.name)  + '</span>' +
        '<span class="check-value">' + escHtml(chk.value) + '</span>' +
        '<span class="chevron">&#9654;</span>';

      const detail = document.createElement('div');
      detail.className = 'check-detail';
      detail.innerHTML =
        '<p>' + escHtml(chk.detail) + '</p>' +
        (chk.remediation
          ? '<div class="remediation">' + escHtml(chk.remediation) + '</div>'
          : '');

      // Toggle open/closed on click.
      summary.addEventListener('click', function () {
        item.classList.toggle('open');
      });

      item.appendChild(summary);
      item.appendChild(detail);
      return item;
    }

    // ── Export to JSON ────────────────────────────────────────────────
    exportBtn.addEventListener('click', function () {
      if (!lastResult) return;
      const blob = new Blob(
        [JSON.stringify(lastResult, null, 2)],
        { type: 'application/json' }
      );
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      // Build a filename like: webguard_example.com_20240101T120000.json
      const host = (lastResult.url || 'scan').replace(/https?:\/\//, '').replace(/[^a-z0-9]/gi, '_');
      const ts   = (lastResult.timestamp || '').replace(/[^0-9T]/g, '').substring(0, 15);
      a.download = 'webguard_' + host + '_' + ts + '.json';
      a.click();
      URL.revokeObjectURL(a.href);
    });

    // ── Utility helpers ───────────────────────────────────────────────
    function escHtml(str) {
      // Prevent XSS when inserting server data into innerHTML.
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function gradeToColor(grade) {
      return { A: '#3fb950', B: '#79c0ff', C: '#e3b341', D: '#f0883e', F: '#f85149' }[grade] || '#8b949e';
    }

    function formatTime(iso) {
      if (!iso) return 'N/A';
      try {
        return new Date(iso).toLocaleString();
      } catch (e) {
        return iso;
      }
    }
  </script>

</body>
</html>
"""

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 55)
    print("  WebGuard — Web Security Scanner  |  Subham Padhi")
    print("=" * 55)
    print("  Dashboard: http://127.0.0.1:5000")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 55)
    # debug=True enables auto-reload on file save and detailed error pages.
    # This is intentional for local development only.
    # The server is bound to 127.0.0.1 so it is not reachable from other
    # machines.  Never deploy with debug=True on a public or shared network.
    app.run(host="127.0.0.1", port=5000, debug=True)
