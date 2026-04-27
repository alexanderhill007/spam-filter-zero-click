"""
Method 2: Hyperlink Trust Analysis
===================================

CISSP mapping: Domain 4 (Communication & Network Security) — URL filtering,
DNS reputation; Domain 1 (Security & Risk Management) — threat intelligence.

Theory
------
The naive form of this control — "does the destination domain present a TLS
certificate?" — is a weak signal in 2026 because Let's Encrypt issues free
certs in seconds. So we treat the cert check as one signal among several:

  (a) Domain hosts no valid TLS cert at all                — moderate
  (b) Display text differs from the actual href            — strong
  (c) Link uses a URL shortener (bit.ly, tinyurl, t.co...) — moderate
  (d) Link points to a raw IP address                      — strong
  (e) Link uses a high-abuse TLD (.zip, .top, .xyz, ...)   — moderate
  (f) Domain age < 30 days                                 — strong *
  (g) Brand-name impersonation in display vs. href host    — strong

(*) Domain age requires a WHOIS lookup. Degrades gracefully if offline.

References
----------
- NIST SP 800-177 Rev.1 §6.3, "Content Filtering"
- CIS Controls v8, Control 9.2/9.3 (DNS filtering, URL filtering)
- Spamhaus, "World's Most Abused TLDs" (updated quarterly)
"""

import re
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urlparse

# ----- known-shady patterns ------------------------------------------------

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "lnkd.in", "rb.gy",
    "x.co", "tr.im", "qr.net",
}

HIGH_ABUSE_TLDS = {
    "zip", "top", "xyz", "click", "country", "stream", "download",
    "loan", "racing", "review", "trade", "win", "work", "men", "kim",
    "party", "science", "gq", "cf", "ml", "ga", "tk", "rest",
    "support", "cyou", "icu", "buzz",
}

IP_ADDRESS_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|^\[?[a-f0-9:]+\]?$", re.IGNORECASE
)


# ----- HTML anchor extraction ----------------------------------------------

class _AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors = []           # (href, display_text)
        self._cur_href = None
        self._cur_text_parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = next((v for k, v in attrs if k.lower() == "href"), None)
            self._cur_href = href
            self._cur_text_parts = []

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._cur_href is not None:
            text = "".join(self._cur_text_parts).strip()
            self.anchors.append((self._cur_href, text))
            self._cur_href = None
            self._cur_text_parts = []

    def handle_data(self, data):
        if self._cur_href is not None:
            self._cur_text_parts.append(data)


def extract_links(body: str) -> list:
    """Return a list of (href, display_text) tuples, including plain-text URLs."""
    parser = _AnchorParser()
    try:
        parser.feed(body)
    except Exception:
        pass
    anchors = parser.anchors
    plain_re = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
    seen_hrefs = {h for h, _ in anchors}
    for url in plain_re.findall(body):
        if url not in seen_hrefs:
            anchors.append((url, url))
    return anchors


# ----- per-link scoring -----------------------------------------------------

def cert_valid(host: str, timeout: float = 3.0) -> bool | None:
    """True if host serves a valid TLS cert; False if it doesn't; None if
    we can't determine (network unreachable, timeout). None ≠ held against."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return bool(cert)
    except (ssl.SSLError, ssl.CertificateError):
        return False
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError):
        return None


def domain_age_days(domain: str, timeout: float = 3.0) -> int | None:
    """Return age in days if determinable; None if not. Optional dep on python-whois."""
    try:
        import whois  # noqa
    except ImportError:
        return None
    try:
        socket.setdefaulttimeout(timeout)
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if not creation:
            return None
        from datetime import datetime, timezone
        if hasattr(creation, "tzinfo") and creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (now - creation).days
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def score_link(href: str, display: str, network: bool = True) -> dict:
    """Return per-link risk indicators and a 0-100 score."""
    indicators = []
    score = 0
    host = (urlparse(href).hostname or "")
    if not host:
        return {"href": href, "score": 0, "indicators": ["unparseable"]}

    if IP_ADDRESS_RE.match(host):
        score += 50
        indicators.append("raw-IP-URL")

    if host.lower() in URL_SHORTENERS:
        score += 25
        indicators.append(f"shortener:{host}")

    tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
    if tld in HIGH_ABUSE_TLDS:
        score += 25
        indicators.append(f"abused-tld:.{tld}")

    disp = display.strip().lower()
    if disp.startswith(("http://", "https://")):
        try:
            disp_host = urlparse(disp).hostname or ""
            if disp_host and disp_host.lower() != host.lower():
                score += 35
                indicators.append(f"display/href mismatch ({disp_host} vs {host})")
        except Exception:
            pass
    else:
        brand_tokens = re.findall(r"\b(paypal|amazon|apple|google|microsoft|"
                                  r"netflix|chase|wellsfargo|usbank|fedex|ups|dhl|"
                                  r"irs|usps|ebay|facebook|instagram|linkedin)\b", disp)
        for tok in brand_tokens:
            if tok not in host.lower():
                score += 30
                indicators.append(f"brand-impersonation:{tok}→{host}")
                break

    if network:
        cert_ok = cert_valid(host)
        if cert_ok is False:
            score += 20
            indicators.append("no-valid-TLS-cert")

        age = domain_age_days(host)
        if age is not None and age < 30:
            score += 40
            indicators.append(f"domain-age:{age}d")
        elif age is not None and age < 180:
            score += 15
            indicators.append(f"young-domain:{age}d")

    return {"href": href, "score": min(score, 100), "indicators": indicators}


# ----- detection entry point -----------------------------------------------

def check(body: str, network: bool = True) -> dict:
    links = extract_links(body)
    if not links:
        return {
            "method": "hyperlinks",
            "verdict": "inconclusive",
            "score": 0,
            "evidence": "No URLs in message body.",
            "details": [],
        }

    per_link = [score_link(h, d, network=network) for h, d in links]
    max_score = max(r["score"] for r in per_link) if per_link else 0
    avg_score = sum(r["score"] for r in per_link) / len(per_link)

    # Worst-link-wins (70%) blended with average (30%) — prevents one bad
    # link from being diluted by 20 benign links, but also penalizes when
    # *most* links are sketchy.
    aggregate = int(0.7 * max_score + 0.3 * avg_score)

    if aggregate >= 50:
        verdict = "spam"
    elif aggregate >= 25:
        verdict = "spam"   # lower-confidence flag
    else:
        verdict = "ham"

    flagged = [r for r in per_link if r["score"] >= 25]
    if flagged:
        evidence = "; ".join(
            f"{r['href'][:50]} → [{', '.join(r['indicators'])}]"
            for r in flagged[:3]
        )
    else:
        evidence = f"{len(per_link)} link(s) inspected, none flagged"
    return {
        "method": "hyperlinks",
        "verdict": verdict,
        "score": aggregate,
        "evidence": evidence,
        "details": per_link,
    }