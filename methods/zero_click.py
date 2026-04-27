"""
Method 5 (Bonus): Zero-Click Attack Surface Detection
======================================================

CISSP mapping
-------------
  Domain 3 (Cryptography)            — covert exfiltration channels (EFAIL),
                                       NTLM hash theft via SMB references
  Domain 4 (Comms / Network Sec.)    — URI scheme abuse, SMB / WebDAV
                                       outbound, content-policy enforcement
  Domain 7 (Security Operations)     — indicators of compromise, threat
                                       hunting, MITRE ATT&CK mapping
  Domain 8 (Software Dev Security)   — input validation, secure parsing,
                                       content sanitization, fail-safe defaults

Threat model
------------
"Zero-click" exploits execute the moment a mail client parses or renders the
message — no user click required. This module does NOT claim to detect
specific CVEs (that requires sandboxing, YARA, and parser fuzzing) but it
DOES enumerate the *attack surface* that exposes a recipient to those
exploits. Surface reduction is a defensible defense-in-depth control even
when CVE-specific detection is impossible.

Real-world precedent (cited inline below per finding):

  CVE-2023-23397   Outlook NTLM hash leak via crafted reminder UNC path.
                   Exploited in the wild by APT28 (Forest Blizzard, 2022-2023).
  CVE-2021-30860   FORCEDENTRY — integer overflow in Apple CoreGraphics
                   PDF parsing, weaponized by NSO Group's Pegasus.
  CVE-2022-30190   Follina — MSDT URI scheme RCE in Office.
  CVE-2023-36884   Office / Windows Search HTML RCE.
  EFAIL (2018)     Poddebniak et al. — exfiltration of S/MIME / OpenPGP
                   plaintext via CSS background-image and image src
                   backchannels triggered on render.
  Triangulation    iOS zero-click via iMessage attachment chain (2023).

This module operates as Microsoft Defender for O365's Safe Links /
Proofpoint TAP URL Defense / Mimecast Targeted Threat Protection do at
the *surface-reduction* layer: parse the message, enumerate dangerous
constructs, score by severity, hand the result up to the orchestrator.

Severity tiers
--------------
Tier 1  CRITICAL  (70-90 pts)  Active code execution surface
                              <script>, javascript:/vbscript: URIs,
                              UNC paths, file://, ms-msdt:, etc.
Tier 2  HIGH      (40-60 pts)  Automatic action / external content load
                              meta refresh, iframe, EFAIL CSS exfil,
                              risky attachment extensions, MIME mismatch.
Tier 3  MEDIUM    (20-35 pts)  Exfil / surveillance / event handlers
                              tracking pixels, onload/onerror, tracking
                              parameters, conditional rendering.
Tier 4  LOW       (5-15 pts)   Obfuscation indicators (additive only)
                              RTL override, zero-width chars, excessive
                              entity encoding.

Standards & frameworks
----------------------
  NIST SP 800-177 Rev.1 §6      — UBE filtering pipeline, content filtering
  NIST SP 800-83  Rev.1         — Malware incident prevention/handling
  NIST SP 800-45  v2  §6.4      — Active content in mail
  NIST SP 800-53  Rev.5         — SI-3 (malicious code), SI-7 (integrity),
                                  SC-7 (boundary protection),
                                  SC-18 (mobile code)
  CIS Controls v8 Control 9     — Email and Web Browser Protections
  CIS Controls v8 Control 10    — Malware Defenses
  CISA KEV Catalog              — Known Exploited Vulnerabilities
  OWASP HTML5 Security Cheat Sheet
  MITRE ATT&CK                  — T1566, T1203, T1204, T1187, T1027

Limitations (state these explicitly to a CISO audience)
-------------------------------------------------------
  * Surface reduction, NOT exploit detection. Cannot identify specific
    CVEs, novel zero-days, or memory corruption in client parsers.
  * No attachment binary inspection. Detected only by extension/heuristic.
    Production stacks add Joe Sandbox / Any.run / Cuckoo for static and
    dynamic binary analysis.
  * HTML parser is the Python stdlib `html.parser` — sufficient for clear
    constructs but a determined attacker can use parser-differential
    techniques (browsers vs. our parser see different DOMs). Production
    tools use full browser engines (e.g. headless Chromium) to align
    with what the recipient's client will actually render.
  * No detonation. URL Defense / Safe Links rewrite URLs and detonate
    them in a sandbox at click-time. Out of scope here.
  * Bypassable by inline-CSS class obfuscation, JS-driven DOM mutation,
    and HTML smuggling. Real defense requires multiple parser models.
"""

from __future__ import annotations

import email
import re
from email.message import Message
from html.parser import HTMLParser

# ============================================================================
# Constants
# ============================================================================

# Hard input cap to prevent regex denial-of-service (ReDoS) on adversarial
# input. 1 MB of body content is generous; legit email bodies rarely exceed
# 100 KB. Anything larger is auto-flagged as suspicious in itself.
MAX_BODY_BYTES = 1_048_576  # 1 MiB

# Severity tier scores
SEV_CRITICAL = "CRITICAL"
SEV_HIGH     = "HIGH"
SEV_MEDIUM   = "MEDIUM"
SEV_LOW      = "LOW"

# Score per severity tier (used by the aggregator)
TIER_SCORES = {
    SEV_CRITICAL: 80,
    SEV_HIGH:     50,
    SEV_MEDIUM:   28,
    SEV_LOW:      10,
}

# Decision thresholds for this method's verdict
SPAM_THRESHOLD       = 50
SHORT_CIRCUIT_FLOOR  = 80   # any single critical finding alone calls Spam


# ============================================================================
# Pattern definitions — compiled once at module load
# ============================================================================

# --- Tier 1 (Critical) ------------------------------------------------------

# Dangerous URI schemes anywhere in the body (href, src, action, formaction).
# javascript:/vbscript: are direct code execution surfaces. ms-msdt etc. are
# the Follina-class Office URI scheme abuse vectors (CVE-2022-30190).
_DANGEROUS_URI_RE = re.compile(
    r"\b(?P<scheme>"
    r"javascript|vbscript|"
    r"ms-msdt|ms-search|search-ms|ms-officecmd|ms-excel|ms-word|"
    r"ms-powerpoint|ms-visio|ms-access|ms-publisher|"
    r"file"
    r"):",
    re.IGNORECASE,
)

# UNC paths and SMB/WebDAV references — CVE-2023-23397 NTLM hash theft class.
# An Outlook reminder, calendar entry, or HTML href pointing to \\attacker\share
# triggers an SMB authentication attempt that leaks the user's NTLMv2 hash.
_UNC_PATH_RE = re.compile(
    r"(?:\\\\[a-z0-9._\-]+\\[a-z0-9._\-\\]+)"        # \\server\share\path
    r"|(?:\bsmb://[a-z0-9._\-]+)"                     # smb:// URI
    r"|(?:\bwebdav://[a-z0-9._\-]+)",                 # webdav://
    re.IGNORECASE,
)

# <script> in any context. Effectively never legitimate in mail bodies; mail
# clients strip them on render but a parser-differential attack could still
# expose recipients on non-conformant clients.
_SCRIPT_TAG_RE = re.compile(r"<script\b", re.IGNORECASE)

# --- Tier 2 (High) ----------------------------------------------------------

# meta refresh — auto-redirect on render
_META_REFRESH_RE = re.compile(
    r"<meta\b[^>]*http-equiv\s*=\s*[\"']?refresh[\"']?",
    re.IGNORECASE,
)

# iframe / embed / object — auto-load external content
_FRAME_TAG_RE = re.compile(
    r"<(?:iframe|embed|object|frame|frameset)\b",
    re.IGNORECASE,
)

# Inline SVG with executable subnodes — XSS bypass technique. SVG can carry
# <script>, <foreignObject>, <animate>, and event handlers.
_SVG_EXEC_RE = re.compile(
    r"<svg\b[^>]*>(?:(?!</svg>).)*?"
    r"(?:<script\b|<foreignObject\b|on\w+\s*=|<animate\b[^>]*\battributeName)"
    r"(?:(?!</svg>).)*?</svg>",
    re.IGNORECASE | re.DOTALL,
)

# data: URIs that carry HTML or SVG (payload smuggling)
_DATA_URI_RE = re.compile(
    r"data:(?:text/html|image/svg\+xml|application/xhtml\+xml)[;,]",
    re.IGNORECASE,
)

# Form with external action (credential phishing surface, no click needed
# if combined with auto-submit script — and even without, it's an exfil
# channel for any prefilled hidden fields).
_FORM_TAG_RE = re.compile(
    r"<form\b[^>]*\baction\s*=\s*[\"']https?://",
    re.IGNORECASE,
)

# EFAIL-class exfiltration: CSS background-image, list-style-image, etc.
# loading remote URLs. Triggers on render to disclose decrypted content
# (Poddebniak et al. 2018).
_CSS_REMOTE_LOAD_RE = re.compile(
    r"(?:background(?:-image)?|list-style(?:-image)?|content|cursor)\s*:\s*"
    r"url\s*\(\s*[\"']?https?://",
    re.IGNORECASE,
)

# Risky attachment file extensions. Not a guarantee — legitimate emails do
# attach these — but presence is a signal worth a finding.
_RISKY_EXT_RE = re.compile(
    r"\bfilename\s*=\s*[\"']?[^\"';\s]*?\."
    r"(iso|img|vhd|vhdx|lnk|scr|hta|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|"
    r"msi|msp|reg|cab|cpl|com|pif|cmd|bat|dll|sys|"
    r"docm|xlsm|pptm|dotm|xltm|potm|sldm|"
    r"jar|jnlp|appx|msix|application)"
    r"[\"']?",
    re.IGNORECASE,
)

# Double extensions like invoice.pdf.exe — classic obfuscation.
_DOUBLE_EXT_RE = re.compile(
    r"\bfilename\s*=\s*[\"']?[^\"';\s]*?"
    r"\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif)"
    r"\.(?:exe|scr|com|bat|vbs|js|hta|cmd|pif|lnk)"
    r"[\"']?",
    re.IGNORECASE,
)

# --- Tier 3 (Medium) --------------------------------------------------------

# HTML event handlers (onload, onerror, onclick, etc.). Most clients sanitize
# these but presence indicates intent and the parser-differential risk remains.
_EVENT_HANDLER_RE = re.compile(
    r"\bon(?:load|error|click|mouseover|mouseout|mousedown|mouseup|"
    r"focus|blur|submit|change|keydown|keyup|keypress|abort|unload|"
    r"resize|scroll|animation\w*|transition\w*|begin|end|repeat|"
    r"toggle|input|invalid|select|wheel|drag\w*|drop|copy|cut|paste)"
    r"\s*=",
    re.IGNORECASE,
)

# Tracking pixel — 1×1, hidden, or off-screen <img>.
_TRACKING_PIXEL_RE = re.compile(
    r"<img\b[^>]*?(?:"
    r"(?:width\s*=\s*[\"']?[01][\"']?[^>]*?height\s*=\s*[\"']?[01][\"']?)|"
    r"(?:height\s*=\s*[\"']?[01][\"']?[^>]*?width\s*=\s*[\"']?[01][\"']?)|"
    r"(?:style\s*=\s*[\"'][^\"']*?(?:"
    r"display\s*:\s*none|"
    r"visibility\s*:\s*hidden|"
    r"opacity\s*:\s*0|"
    r"width\s*:\s*[01]px|"
    r"height\s*:\s*[01]px|"
    r"position\s*:\s*absolute[^\"']*?(?:left|top)\s*:\s*-\d))"
    r")",
    re.IGNORECASE | re.DOTALL,
)

# Tracking parameters in any external resource src. Method 1 strips these
# before hashing; here we want to know they were present in the raw input.
_TRACKING_PARAM_RE = re.compile(
    r"<(?:img|link|script|iframe)\b[^>]*\bsrc\s*=\s*[\"'][^\"']*"
    r"[?&](?:utm_[a-z]+|mc_[a-z]+|pk_[a-z]+|fbclid|gclid|"
    r"track(?:ing)?_id|recipient|email|uid|tid|sid|cid)=",
    re.IGNORECASE,
)

# --- Tier 4 (Low — additive obfuscation indicators) -------------------------

# Unicode RTL override — used to make filenames or URLs appear different
# from what they actually are (e.g. cv\u202Egnp.exe renders as cv exe.png).
_RTL_OVERRIDE_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

# Zero-width characters — used to hide content from human readers and some
# parsers without affecting machine interpretation.
_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")

# Excessive HTML entity encoding (&#x.. ;) — common evasion of pattern-based
# scanners. We flag when the ratio is suspiciously high.
_HTML_ENTITY_RE = re.compile(r"&#x?[0-9a-f]+;", re.IGNORECASE)


# ============================================================================
# Finding object
# ============================================================================

class Finding:
    """Structured finding for forensic / SIEM ingestion."""

    __slots__ = ("signal", "severity", "score", "mitre", "evidence", "note")

    def __init__(self, signal: str, severity: str, mitre: str,
                 evidence: str, note: str = ""):
        self.signal   = signal
        self.severity = severity
        self.score    = TIER_SCORES[severity]
        self.mitre    = mitre
        self.evidence = evidence[:120]   # cap evidence length for log safety
        self.note     = note

    def to_dict(self) -> dict:
        return {
            "signal":   self.signal,
            "severity": self.severity,
            "score":    self.score,
            "mitre":    self.mitre,
            "evidence": self.evidence,
            "note":     self.note,
        }

    def __repr__(self) -> str:
        return f"<{self.severity} {self.signal} ({self.mitre})>"


# ============================================================================
# Body extraction
# ============================================================================

def _extract_body(msg: Message) -> str:
    """Reconstruct the rendered body (text/plain + text/html parts).
    Bounded to MAX_BODY_BYTES to prevent ReDoS on adversarial input."""
    parts: list[str] = []
    total = 0
    walker = msg.walk() if msg.is_multipart() else [msg]
    for part in walker:
        ctype = (part.get_content_type() or "").lower()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                payload = str(part.get_payload()).encode("utf-8", "replace")
            chunk = payload.decode(
                part.get_content_charset() or "utf-8", errors="replace"
            )
        except Exception:
            chunk = str(part.get_payload())
        if total + len(chunk) > MAX_BODY_BYTES:
            chunk = chunk[: MAX_BODY_BYTES - total]
            parts.append(chunk)
            break
        total += len(chunk)
        parts.append(chunk)
    return "\n".join(parts)


# ============================================================================
# DOM-tree-aware tag/attribute extractor (in addition to regex)
# ============================================================================

class _TagAuditor(HTMLParser):
    """Walks the HTML tree and records dangerous tags / attributes that are
    hard to detect reliably with regex (e.g. attributes spread across lines,
    unusual quoting). Complements the regex layer for parser-differential
    resistance."""

    DANGEROUS_TAGS = {"script", "iframe", "embed", "object", "frame",
                      "frameset", "applet", "base", "form"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tag_hits: list[tuple[str, dict]] = []
        self.event_handler_attrs: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() in self.DANGEROUS_TAGS:
            self.tag_hits.append((tag.lower(), attr_dict))
        for k, v in attr_dict.items():
            if k.startswith("on"):
                self.event_handler_attrs.append((k, v[:80]))


# ============================================================================
# MIME / header analysis
# ============================================================================

def _check_mime_mismatch(msg: Message, body: str) -> Finding | None:
    """Top-level Content-Type claims text/plain but body contains HTML.
    Parser-confusion attack surface (different MTAs / clients render
    different content)."""
    if msg.is_multipart():
        return None
    ctype = (msg.get_content_type() or "").lower()
    if ctype != "text/plain":
        return None
    if re.search(r"<(?:html|body|script|iframe|div|table)\b", body, re.IGNORECASE):
        return Finding(
            signal="mime_type_mismatch",
            severity=SEV_HIGH,
            mitre="T1027",
            evidence="Content-Type: text/plain but body contains HTML markup",
            note="Parser-confusion attack surface (RFC 2046 violation).",
        )
    return None


def _check_attachment_risk(msg: Message) -> list[Finding]:
    """Risky attachment extensions / double extensions / RTL override in
    filenames. CIS Controls v8 9.6 explicitly recommends blocking these."""
    findings: list[Finding] = []
    if not msg.is_multipart():
        return findings
    for part in msg.walk():
        cd = part.get("Content-Disposition", "") or ""
        ct = part.get("Content-Type", "") or ""
        haystack = f"{cd} {ct}"
        # Filename-based RTL override
        if _RTL_OVERRIDE_RE.search(haystack):
            findings.append(Finding(
                signal="rtl_override_filename",
                severity=SEV_HIGH,
                mitre="T1036.002",
                evidence="Unicode RTL/bidi override in filename",
                note="U+202A–U+202E used to disguise file extension.",
            ))
        if _DOUBLE_EXT_RE.search(haystack):
            findings.append(Finding(
                signal="double_extension",
                severity=SEV_HIGH,
                mitre="T1036.007",
                evidence="Filename uses double extension (e.g. invoice.pdf.exe)",
                note="Classic Windows-icon spoofing technique.",
            ))
        elif _RISKY_EXT_RE.search(haystack):
            findings.append(Finding(
                signal="risky_attachment_extension",
                severity=SEV_HIGH,
                mitre="T1566.001",
                evidence="Attachment uses high-risk extension",
                note="See CIS Controls v8 sub-control 9.6.",
            ))
        # Password-protected archive — sandbox cannot inspect
        if "encrypted" in haystack.lower() or "password" in haystack.lower():
            if re.search(r"\.(zip|rar|7z|gz|tar)\b", haystack, re.IGNORECASE):
                findings.append(Finding(
                    signal="password_protected_archive",
                    severity=SEV_HIGH,
                    mitre="T1027.002",
                    evidence="Encrypted archive — bypasses sandbox inspection",
                    note="Common malware delivery vector (Emotet, IcedID).",
                ))
    return findings


# ============================================================================
# Body content scanners
# ============================================================================

def _scan_body_critical(body: str, findings: list[Finding]) -> None:
    """Tier 1 — code execution surface."""
    # <script> tag
    if _SCRIPT_TAG_RE.search(body):
        findings.append(Finding(
            signal="script_tag",
            severity=SEV_CRITICAL,
            mitre="T1059.007",
            evidence="<script> tag present in HTML body",
            note="Code execution surface; effectively never legitimate in mail.",
        ))

    # Dangerous URI schemes
    m = _DANGEROUS_URI_RE.search(body)
    if m:
        scheme = m.group("scheme").lower()
        cve_note = {
            "ms-msdt":      "CVE-2022-30190 (Follina) class.",
            "ms-search":    "URI scheme abuse (Office RCE class).",
            "search-ms":    "URI scheme abuse (Office RCE class).",
            "javascript":   "Direct code execution surface.",
            "vbscript":     "Legacy code execution surface.",
            "file":         "Local filesystem reference; CVE-2023-23397 class.",
        }.get(scheme, "Dangerous URI scheme.")
        findings.append(Finding(
            signal=f"dangerous_uri_scheme:{scheme}",
            severity=SEV_CRITICAL,
            mitre="T1204.001",
            evidence=f"{scheme}: URI scheme used in message",
            note=cve_note,
        ))

    # UNC path / SMB / WebDAV (NTLM hash theft)
    m = _UNC_PATH_RE.search(body)
    if m:
        findings.append(Finding(
            signal="unc_smb_webdav_reference",
            severity=SEV_CRITICAL,
            mitre="T1187",
            evidence=m.group(0)[:80],
            note=("CVE-2023-23397 class — outbound SMB authentication leaks "
                  "NTLMv2 hash. Exploited in the wild by APT28."),
        ))


def _scan_body_high(body: str, findings: list[Finding]) -> None:
    """Tier 2 — automatic action / external content load."""
    if _META_REFRESH_RE.search(body):
        findings.append(Finding(
            signal="meta_refresh",
            severity=SEV_HIGH,
            mitre="T1204.001",
            evidence="<meta http-equiv='refresh'> auto-redirect",
            note="Triggers navigation without user interaction.",
        ))

    m = _FRAME_TAG_RE.search(body)
    if m:
        findings.append(Finding(
            signal="frame_or_object_tag",
            severity=SEV_HIGH,
            mitre="T1185",
            evidence=m.group(0)[:60],
            note="Auto-loads external content on render.",
        ))

    if _SVG_EXEC_RE.search(body):
        findings.append(Finding(
            signal="svg_with_executable_content",
            severity=SEV_HIGH,
            mitre="T1059.007",
            evidence="Inline SVG containing <script> or event handler",
            note="SVG-based XSS bypass; renders inline in many clients.",
        ))

    if _DATA_URI_RE.search(body):
        findings.append(Finding(
            signal="data_uri_html_payload",
            severity=SEV_HIGH,
            mitre="T1027",
            evidence="data: URI carrying HTML or SVG payload",
            note="HTML-smuggling technique; bypasses URL reputation checks.",
        ))

    if _FORM_TAG_RE.search(body):
        findings.append(Finding(
            signal="form_external_action",
            severity=SEV_HIGH,
            mitre="T1566.003",
            evidence="<form> with external action URL",
            note="Credential phishing surface; exfiltration channel.",
        ))

    if _CSS_REMOTE_LOAD_RE.search(body):
        findings.append(Finding(
            signal="css_remote_resource_load",
            severity=SEV_HIGH,
            mitre="T1071.004",
            evidence="CSS property loading remote URL on render",
            note=("EFAIL-class exfiltration vector (Poddebniak et al. 2018). "
                  "Remote CSS load triggers on render and can leak content."),
        ))


def _scan_body_medium(body: str, findings: list[Finding]) -> None:
    """Tier 3 — exfil / surveillance / event handlers."""
    if _EVENT_HANDLER_RE.search(body):
        handler_count = len(_EVENT_HANDLER_RE.findall(body))
        findings.append(Finding(
            signal="html_event_handler",
            severity=SEV_MEDIUM,
            mitre="T1059.007",
            evidence=f"{handler_count} HTML event handler(s) in body",
            note="onload/onerror/etc.; most clients sanitize but presence "
                 "still indicates intent.",
        ))

    if _TRACKING_PIXEL_RE.search(body):
        findings.append(Finding(
            signal="tracking_pixel",
            severity=SEV_MEDIUM,
            mitre="T1056.001",
            evidence="Hidden / 1×1 / off-screen <img> element",
            note="Read-receipt surveillance; leaks IP, user-agent, timestamp.",
        ))

    if _TRACKING_PARAM_RE.search(body):
        findings.append(Finding(
            signal="tracking_parameters",
            severity=SEV_MEDIUM,
            mitre="T1056.001",
            evidence="External resource loaded with tracking parameters",
            note="Recipient identification on render.",
        ))


def _scan_body_low(body: str, findings: list[Finding]) -> None:
    """Tier 4 — additive obfuscation indicators."""
    if _RTL_OVERRIDE_RE.search(body):
        findings.append(Finding(
            signal="rtl_override_in_body",
            severity=SEV_LOW,
            mitre="T1036.002",
            evidence="Unicode RTL/bidi override character in body",
            note="Used to disguise URL or filename rendering direction.",
        ))

    if _ZERO_WIDTH_RE.search(body):
        findings.append(Finding(
            signal="zero_width_chars",
            severity=SEV_LOW,
            mitre="T1027",
            evidence="Zero-width Unicode characters in body",
            note="Used to break keyword detection without altering display.",
        ))

    # Excessive HTML entity encoding (>5% of body length is suspicious)
    if body and len(body) > 200:
        entity_chars = sum(len(m) for m in _HTML_ENTITY_RE.findall(body))
        if entity_chars / max(len(body), 1) > 0.05:
            findings.append(Finding(
                signal="excessive_html_entity_encoding",
                severity=SEV_LOW,
                mitre="T1027",
                evidence=f"{entity_chars} bytes of HTML entity encoding",
                note="Pattern-scanner evasion technique.",
            ))


def _scan_dom_tree(body: str, findings: list[Finding]) -> None:
    """DOM-tree pass complements the regex pass — catches dangerous tags
    spread across multiple lines or with unusual quoting that might evade
    the flat regex pattern."""
    auditor = _TagAuditor()
    try:
        auditor.feed(body)
    except Exception:
        return  # malformed HTML — let regex layer handle

    # Already-recorded signals (avoid double-counting from regex pass)
    seen = {f.signal for f in findings}

    if any(t == "base" for t, _ in auditor.tag_hits) and \
            "base_tag_override" not in seen:
        findings.append(Finding(
            signal="base_tag_override",
            severity=SEV_HIGH,
            mitre="T1185",
            evidence="<base> tag rewrites all relative URLs in document",
            note="Used to silently redirect every relative link to attacker.",
        ))


# ============================================================================
# Public entry point
# ============================================================================

def check(raw: str) -> dict:
    """Run zero-click attack-surface detection on a raw RFC 5322 message.

    Returns a dict with: method, verdict, score, evidence, findings.
    The `findings` field is a list of structured Finding dicts suitable
    for SIEM / forensic-report ingestion.
    """
    try:
        msg = email.message_from_string(raw)
    except Exception as e:
        return {
            "method":   "zero_click",
            "verdict":  "inconclusive",
            "score":    0,
            "evidence": f"could not parse message ({e})",
            "findings": [],
        }

    body = _extract_body(msg)
    findings: list[Finding] = []

    # Body scanners — order doesn't matter; scoring is additive
    _scan_body_critical(body, findings)
    _scan_body_high(body, findings)
    _scan_body_medium(body, findings)
    _scan_body_low(body, findings)
    _scan_dom_tree(body, findings)

    # Header / MIME-level checks
    mime_finding = _check_mime_mismatch(msg, body)
    if mime_finding:
        findings.append(mime_finding)
    findings.extend(_check_attachment_risk(msg))

    # Aggregate score
    if not findings:
        return {
            "method":   "zero_click",
            "verdict":  "ham",
            "score":    0,
            "evidence": "No zero-click attack-surface indicators found.",
            "findings": [],
        }

    score = min(sum(f.score for f in findings), 100)

    # Verdict logic:
    #   - any single CRITICAL finding ≥ short-circuit floor → spam
    #   - aggregate ≥ 50 → spam
    #   - 25–49 → spam (low confidence; still contributes to orchestrator)
    #   - < 25  → ham
    has_critical = any(f.severity == SEV_CRITICAL for f in findings)
    if has_critical or score >= SPAM_THRESHOLD:
        verdict = "spam"
    elif score >= 25:
        verdict = "spam"   # low-confidence flag
    else:
        verdict = "ham"

    # Compact human-readable evidence: top findings by severity
    findings.sort(key=lambda f: -f.score)
    evidence = "; ".join(
        f"{f.signal}[{f.severity[:1]}/{f.score}/{f.mitre}]"
        for f in findings[:5]
    )
    if len(findings) > 5:
        evidence += f"; +{len(findings) - 5} more"

    return {
        "method":   "zero_click",
        "verdict":  verdict,
        "score":    score,
        "evidence": evidence,
        "findings": [f.to_dict() for f in findings],
    }