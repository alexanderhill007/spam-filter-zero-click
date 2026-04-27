"""
Method 3: Unsubscribe Link Presence
====================================

CISSP mapping: Domain 1 (Security & Risk Management) — legal & regulatory
compliance; Domain 4 (Communication & Network Security) — RFC-defined headers.

Theory
------
Legitimate commercial mailers in the US are required by the CAN-SPAM Act
(15 U.S.C. § 7704(a)(3)–(5)) to provide a working opt-out mechanism. In the
EU, GDPR Article 21 grants a right to object to direct marketing. The IETF
codified the technical mechanism in:

  - RFC 2369 (1998): the `List-Unsubscribe` header — a mailto: or https URI
  - RFC 8058 (2017): one-click unsubscribe via `List-Unsubscribe-Post:
                     List-Unsubscribe=One-Click`

Therefore:

  * Absence of List-Unsubscribe header AND no body unsubscribe link
      → very likely spam or non-compliant marketing
  * Presence does not prove legitimacy (spammers also include them) — but
    its absence is a meaningful negative signal.

We treat this as a *compliance* check, not a malice check.

References
----------
- RFC 2369 (Chandhok & Wenger): "The Use of URLs as Meta-Syntax for Core
  Mail List Commands and their Transport through Message Header Fields"
- RFC 8058 (Levine): "Signaling One-Click Functionality for List Email Headers"
- 15 U.S.C. §§ 7701–7713 ("CAN-SPAM Act of 2003")
- NIST SP 800-177 Rev.1 §6.3 ("Content Filtering")
"""

import email
import re
from email.message import Message


def _get_headers_and_body(raw: str):
    """Parse a raw email .txt/.eml string. Returns (Message, body_text)."""
    msg = email.message_from_string(raw)
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    body_parts.append(part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    ))
                except Exception:
                    body_parts.append(str(part.get_payload()))
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body_parts.append(payload.decode(
                    msg.get_content_charset() or "utf-8", errors="replace"
                ))
            else:
                body_parts.append(str(msg.get_payload()))
        except Exception:
            body_parts.append(str(msg.get_payload()))
    return msg, "\n".join(body_parts)


def _has_list_unsubscribe(msg: Message) -> tuple[bool, str | None]:
    """RFC 2369 List-Unsubscribe header."""
    val = msg.get("List-Unsubscribe")
    if not val:
        return False, None
    return True, val.strip()


def _has_one_click(msg: Message) -> bool:
    """RFC 8058 one-click unsubscribe."""
    val = msg.get("List-Unsubscribe-Post", "").lower()
    return "one-click" in val


_BODY_UNSUB_RE = re.compile(
    r"<a\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"'][^>]*>([^<]*?\bunsubscribe\b[^<]*)</a>",
    re.IGNORECASE | re.DOTALL,
)
_BODY_UNSUB_PLAIN_RE = re.compile(
    r"\b(?:to\s+)?unsubscribe\b[^.\n]{0,80}?(https?://[^\s<>\"')\]]+)",
    re.IGNORECASE,
)


def _has_body_unsub(body: str) -> tuple[bool, str | None]:
    """Look for an unsubscribe link inside the rendered body (HTML or plain)."""
    m = _BODY_UNSUB_RE.search(body)
    if m:
        return True, m.group(1)
    m = _BODY_UNSUB_PLAIN_RE.search(body)
    if m:
        return True, m.group(1)
    return False, None


def check(raw: str) -> dict:
    """Run unsubscribe-presence detection on a raw email string."""
    try:
        msg, body = _get_headers_and_body(raw)
    except Exception as e:
        return {
            "method": "unsubscribe",
            "verdict": "inconclusive",
            "score": 0,
            "evidence": f"could not parse message ({e})",
        }

    has_header, header_val = _has_list_unsubscribe(msg)
    has_oneclick = _has_one_click(msg)
    has_body, body_url = _has_body_unsub(body)

    if has_header and has_oneclick:
        return {
            "method": "unsubscribe",
            "verdict": "ham",
            "score": 0,
            "evidence": f"RFC 8058 one-click unsubscribe present: {header_val[:60]}",
        }
    if has_header:
        return {
            "method": "unsubscribe",
            "verdict": "ham",
            "score": 5,
            "evidence": f"RFC 2369 List-Unsubscribe header present: {header_val[:60]}",
        }
    if has_body:
        return {
            "method": "unsubscribe",
            "verdict": "ham",
            "score": 15,
            "evidence": f"Body-level unsubscribe link present: {body_url[:60]}",
        }
    return {
        "method": "unsubscribe",
        "verdict": "spam",
        "score": 60,
        "evidence": (
            "No List-Unsubscribe header (RFC 2369), no one-click "
            "(RFC 8058), and no body unsubscribe link — "
            "non-compliant with CAN-SPAM §7704(a)(5)."
        ),
    }