"""
Method 4 (Bonus): Sender Authentication — SPF / DKIM / DMARC
=============================================================

CISSP mapping: Domain 4 (Communication & Network Security) — sender
authentication; Domain 3 (Cryptography) — DKIM digital signatures.

Theory
------
Three layered domain-authentication standards live "above" content filtering
in NIST SP 800-177 Rev.1's UBE pipeline:

  - SPF   (RFC 7208) — receiver checks the sending IP against the From-domain's
                       published SPF DNS record. Pass / Fail / SoftFail / None.
  - DKIM  (RFC 6376) — sender signs the message body & key headers with a
                       private key; receiver fetches the public key from DNS
                       (selector._domainkey.example.com) and verifies.
  - DMARC (RFC 7489) — policy layer on top: domain owner declares what to do
                       when SPF/DKIM fail (none / quarantine / reject) AND
                       requires alignment between the From-domain and the
                       authenticated identifier.

When a Gmail/Outlook/Proofpoint MTA receives mail, it does the SPF/DKIM/DMARC
checks itself and stamps the result into the message in an `Authentication-
Results` header (RFC 8601). Because we are filtering already-delivered mail
exported from Gmail, parsing that header is the most reliable approach.

References
----------
- RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8601 (Auth-Results)
- NIST SP 800-177 Rev.1 §§ 4.4–4.6
- CIS Controls v8, Control 9.5 ("Implement DMARC")
"""

import email
import re

_AUTH_RES_PATTERNS = {
    "spf":   re.compile(r"\bspf\s*=\s*([a-z]+)",   re.IGNORECASE),
    "dkim":  re.compile(r"\bdkim\s*=\s*([a-z]+)",  re.IGNORECASE),
    "dmarc": re.compile(r"\bdmarc\s*=\s*([a-z]+)", re.IGNORECASE),
}


def _parse_auth_results(msg) -> dict:
    """Extract spf/dkim/dmarc verdicts from Authentication-Results header(s)."""
    out = {"spf": None, "dkim": None, "dmarc": None}
    for header in msg.get_all("Authentication-Results", []):
        for key, pattern in _AUTH_RES_PATTERNS.items():
            if out[key] is None:
                m = pattern.search(header)
                if m:
                    out[key] = m.group(1).lower()
    return out


# Severity weights — "fail" is much worse than "softfail"; "pass" is good;
# missing is unknown (no penalty).
SCORE_BY_VERDICT = {
    "pass":      0,
    "neutral":  10,
    "softfail": 20,
    "none":     10,
    "policy":   15,
    "permerror":25,
    "temperror":15,
    "fail":     40,
}


def check(raw: str) -> dict:
    try:
        msg = email.message_from_string(raw)
    except Exception as e:
        return {
            "method": "authentication",
            "verdict": "inconclusive",
            "score": 0,
            "evidence": f"could not parse message ({e})",
        }

    results = _parse_auth_results(msg)
    if all(v is None for v in results.values()):
        return {
            "method": "authentication",
            "verdict": "inconclusive",
            "score": 0,
            "evidence": "No Authentication-Results header — cannot evaluate SPF/DKIM/DMARC.",
        }

    score = 0
    parts = []
    for key in ("spf", "dkim", "dmarc"):
        v = results[key]
        if v is None:
            parts.append(f"{key}=missing")
        else:
            parts.append(f"{key}={v}")
            score += SCORE_BY_VERDICT.get(v, 0)

    score = min(score, 100)

    # DMARC fail = "this sender lied about who they are" — strongest single
    # signal in the entire filter. Short-circuit material.
    if results.get("dmarc") == "fail":
        verdict = "spam"
    elif score >= 40:
        verdict = "spam"
    elif score >= 20:
        verdict = "spam"   # lower-confidence flag
    else:
        verdict = "ham"

    return {
        "method": "authentication",
        "verdict": verdict,
        "score": score,
        "evidence": " · ".join(parts),
    }