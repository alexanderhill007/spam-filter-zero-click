#!/usr/bin/env python3
"""
spam_filter.py — multi-method advertisement-spam filter
=========================================================

Usage
-----
  python spam_filter.py samples/spam_01.txt
  python spam_filter.py samples/ham_01.txt --verbose
  python spam_filter.py --no-network samples/spam_01.txt
  python spam_filter.py --batch samples/

Methods (per assignment + bonus)
--------------------------------
  1. Signature-based  — SHA-256 exact + Jaccard fuzzy match
  2. Hyperlink trust  — TLS cert, shorteners, raw-IP, brand impersonation,
                        abused TLDs, domain age (WHOIS), display/href mismatch
  3. Unsubscribe      — RFC 2369 List-Unsubscribe + RFC 8058 one-click
                        + body-level unsubscribe link
  4. Authentication   — SPF / DKIM / DMARC verdict from Authentication-Results
                        header (RFC 8601) — bonus method

Final decision is a weighted aggregate of the four methods. Any single high-
confidence verdict (signature exact match, DMARC fail, etc.) trips the
decision on its own, mirroring how production gateways (Proofpoint, Mimecast,
Defender for O365) do hierarchical scoring.

CISSP framing
-------------
  Domain 1 (Risk/Compliance)   — CAN-SPAM, GDPR, regulatory framing
  Domain 3 (Cryptography)      — hashing primitives, DKIM signatures
  Domain 4 (Comms/Network)     — SMTP, SPF/DKIM/DMARC, URL filtering
  Domain 7 (Security Ops)      — signature-based vs. heuristic detection
  Domain 8 (Software Dev)      — defense-in-depth, layered fail-safe defaults
"""

import argparse
import email
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from methods import signature, hyperlinks, unsubscribe, authentication


# ---- weights & thresholds -------------------------------------------------

WEIGHTS = {
    "signature":      1.00,   # high precision — when it fires, we trust it
    "hyperlinks":     0.65,
    "unsubscribe":    0.50,
    "authentication": 0.85,   # DMARC fail is a near-definitive spoof signal
}

DECISION_THRESHOLD = 50            # weighted aggregate above this = Spam
SHORT_CIRCUIT_THRESHOLD = 90       # any single method ≥ this = Spam


# ---- pipeline -------------------------------------------------------------

def get_body(raw: str) -> str:
    """Return decoded plain+HTML text of the message for content checks."""
    msg = email.message_from_string(raw)
    parts = []
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() in ("text/plain", "text/html"):
                try:
                    parts.append(p.get_payload(decode=True).decode(
                        p.get_content_charset() or "utf-8", errors="replace"))
                except Exception:
                    parts.append(str(p.get_payload()))
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                parts.append(payload.decode(
                    msg.get_content_charset() or "utf-8", errors="replace"))
            else:
                parts.append(str(msg.get_payload()))
        except Exception:
            parts.append(str(msg.get_payload()))
    return "\n".join(parts)


def evaluate(raw: str, db: signature.SignatureDB, *, network: bool = True) -> dict:
    body = get_body(raw)
    results = {
        "signature":      signature.check(body, db),
        "hyperlinks":     hyperlinks.check(body, network=network),
        "unsubscribe":    unsubscribe.check(raw),
        "authentication": authentication.check(raw),
    }

    # Weighted aggregate (only count methods that produced a real verdict)
    weighted_sum = 0.0
    weight_total = 0.0
    short_circuit = False
    for name, res in results.items():
        if res["verdict"] == "inconclusive":
            continue
        w = WEIGHTS[name]
        weighted_sum += w * res["score"]
        weight_total += w
        if res["score"] >= SHORT_CIRCUIT_THRESHOLD and res["verdict"] == "spam":
            short_circuit = True

    aggregate = (weighted_sum / weight_total) if weight_total else 0.0
    is_spam = short_circuit or aggregate >= DECISION_THRESHOLD
    return {
        "verdict": "Spam" if is_spam else "Not Spam",
        "aggregate_score": round(aggregate, 1),
        "short_circuit": short_circuit,
        "methods": results,
    }


# ---- CLI ------------------------------------------------------------------

def _format_verbose(path: Path, result: dict) -> str:
    out = []
    out.append(f"=== {path.name} ===")
    out.append(f"Verdict: {result['verdict']}  "
               f"(aggregate score: {result['aggregate_score']:.1f}/100"
               f"{', short-circuit triggered' if result['short_circuit'] else ''})")
    out.append("")
    for name, res in result["methods"].items():
        verdict = res["verdict"].upper()
        out.append(f"  [{name:14}] {verdict:13} score={res['score']:>3}")
        out.append(f"                  {res['evidence']}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="Multi-method advertisement-spam filter.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("path", help="Path to email .txt file (or folder with --batch)")
    ap.add_argument("--batch", action="store_true",
                    help="Treat path as a directory; evaluate every .txt in it")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Print per-method evidence")
    ap.add_argument("--no-network", action="store_true",
                    help="Skip TLS-cert and WHOIS lookups (offline demo mode)")
    args = ap.parse_args()

    db = signature.SignatureDB()
    target = Path(args.path)

    if args.batch:
        if not target.is_dir():
            print(f"--batch requires a directory; got {target}", file=sys.stderr)
            sys.exit(2)
        for p in sorted(target.glob("*.txt")):
            raw = p.read_text(encoding="utf-8", errors="replace")
            result = evaluate(raw, db, network=not args.no_network)
            if args.verbose:
                print(_format_verbose(p, result))
                print()
            else:
                print(f"{p.name:30}  {result['verdict']}")
    else:
        if not target.is_file():
            print(f"file not found: {target}", file=sys.stderr)
            sys.exit(2)
        raw = target.read_text(encoding="utf-8", errors="replace")
        result = evaluate(raw, db, network=not args.no_network)
        if args.verbose:
            print(_format_verbose(target, result))
        else:
            print(result["verdict"])


if __name__ == "__main__":
    main()