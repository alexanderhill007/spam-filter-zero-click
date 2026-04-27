"""
Method 1: Signature-Based Detection
====================================

CISSP mapping: Domain 7 (Security Operations) — signature-based vs. anomaly-based
detection; Domain 3 (Cryptography) — properties of cryptographic vs. fuzzy hash
functions.

Theory
------
Signature-based detection compares an artifact (file, email, packet) against a
database of known-bad fingerprints. Used by AV engines, IDS rules (Snort/Suricata),
YARA, and spam filters. Strengths: very low false positives. Weaknesses: zero-day
blind, defeated by polymorphism — the same problem AV vendors hit in the early
2000s (NIST SP 800-83 Rev.1 §4.1).

This module implements two layers:
  (1) Exact hash matching — SHA-256 of normalized email body.
  (2) Fuzzy hash matching — Jaccard similarity over word n-gram shingles
      (a pure-Python equivalent of ssdeep / TLSH context-triggered piecewise
      hashing). Tolerates the recipient-name and timestamp churn that defeats
      exact hashing on real spam.

References
----------
- NIST SP 800-83 Rev.1, "Guide to Malware Incident Prevention and Handling"
- NIST SP 800-177 Rev.1 §6.3, "Content Filtering"
- Kornblum, J. (2006). "Identifying almost identical files using context
  triggered piecewise hashing." DFRWS.
"""

import hashlib
import json
import re
from pathlib import Path

# ----- normalization -------------------------------------------------------

_WHITESPACE_RE = re.compile(r"\s+")
_RECIPIENT_TOKEN_RE = re.compile(
    r"\b(?:dear|hello|hi|hey)\s+[a-z][a-z\-']{1,30}\b", re.IGNORECASE
)
_DATE_RE = re.compile(
    r"\b\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b|"
    r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}",
    re.IGNORECASE,
)
_TRACKING_RE = re.compile(r"[?&](?:utm_[a-z]+|mc_[a-z]+|pk_[a-z]+|fbclid|gclid)=[^&\s\"']+")
_NUMBER_RE = re.compile(r"\b\d[\d,]*\.?\d*\b")
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def normalize_body(text: str) -> str:
    """Strip recipient-specific and time-specific tokens so the same
    underlying spam template hashes consistently across recipients."""
    text = text.lower()
    text = _RECIPIENT_TOKEN_RE.sub("dear recipient", text)
    text = _DATE_RE.sub("<date>", text)
    text = _TRACKING_RE.sub("", text)
    text = _NUMBER_RE.sub("<num>", text)
    def _host_only(m):
        url = m.group(0)
        try:
            from urllib.parse import urlparse
            return "url:" + (urlparse(url).hostname or "")
        except Exception:
            return "url:?"
    text = _URL_RE.sub(_host_only, text)
    text = _WHITESPACE_RE.sub(" ", text)
    return text.strip()


# ----- exact hash ----------------------------------------------------------

def sha256_signature(body: str) -> str:
    """SHA-256 of the *normalized* email body. Hex-encoded."""
    norm = normalize_body(body)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


# ----- fuzzy hash (n-gram Jaccard) -----------------------------------------
# Pure-Python stand-in for ssdeep/TLSH that is portable across Windows /
# macOS / Linux without C-extension build pain. Math is Jaccard similarity
# over word-level 5-grams ("shingles").

SHINGLE_SIZE = 5


def shingles(body: str, k: int = SHINGLE_SIZE) -> set:
    norm = normalize_body(body)
    tokens = norm.split()
    if len(tokens) < k:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


# ----- signature database --------------------------------------------------

class SignatureDB:
    """Loads / persists known-spam signatures."""

    def __init__(self, exact_path: Path = None, fuzzy_path: Path = None):
        base = Path(__file__).resolve().parent.parent / "signatures"
        self.exact_path = exact_path or (base / "known_spam_hashes.txt")
        self.fuzzy_path = fuzzy_path or (base / "known_spam_fuzzy.json")
        self.exact_hashes = self._load_exact()
        self.fuzzy_corpus = self._load_fuzzy()

    def _load_exact(self) -> set:
        if not self.exact_path.exists():
            return set()
        return {
            line.strip().split("#", 1)[0].strip()
            for line in self.exact_path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        }

    def _load_fuzzy(self) -> list:
        if not self.fuzzy_path.exists():
            return []
        data = json.loads(self.fuzzy_path.read_text())
        return [(entry["id"], {tuple(s) for s in entry["shingles"]}) for entry in data]

    def add_sample(self, sample_id: str, body: str):
        h = sha256_signature(body)
        if h not in self.exact_hashes:
            with self.exact_path.open("a") as f:
                f.write(f"{h}  # {sample_id}\n")
            self.exact_hashes.add(h)
        sh = shingles(body)
        self.fuzzy_corpus.append((sample_id, sh))
        self._persist_fuzzy()

    def _persist_fuzzy(self):
        data = [
            {"id": sid, "shingles": [list(s) for s in sh]}
            for sid, sh in self.fuzzy_corpus
        ]
        self.fuzzy_path.write_text(json.dumps(data, indent=2))


# ----- detection entry point ----------------------------------------------

FUZZY_MATCH_THRESHOLD = 0.30      # partial match — contributes to aggregate
FUZZY_HIGH_CONFIDENCE = 0.70      # near-duplicate — short-circuit territory


def check(body: str, db: SignatureDB) -> dict:
    sig = sha256_signature(body)
    if sig in db.exact_hashes:
        return {
            "method": "signature",
            "verdict": "spam",
            "score": 100,
            "evidence": f"Exact SHA-256 match against known-spam DB ({sig[:12]}…)",
        }

    sample_shingles = shingles(body)
    best_id, best_score = None, 0.0
    for sid, sh in db.fuzzy_corpus:
        score = jaccard(sample_shingles, sh)
        if score > best_score:
            best_id, best_score = sid, score

    if best_score >= FUZZY_HIGH_CONFIDENCE:
        return {
            "method": "signature",
            "verdict": "spam",
            "score": 95,
            "evidence": f"Fuzzy match {best_score:.0%} against known spam {best_id}",
        }
    if best_score >= FUZZY_MATCH_THRESHOLD:
        return {
            "method": "signature",
            "verdict": "spam",
            "score": int(70 * best_score / FUZZY_HIGH_CONFIDENCE),
            "evidence": f"Partial fuzzy match {best_score:.0%} against {best_id}",
        }
    return {
        "method": "signature",
        "verdict": "ham",
        "score": 0,
        "evidence": f"No signature or fuzzy match (best similarity {best_score:.0%})",
    }