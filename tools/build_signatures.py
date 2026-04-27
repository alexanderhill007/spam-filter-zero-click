#!/usr/bin/env python3
"""
build_signatures.py — populate the known-spam signature DB from a corpus of
.txt spam samples.
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from methods.signature import SignatureDB
from spam_filter import get_body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", help="Spam .txt files to ingest")
    ap.add_argument("--reset", action="store_true",
                    help="Wipe existing signature DB before adding")
    args = ap.parse_args()

    sig_dir = ROOT / "signatures"
    sig_dir.mkdir(exist_ok=True)
    if args.reset:
        for p in (sig_dir / "known_spam_hashes.txt", sig_dir / "known_spam_fuzzy.json"):
            if p.exists():
                p.unlink()

    db = SignatureDB()
    added = 0
    for path_str in args.paths:
        path = Path(path_str)
        if path.is_file():
            raw = path.read_text(encoding="utf-8", errors="replace")
            db.add_sample(path.name, get_body(raw))
            added += 1
            print(f"  added: {path.name}")

    print(f"\nDone. {added} sample(s) ingested.")


if __name__ == "__main__":
    main()