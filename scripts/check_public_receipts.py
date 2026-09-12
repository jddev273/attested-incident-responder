#!/usr/bin/env python3
"""Confirm the public Creditcoin receipts still show the demonstrated payment lifecycle."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

RECEIPTS = Path(__file__).resolve().parents[1] / "fixtures" / "public-receipts.json"
API = "https://creditcoin-testnet.blockscout.com/api/v2/transactions/{tx}"


def main() -> int:
    rows = json.loads(RECEIPTS.read_text(encoding="utf-8"))
    failed = 0
    for row in rows:
        url = API.format(tx=row["tx"])
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AIR-judge-demo/1.0"})
            with urllib.request.urlopen(req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            print(f"[FAIL] {row['name']}: receipt fetch failed ({type(exc).__name__})")
            failed += 1
            continue
        status = str(payload.get("status", "")).lower()
        expected = str(row["status"])
        ok = (expected == "1" and status in {"1", "ok", "success"}) or (
            expected == "0" and status in {"0", "error", "failed"}
        )
        if not ok and expected == "0" and payload.get("result") == "0":
            ok = True
        if ok:
            print(f"[PASS] {row['name']}: {row['tx']} status {expected}")
        else:
            print(f"[FAIL] {row['name']}: expected status {expected}, got {status!r}")
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
