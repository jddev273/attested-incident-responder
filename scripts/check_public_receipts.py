#!/usr/bin/env python3
"""Verify the public Creditcoin payment lifecycle, not just pass/fail status."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

RECEIPTS = Path(__file__).resolve().parents[1] / "fixtures" / "public-receipts.json"
API = "https://creditcoin-testnet.blockscout.com/api/v2/transactions/{tx}"
VAULT = "0x1EF3B69DaF030b41449c5E1a31720fb28A8767Cc"


def _fetch(tx: str) -> dict:
    req = urllib.request.Request(API.format(tx=tx), headers={"User-Agent": "AIR-judge-demo/1.0"})
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def _addr(payload: dict, key: str) -> str:
    value = payload.get(key) or {}
    return str(value.get("hash") or "").lower()


def _check(row: dict, payload: dict, previous_block: int | None) -> tuple[list[str], int | None]:
    errors: list[str] = []
    status = str(payload.get("status") or "").lower()
    if status != str(row["status"]).lower():
        errors.append(f"status {status!r} != {row['status']!r}")
    method = str(payload.get("method") or "").lower()
    if method != str(row["method"]).lower():
        errors.append(f"method {method!r} != {row['method']!r}")
    if _addr(payload, "to") != row["to"].lower():
        errors.append(f"to {_addr(payload, 'to')} != {row['to'].lower()}")
    if _addr(payload, "from") != row["from"].lower():
        errors.append(f"from {_addr(payload, 'from')} != {row['from'].lower()}")
    block = payload.get("block_number")
    if not isinstance(block, int):
        errors.append("missing block_number")
    elif block < int(row["min_block"]):
        errors.append(f"block {block} before expected {row['min_block']}")
    elif previous_block is not None and block <= previous_block:
        errors.append(f"block {block} is not after previous {previous_block}")
    expected_revert = row.get("revert_selector")
    raw = ((payload.get("revert_reason") or {}) if isinstance(payload.get("revert_reason"), dict) else {}).get("raw")
    if expected_revert:
        if str(raw or "").lower() != expected_revert.lower():
            errors.append(f"revert {raw!r} != {expected_revert}")
    elif raw:
        errors.append(f"unexpected revert {raw!r}")
    return errors, block if isinstance(block, int) else previous_block


def main() -> int:
    rows = json.loads(RECEIPTS.read_text(encoding="utf-8"))
    failed = 0
    previous = None
    for row in rows:
        try:
            payload = _fetch(row["tx"])
        except Exception as exc:
            print(f"[FAIL] {row['name']}: receipt fetch failed ({type(exc).__name__})")
            failed += 1
            continue
        errors, previous = _check(row, payload, previous)
        if errors:
            print(f"[FAIL] {row['name']}: {'; '.join(errors)}")
            failed += 1
        else:
            print(f"[PASS] {row['name']}: same vault {VAULT} method {row['method']} block-ordered")
    if failed == 0:
        print("[PASS] causal payment lifecycle: success -> PaymentsFrozen revert -> success")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
