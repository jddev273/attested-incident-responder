#!/usr/bin/env python3
"""Verify the public Creditcoin lifecycle: payments, responder events, and incident id."""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

RECEIPTS = Path(__file__).resolve().parents[1] / "fixtures" / "public-receipts.json"
RPC_URL = os.environ.get("CREDITCOIN_RPC_URL", "https://rpc.cc3-testnet.creditcoin.network")


def rpc(method: str, params: list[object]) -> object:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        RPC_URL, data=body, headers={"Content-Type": "application/json", "User-Agent": "AIR-judge-demo/1.0"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if payload.get("error"):
        raise RuntimeError(str(payload["error"]))
    return payload["result"]


def _incident_topic(incident_id: str) -> str:
    return "0x" + incident_id[2:].lower().rjust(64, "0")


def main() -> int:
    spec = json.loads(RECEIPTS.read_text(encoding="utf-8"))
    vault = spec["vault"].lower()
    responder = spec["responder"].lower()
    operator = spec["operator"].lower()
    selector = spec["execute_payment_selector"].lower()
    incident_topic = _incident_topic(spec["incident_id"])
    failed = 0
    previous = None
    for row in spec["steps"]:
        try:
            receipt = rpc("eth_getTransactionReceipt", [row["tx"]])
            tx = rpc("eth_getTransactionByHash", [row["tx"]])
        except Exception as exc:
            print(f"[FAIL] {row['name']}: fetch failed ({type(exc).__name__})")
            failed += 1
            continue
        errors: list[str] = []
        status_ok = str(receipt.get("status") or "").lower() in {"0x1", "1"}
        expected_ok = row["status"] == "ok"
        if status_ok != expected_ok:
            errors.append(f"status {receipt.get('status')!r}")
        expected_to = vault if row["to"] == "vault" else responder
        if str(tx.get("to") or "").lower() != expected_to:
            errors.append(f"to {tx.get('to')}")
        if str(tx.get("from") or "").lower() != operator:
            errors.append("wrong sender")
        block = int(receipt["blockNumber"], 16) if receipt.get("blockNumber") else None
        if block is None:
            errors.append("missing block")
        elif previous is not None and block <= previous:
            errors.append(f"block {block} not after {previous}")
        if row["kind"] == "payment":
            data = str(tx.get("input") or tx.get("data") or "")
            if not data.lower().startswith(selector):
                errors.append("not executePayment")
            if row.get("revert_selector") and status_ok:
                errors.append("expected revert")
        if row.get("require_incident_topic"):
            topics = []
            for log in receipt.get("logs") or []:
                topics.extend(str(t).lower() for t in (log.get("topics") or []))
            if incident_topic not in topics:
                errors.append("missing incident id topic")
        if errors:
            print(f"[FAIL] {row['name']}: {'; '.join(errors)}")
            failed += 1
        else:
            print(f"[PASS] {row['name']}: block {block}")
        if isinstance(block, int):
            previous = block
    if failed == 0:
        print(f"[PASS] same incident {spec['incident_id']} binds containment, freeze, recovery, and restored payment")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
