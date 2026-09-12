#!/usr/bin/env python3
"""Verify the public Creditcoin lifecycle: payments, named responder events, and incident id."""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))
from air_recommender import keccak256  # noqa: E402

RECEIPTS = ROOT / "fixtures" / "public-receipts.json"
RPC_URL = os.environ.get("CREDITCOIN_RPC_URL", "https://rpc.cc3-testnet.creditcoin.network")
EVENT_SIGS = {
    "ContainmentApplied": "ContainmentApplied(bytes32,uint8,uint8,bytes32)",
    "RecommendationStrengthened": "RecommendationStrengthened(bytes32,bytes32,uint8,bytes32)",
    "RecoveryApplied": "RecoveryApplied(bytes32,uint8,bytes32)",
}


def rpc(method: str, params: list[object]) -> object:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        RPC_URL, data=body, headers={"Content-Type": "application/json", "User-Agent": "AIR-judge-demo/1.0"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if payload.get("error"):
        raise RuntimeError(payload["error"])
    return payload["result"]


def topic0(signature: str) -> str:
    return "0x" + keccak256(signature.encode()).hex()


def word(data: str, index: int) -> int:
    raw = data[2:] if data.startswith("0x") else data
    chunk = raw[index * 64 : (index + 1) * 64]
    if len(chunk) != 64:
        raise ValueError("event data too short")
    return int(chunk, 16)


def revert_selector(tx: dict, block_hex: str) -> str:
    try:
        rpc(
            "eth_call",
            [
                {
                    "from": tx["from"],
                    "to": tx["to"],
                    "data": tx.get("input") or tx.get("data"),
                    "value": tx.get("value", "0x0"),
                    "gas": tx.get("gas"),
                },
                block_hex,
            ],
        )
    except RuntimeError as exc:
        err = exc.args[0] if exc.args else {}
        if isinstance(err, dict):
            data = str(err.get("data") or "")
            if isinstance(err.get("data"), dict):
                data = str(err["data"].get("data") or err["data"].get("hex") or "")
            if data.startswith("0x") and len(data) >= 10:
                return data[:10].lower()
        text = str(exc)
        if "0xd5d5c0c9" in text.lower():
            return "0xd5d5c0c9"
        raise
    raise RuntimeError("expected PaymentsFrozen revert, call succeeded")


def find_event(logs: list, responder: str, signature: str, incident_id: str) -> dict | None:
    want = topic0(EVENT_SIGS[signature])
    incident = "0x" + incident_id[2:].lower().rjust(64, "0")
    for log in logs:
        if str(log.get("address") or "").lower() != responder:
            continue
        topics = [str(t).lower() for t in (log.get("topics") or [])]
        if len(topics) >= 2 and topics[0] == want and topics[1] == incident:
            return log
    return None


def main() -> int:
    spec = json.loads(RECEIPTS.read_text(encoding="utf-8"))
    vault = spec["vault"].lower()
    responder = spec["responder"].lower()
    operator = spec["operator"].lower()
    selector = spec["execute_payment_selector"].lower()
    frozen = spec["payments_frozen_selector"].lower()
    incident = spec["incident_id"]
    failed = 0
    previous = None
    for row in spec["steps"]:
        try:
            receipt = rpc("eth_getTransactionReceipt", [row["tx"]])
            tx = rpc("eth_getTransactionByHash", [row["tx"]])
        except Exception as exc:
            print(f"[FAIL] {row['name']}: fetch failed ({type(exc).__name__}: {exc})")
            failed += 1
            continue
        errors: list[str] = []
        status_ok = str(receipt.get("status") or "").lower() in {"0x1", "1"}
        if status_ok != (row["status"] == "ok"):
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
            if row.get("revert_selector"):
                try:
                    parent = hex(block - 1) if block else "latest"
                    got = revert_selector(tx, parent)
                    if got != frozen:
                        errors.append(f"revert {got} != {frozen}")
                except Exception as exc:
                    errors.append(f"revert probe ({exc})")
        if row.get("event"):
            log = find_event(receipt.get("logs") or [], responder, row["event"], incident)
            if not log:
                errors.append(f"missing {row['event']} from responder for this incident")
            else:
                mode = word(str(log.get("data") or "0x"), int(row.get("mode_word", 0)))
                if mode != int(row["expected_mode"]):
                    errors.append(f"{row['event']} mode {mode} != {row['expected_mode']}")
        if errors:
            print(f"[FAIL] {row['name']}: {'; '.join(errors)}")
            failed += 1
        else:
            extra = f" {row['event']} mode {row['expected_mode']}" if row.get("event") else ""
            print(f"[PASS] {row['name']}: block {block}{extra}")
        if isinstance(block, int):
            previous = block
    if failed == 0:
        print(f"[PASS] incident {incident}: ContainmentApplied -> RecommendationStrengthened/FROZEN -> PaymentsFrozen -> RecoveryApplied")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
