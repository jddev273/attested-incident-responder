#!/usr/bin/env python3
"""No-key live proof that AIR's native freshness dependency is available on Creditcoin CC3."""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))
from air_recommender import keccak256  # noqa: E402

RPC_URL = os.environ.get("CREDITCOIN_RPC_URL", "https://rpc.cc3-testnet.creditcoin.network")
EXPECTED_CC3_CHAIN_ID = 102031
SEPOLIA_CHAIN_KEY = 1
CHAIN_INFO = "0x0000000000000000000000000000000000000fd3"
TIMEOUT_SECONDS = 8.0


def rpc(method: str, params: list[object]) -> object:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
        raw = response.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise RuntimeError("RPC response exceeded 64 KiB safety bound")
    payload = json.loads(raw.decode("utf-8"))
    if "error" in payload:
        raise RuntimeError(f"RPC error: {payload['error']}")
    return payload["result"]


def decode_height_hash_result(result_hex: str) -> dict[str, object]:
    if not isinstance(result_hex, str) or not result_hex.startswith("0x"):
        raise RuntimeError("ChainInfo returned non-hex data")
    raw = bytes.fromhex(result_hex[2:])
    if len(raw) != 128:
        raise RuntimeError(f"ChainInfo returned {len(raw)} bytes; expected 128")
    words = [raw[i : i + 32] for i in range(0, 128, 32)]
    return {
        "height": int.from_bytes(words[0], "big"),
        "hash": "0x" + words[1].hex(),
        "isAttestation": bool(int.from_bytes(words[2], "big")),
        "exists": bool(int.from_bytes(words[3], "big")),
    }


def main() -> int:
    chain_id = int(str(rpc("eth_chainId", [])), 16)
    if chain_id != EXPECTED_CC3_CHAIN_ID:
        raise RuntimeError(f"wrong Creditcoin chain id: got {chain_id}, expected {EXPECTED_CC3_CHAIN_ID}")

    signature = b"get_latest_attestation_height_and_hash(uint64)"
    selector = keccak256(signature)[:4]
    calldata = "0x" + (selector + SEPOLIA_CHAIN_KEY.to_bytes(32, "big")).hex()
    result = rpc("eth_call", [{"to": CHAIN_INFO, "data": calldata}, "latest"])
    latest = decode_height_hash_result(str(result))
    if not latest["exists"] or not latest["isAttestation"]:
        raise RuntimeError("Sepolia latest attestation is unavailable")

    print(json.dumps({
        "status": "PASS",
        "creditcoinRpc": RPC_URL,
        "creditcoinChainId": chain_id,
        "chainInfo": CHAIN_INFO,
        "methodSelector": "0x" + selector.hex(),
        "source": {"name": "Ethereum Sepolia", "chainKey": SEPOLIA_CHAIN_KEY, "chainId": 11155111},
        "latestAttested": latest,
        "claim": "Creditcoin native ChainInfo is live and can supply AIR's on-chain freshness head without a relayer-provided head.",
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
