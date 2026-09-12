#!/usr/bin/env python3
"""Trusted AIR recommender signer.

Receives a bounded RecommendationIntent, builds the exact EIP-712 digest
AirResponderCore recovers, signs it, and emits the 224-byte payload.
This module never talks to the model and never chooses destinations.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from typing import Any

from air_recommender import (
    RecommendationIntent,
    build_signing_request,
    encode_signed_recommendation,
    keccak256,
)

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_HALF_N = SECP256K1_N // 2
EIP712_DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)
RECOMMENDATION_TYPEHASH = keccak256(
    b"AIRRecommendation(bytes32 policyHash,bytes32 fingerprint,uint8 mode,bytes32 rationaleHash,uint64 validUntil)"
)
NAME_HASH = keccak256(b"AIR")
VERSION_HASH = keccak256(b"1")


def _inv(value: int, mod: int) -> int:
    return pow(value, -1, mod)


def _point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 * _inv(2 * y1, SECP256K1_P)) % SECP256K1_P
    else:
        lam = ((y2 - y1) * _inv((x2 - x1) % SECP256K1_P, SECP256K1_P)) % SECP256K1_P
    x3 = (lam * lam - x1 - x2) % SECP256K1_P
    y3 = (lam * (x1 - x3) - y1) % SECP256K1_P
    return x3, y3


def _point_mul(scalar: int, point: tuple[int, int] | None = (SECP256K1_GX, SECP256K1_GY)) -> tuple[int, int] | None:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _int_from_hex(value: str, field: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"{field} must be 0x-prefixed hex")
    try:
        parsed = int(value[2:], 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be hex") from exc
    if parsed <= 0 or parsed >= SECP256K1_N:
        raise ValueError(f"{field} is not a valid secp256k1 scalar")
    return parsed


def address_from_private_key(private_key: str) -> str:
    secret = _int_from_hex(private_key, "private_key")
    point = _point_mul(secret)
    if point is None:
        raise ValueError("invalid private key")
    uncompressed = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    return "0x" + keccak256(uncompressed)[12:].hex()


def recommendation_digest(
    policy_hash: str,
    fingerprint: str,
    mode: str,
    rationale_hash: str,
    valid_until: int,
    chain_id: int,
    responder: str,
) -> bytes:
    request = build_signing_request(
        RecommendationIntent(
            mode=mode,
            reason="signed",
            evidence_id=fingerprint,
            fallback=False,
            rationale_hash=rationale_hash,
        ),
        policy_hash,
        chain_id,
        responder,
        valid_until,
    )
    message = request["message"]
    responder_word = bytes.fromhex(responder[2:].rjust(40, "0")).rjust(32, b"\x00")
    domain_separator = keccak256(
        EIP712_DOMAIN_TYPEHASH
        + NAME_HASH
        + VERSION_HASH
        + chain_id.to_bytes(32, "big")
        + responder_word
    )
    struct_hash = keccak256(
        RECOMMENDATION_TYPEHASH
        + bytes.fromhex(message["policyHash"][2:])
        + bytes.fromhex(message["fingerprint"][2:])
        + int(message["mode"]).to_bytes(32, "big")
        + bytes.fromhex(message["rationaleHash"][2:])
        + int(message["validUntil"]).to_bytes(32, "big")
    )
    return keccak256(b"\x19\x01" + domain_separator + struct_hash)


def _rfc6979_k(secret: int, digest: bytes) -> int:
    x = secret.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + digest, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + digest, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < SECP256K1_N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def recover_signer(digest: bytes, r: str, s: str, v: int) -> str:
    if v not in (27, 28):
        raise ValueError("v must be 27 or 28")
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    r_int = int(r[2:], 16)
    s_int = int(s[2:], 16)
    if r_int <= 0 or r_int >= SECP256K1_N or s_int <= 0 or s_int > SECP256K1_HALF_N:
        raise ValueError("invalid signature")
    y_sq = (pow(r_int, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if (y % 2 == 0) != (v == 27):
        y = SECP256K1_P - y
    z = int.from_bytes(digest, "big") % SECP256K1_N
    r_inv = _inv(r_int, SECP256K1_N)
    q = _point_add(_point_mul(s_int, (r_int, y)), _point_mul((SECP256K1_N - z) % SECP256K1_N))
    if q is None:
        raise ValueError("signature does not recover")
    q = _point_mul(r_inv, q)
    if q is None:
        raise ValueError("signature does not recover")
    return "0x" + keccak256(q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big"))[12:].hex()


def sign_digest(private_key: str, digest: bytes) -> tuple[str, str, int]:
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    secret = _int_from_hex(private_key, "private_key")
    z = int.from_bytes(digest, "big") % SECP256K1_N
    k = _rfc6979_k(secret, digest)
    point = _point_mul(k)
    if point is None:
        raise ValueError("invalid nonce")
    r = point[0] % SECP256K1_N
    s = (_inv(k, SECP256K1_N) * (z + r * secret)) % SECP256K1_N
    if r == 0 or s == 0:
        raise ValueError("degenerate signature")
    recovery = 0 if point[1] % 2 == 0 else 1
    if s > SECP256K1_HALF_N:
        s = SECP256K1_N - s
        recovery ^= 1
    return "0x" + r.to_bytes(32, "big").hex(), "0x" + s.to_bytes(32, "big").hex(), 27 + recovery


def sign_intent(
    intent: RecommendationIntent,
    policy_hash: str,
    chain_id: int,
    responder: str,
    valid_until: int,
    private_key: str,
) -> dict[str, Any]:
    request = build_signing_request(intent, policy_hash, chain_id, responder, valid_until)
    digest = recommendation_digest(
        policy_hash,
        request["message"]["fingerprint"],
        intent.mode,
        intent.rationale_hash,
        valid_until,
        chain_id,
        responder,
    )
    r, s, v = sign_digest(private_key, digest)
    payload = encode_signed_recommendation(intent, valid_until, r, s, v)
    return {
        "signer": address_from_private_key(private_key),
        "digest": "0x" + digest.hex(),
        "payload": payload,
        "r": r,
        "s": s,
        "v": v,
        "request": request,
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sign a bounded AIR recommendation")
    parser.add_argument("--intent-json", required=True, help="RecommendationIntent JSON from air_recommender.py")
    parser.add_argument("--policy-hash", required=True)
    parser.add_argument("--chain-id", required=True, type=int)
    parser.add_argument("--responder", required=True)
    parser.add_argument("--valid-until", required=True, type=int)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    blob = args.intent_json
    if not blob.startswith("{"):
        with open(blob, encoding="utf-8") as handle:
            blob = handle.read()
    raw = json.loads(blob)
    intent = RecommendationIntent(
        mode=raw["mode"],
        reason=raw["reason"],
        evidence_id=raw["evidence_id"],
        fallback=bool(raw["fallback"]),
        rationale_hash=raw["rationale_hash"],
    )
    key = os.environ.get("AIR_RECOMMENDER_KEY", "")
    if not key:
        raise SystemExit("AIR_RECOMMENDER_KEY is required")
    print(json.dumps(sign_intent(intent, args.policy_hash, args.chain_id, args.responder, args.valid_until, key), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
