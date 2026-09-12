#!/usr/bin/env python3
"""Bounded AIR model adapter.

The model never receives execution authority. It may only return an evidence-bound
containment intent plus a short reason. That intent is non-authoritative until a
separate trusted signer authorizes the exact EIP-712 recommendation consumed by
AirResponderCore. Any timeout, malformed response, wrong evidence binding, extra
authority field, or out-of-policy mode yields fallback=true; on chain, missing or
invalid recommendation provenance applies the objective source-severity floor
(WARNING -> LIMITED, CRITICAL -> FROZEN).

No private key handling and no third-party Python packages are required here.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Callable

MASK64 = (1 << 64) - 1
ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
MODE_WORD = {"NORMAL": 0, "LIMITED": 1, "FROZEN": 2}
MAX_UINT64 = (1 << 64) - 1
MAX_REASON_CHARS = 280
MAX_RESPONSE_BYTES = 16_384
MAX_COMPLETION_TOKENS = 180
MAX_TIMEOUT_SECONDS = 30.0


def _rotl64(value: int, amount: int) -> int:
    if amount == 0:
        return value & MASK64
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def _keccak_f1600(state: list[int]) -> None:
    for rc in ROUND_CONSTANTS:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= d[x]

        b = [0] * 25
        for y in range(5):
            for x in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y], ROTATION[x][y])

        for y in range(5):
            row = 5 * y
            for x in range(5):
                state[row + x] = b[row + x] ^ ((~b[row + ((x + 1) % 5)] & MASK64) & b[row + ((x + 2) % 5)])
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Ethereum Keccak-256 (legacy Keccak padding 0x01, not SHA3-256)."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * ((-len(padded)) % rate))
    # pad10*1 shares the final rate byte when the 0x01 delimiter lands there.
    padded[-1] |= 0x80

    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8 : i * 8 + 8], "little")
        _keccak_f1600(state)

    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out.extend(state[i].to_bytes(8, "little"))
            if len(out) >= 32:
                return bytes(out[:32])
        _keccak_f1600(state)
    return bytes(out[:32])


def _bytes32(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 66:
        raise ValueError(f"{field} must be 0x-prefixed bytes32")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ValueError(f"{field} must be hex bytes32") from exc
    if len(raw) != 32:
        raise ValueError(f"{field} must be bytes32")
    return raw


def _address(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
        raise ValueError(f"{field} must be a 0x-prefixed address")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ValueError(f"{field} must be a hex address") from exc
    if len(raw) != 20:
        raise ValueError(f"{field} must be 20 bytes")
    return "0x" + raw.hex()


@dataclass(frozen=True)
class VerifiedIncidentEvidence:
    """Model-facing subset derived only after ASC verification/on-chain decoding."""

    evidence_id: str  # AirResponderCore.recommendationFingerprint(...)
    incident_id: str
    severity: int
    source_chain_key: str
    source_contract: str
    source_block: int
    tx_index: int
    observation: str = "raise"
    protected_balance: int | None = None
    warning_floor: int | None = None
    critical_floor: int | None = None

    def validate(self) -> None:
        _bytes32(self.evidence_id, "evidence_id")
        _bytes32(self.incident_id, "incident_id")
        if self.severity not in (1, 2):
            raise ValueError("severity must be 1 or 2")
        if not self.source_chain_key or not self.source_contract:
            raise ValueError("source identity must be non-empty")
        if self.source_block < 0 or self.tx_index < 0:
            raise ValueError("source position must be non-negative")
        if self.observation not in ("raise", "refresh", "escalate"):
            raise ValueError("observation must be raise, refresh, or escalate")

    @property
    def allowed_modes(self) -> tuple[str, ...]:
        return ("LIMITED", "FROZEN") if self.severity == 1 else ("FROZEN",)


@dataclass(frozen=True)
class RecommendationIntent:
    """Non-authoritative model decision. A trusted signer must authorize it before contract submission."""

    mode: str
    reason: str
    evidence_id: str
    fallback: bool
    rationale_hash: str
    cause: str = "ok"


class OpenAICompatibleClient:
    """Tiny /v1/chat/completions client with bounded timeout and injectable transport."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float = 8.0,
        urlopen: Callable[..., Any] = urllib.request.urlopen,
    ) -> None:
        if not base_url or not model:
            raise ValueError("base_url and model are required")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > MAX_TIMEOUT_SECONDS:
            raise ValueError(f"timeout_seconds must be finite and in (0, {MAX_TIMEOUT_SECONDS}]")
        self.endpoint = base_url.rstrip("/") + "/chat/completions"
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self._urlopen = urlopen

    def _chat_body(self, system: str, user_payload: dict[str, Any]) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(user_payload, separators=(",", ":"))},
            ],
        }
        # GPT-5 chat models reject temperature and max_tokens; older compatible models still use them.
        if self.model.lower().startswith("gpt-5"):
            body["max_completion_tokens"] = MAX_COMPLETION_TOKENS
        else:
            body["temperature"] = 0
            body["max_tokens"] = MAX_COMPLETION_TOKENS
        return body

    def complete(self, evidence: VerifiedIncidentEvidence) -> str:
        evidence.validate()
        system = (
            "You are AIR's bounded incident-response classifier. Return ONLY a JSON object with exactly "
            "three keys: evidence_id, mode, reason. Echo evidence_id exactly. mode must be one of the "
            "allowed_modes supplied. reason must be non-empty, <=280 characters, and explain the risk. "
            "CRITICAL must be FROZEN. WARNING may be LIMITED, or FROZEN when remaining buffer to the "
            "critical floor is small, the observation is escalate/refresh, or distress is already ongoing. "
            "You have NO authority to name beneficiaries, contracts, calldata, limits, policies, or recovery actions."
        )
        user_payload = {
            "evidence_id": evidence.evidence_id,
            "incident_id": evidence.incident_id,
            "severity": evidence.severity,
            "policy_floor": source_floor(evidence),
            "observation": evidence.observation,
            "source_chain_key": evidence.source_chain_key,
            "source_contract": evidence.source_contract,
            "source_block": evidence.source_block,
            "tx_index": evidence.tx_index,
            "allowed_modes": list(evidence.allowed_modes),
        }
        if evidence.protected_balance is not None:
            user_payload["protected_balance"] = evidence.protected_balance
        if evidence.warning_floor is not None:
            user_payload["warning_floor"] = evidence.warning_floor
        if evidence.critical_floor is not None:
            user_payload["critical_floor"] = evidence.critical_floor
            if evidence.protected_balance is not None:
                user_payload["buffer_to_critical"] = evidence.protected_balance - evidence.critical_floor
        body = json.dumps(self._chat_body(system, user_payload), separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        with self._urlopen(request, timeout=self.timeout_seconds) as response:
            raw_response = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw_response) > MAX_RESPONSE_BYTES:
            raise ValueError("model response exceeds bounded byte limit")
        parsed = json.loads(raw_response.decode("utf-8"))
        content = parsed["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise ValueError("model content must be text")
        return content


def source_floor(evidence: VerifiedIncidentEvidence) -> str:
    evidence.validate()
    return "LIMITED" if evidence.severity == 1 else "FROZEN"


def _fallback(evidence: VerifiedIncidentEvidence, reason: str, cause: str) -> RecommendationIntent:
    return RecommendationIntent(
        mode=source_floor(evidence),
        reason=reason,
        evidence_id=evidence.evidence_id,
        fallback=True,
        rationale_hash="0x" + "00" * 32,
        cause=cause,
    )


def parse_model_output(evidence: VerifiedIncidentEvidence, raw_model_text: str) -> RecommendationIntent:
    evidence.validate()
    fallback_reason = "model output invalid or outside immutable policy; contract applies objective source-severity floor"
    try:
        obj = json.loads(raw_model_text)
    except (TypeError, json.JSONDecodeError):
        return _fallback(evidence, fallback_reason, "invalid_output")
    if not isinstance(obj, dict) or set(obj) != {"evidence_id", "mode", "reason"}:
        return _fallback(evidence, fallback_reason, "invalid_output")
    if obj["evidence_id"] != evidence.evidence_id:
        return _fallback(evidence, "model evidence binding mismatch; contract applies objective source-severity floor", "invalid_output")
    mode = obj["mode"]
    reason = obj["reason"]
    if mode not in evidence.allowed_modes:
        return _fallback(evidence, "model mode outside deterministic policy envelope; contract applies objective source-severity floor", "invalid_output")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_REASON_CHARS:
        return _fallback(evidence, fallback_reason, "invalid_output")
    reason = reason.strip()
    rationale = keccak256(reason.encode("utf-8"))
    return RecommendationIntent(
        mode=mode,
        reason=reason,
        evidence_id=evidence.evidence_id,
        fallback=False,
        rationale_hash="0x" + rationale.hex(),
    )


def build_signing_request(
    intent: RecommendationIntent,
    policy_hash: str,
    chain_id: int,
    responder: str,
    valid_until: int,
) -> dict[str, Any]:
    """Build the canonical EIP-712 request for a separate trusted signer."""
    if intent.fallback:
        raise ValueError("fallback intent must not be signed")
    if intent.mode not in ("LIMITED", "FROZEN"):
        raise ValueError("intent mode is not signable")
    fingerprint = "0x" + _bytes32(intent.evidence_id, "evidence_id").hex()
    rationale_hash = "0x" + _bytes32(intent.rationale_hash, "rationale_hash").hex()
    policy_hash = "0x" + _bytes32(policy_hash, "policy_hash").hex()
    responder = _address(responder, "responder")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
        raise ValueError("chain_id must be a positive integer")
    if not isinstance(valid_until, int) or isinstance(valid_until, bool) or not (0 <= valid_until <= MAX_UINT64):
        raise ValueError("valid_until must fit uint64")
    return {
        "domain": {"name": "AIR", "version": "1", "chainId": chain_id, "verifyingContract": responder},
        "primaryType": "AIRRecommendation",
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "AIRRecommendation": [
                {"name": "policyHash", "type": "bytes32"},
                {"name": "fingerprint", "type": "bytes32"},
                {"name": "mode", "type": "uint8"},
                {"name": "rationaleHash", "type": "bytes32"},
                {"name": "validUntil", "type": "uint64"},
            ],
        },
        "message": {
            "policyHash": policy_hash,
            "fingerprint": fingerprint,
            "mode": MODE_WORD[intent.mode],
            "rationaleHash": rationale_hash,
            "validUntil": valid_until,
        },
    }


def encode_signed_recommendation(
    intent: RecommendationIntent,
    valid_until: int,
    r: str,
    s: str,
    v: int,
) -> str:
    """Encode the seven fixed ABI words accepted by AirResponderCore after a trusted signer signs the request."""
    if intent.fallback:
        raise ValueError("fallback intent must not be encoded as an authenticated recommendation")
    if intent.mode not in ("LIMITED", "FROZEN"):
        raise ValueError("intent mode is not encodable")
    if not isinstance(valid_until, int) or isinstance(valid_until, bool) or not (0 <= valid_until <= MAX_UINT64):
        raise ValueError("valid_until must fit uint64")
    if v not in (27, 28):
        raise ValueError("v must be 27 or 28")
    fingerprint = _bytes32(intent.evidence_id, "evidence_id")
    rationale = _bytes32(intent.rationale_hash, "rationale_hash")
    r_raw = _bytes32(r, "r")
    s_raw = _bytes32(s, "s")
    if not any(r_raw) or not any(s_raw):
        raise ValueError("r and s must be nonzero")
    payload = b"".join(
        (
            fingerprint,
            MODE_WORD[intent.mode].to_bytes(32, "big"),
            rationale,
            valid_until.to_bytes(32, "big"),
            r_raw,
            s_raw,
            v.to_bytes(32, "big"),
        )
    )
    if len(payload) != 224:
        raise AssertionError("AIR signed recommendation ABI payload must be exactly 224 bytes")
    return "0x" + payload.hex()


def recommend(evidence: VerifiedIncidentEvidence, client: Any) -> RecommendationIntent:
    try:
        raw = client.complete(evidence)
        return parse_model_output(evidence, raw)
    except TimeoutError as exc:
        return _fallback(
            evidence,
            f"model adapter timeout ({type(exc).__name__}); contract applies objective source-severity floor",
            "provider_timeout",
        )
    except Exception as exc:  # network/provider failure must never block containment
        return _fallback(
            evidence,
            f"model adapter failure ({type(exc).__name__}); contract applies objective source-severity floor",
            "provider_error",
        )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a bounded AIR recommendation payload")
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument("--incident-id", required=True)
    parser.add_argument("--severity", required=True, type=int, choices=(1, 2))
    parser.add_argument("--source-chain-key", required=True)
    parser.add_argument("--source-contract", required=True)
    parser.add_argument("--source-block", required=True, type=int)
    parser.add_argument("--tx-index", required=True, type=int)
    parser.add_argument("--observation", default="raise", choices=("raise", "refresh", "escalate"))
    parser.add_argument("--protected-balance", type=int, default=None)
    parser.add_argument("--warning-floor", type=int, default=None)
    parser.add_argument("--critical-floor", type=int, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    evidence = VerifiedIncidentEvidence(
        evidence_id=args.evidence_id,
        incident_id=args.incident_id,
        severity=args.severity,
        source_chain_key=args.source_chain_key,
        source_contract=args.source_contract,
        source_block=args.source_block,
        tx_index=args.tx_index,
        observation=args.observation,
        protected_balance=args.protected_balance,
        warning_floor=args.warning_floor,
        critical_floor=args.critical_floor,
    )
    client = OpenAICompatibleClient(
        base_url=os.environ.get("AIR_MODEL_BASE_URL", "https://api.openai.com/v1"),
        api_key=os.environ.get("AIR_MODEL_API_KEY", ""),
        model=os.environ.get("AIR_MODEL", "gpt-5-mini"),
        timeout_seconds=float(os.environ.get("AIR_MODEL_TIMEOUT", "8")),
    )
    result = recommend(evidence, client)
    print(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
