#!/usr/bin/env python3
"""Optional live-provider smoke test. Skips unless AIR_MODEL_API_KEY is set."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))

from air_recommender import OpenAICompatibleClient, VerifiedIncidentEvidence, parse_model_output  # noqa: E402


def main() -> int:
    key = os.environ.get("AIR_MODEL_API_KEY", "").strip()
    if not key:
        print("[SKIP] live AI smoke: AIR_MODEL_API_KEY is not set")
        return 0
    evidence = VerifiedIncidentEvidence(
        evidence_id="0x" + "11" * 32,
        incident_id="0x" + "22" * 32,
        severity=1,
        source_chain_key="sepolia",
        source_contract="0x1234567890123456789012345678901234567890",
        source_block=1,
        tx_index=0,
        observation="raise",
        protected_balance=190,
        warning_floor=200,
        critical_floor=100,
    )
    token_env = os.environ.get("AIR_MODEL_MAX_TOKENS", "").strip()
    client = OpenAICompatibleClient(
        os.environ.get("AIR_MODEL_BASE_URL", "https://api.openai.com/v1"),
        key,
        os.environ.get("AIR_MODEL", "gpt-5-mini"),
        timeout_seconds=float(os.environ.get("AIR_MODEL_TIMEOUT", "20")),
        max_completion_tokens=int(token_env) if token_env else None,
        reasoning_effort=os.environ.get("AIR_MODEL_REASONING_EFFORT", "low"),
    )
    raw = client.complete(evidence)
    intent = parse_model_output(evidence, raw)
    print(json.dumps({"raw": raw, "mode": intent.mode, "fallback": intent.fallback, "cause": intent.cause}, separators=(",", ":")))
    if intent.fallback:
        print("[FAIL] live AI returned fallback instead of a bounded recommendation")
        return 1
    print("[PASS] live AI produced a signable bounded recommendation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
