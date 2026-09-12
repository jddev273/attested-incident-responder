#!/usr/bin/env python3
"""Offline AIR recommender/signer scenarios using recorded model responses."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from air_recommender import VerifiedIncidentEvidence, parse_model_output, recommend  # noqa: E402
from air_signer import sign_intent  # noqa: E402

SCENARIOS = ROOT / "fixtures" / "ai-scenarios.json"
DEMO_KEY = "0x" + "00" * 29 + "0a11ce"
POLICY = "0x" + "33" * 32
RESPONDER = "0x1234567890123456789012345678901234567890"


class RecordedClient:
    def __init__(self, raw=None, exc=None):
        self.raw = raw
        self.exc = exc

    def complete(self, _evidence):
        if self.exc:
            raise self.exc
        return self.raw


def _evidence(row: dict) -> VerifiedIncidentEvidence:
    return VerifiedIncidentEvidence(
        evidence_id=row["evidence_id"],
        incident_id=row["incident_id"],
        severity=row["severity"],
        source_chain_key=row.get("source_chain_key", "sepolia"),
        source_contract=row.get("source_contract", RESPONDER),
        source_block=row.get("source_block", 1),
        tx_index=row.get("tx_index", 0),
        observation=row.get("observation", "raise"),
        protected_balance=row.get("protected_balance"),
        warning_floor=row.get("warning_floor"),
        critical_floor=row.get("critical_floor"),
    )


def run_scenario(row: dict) -> None:
    evidence = _evidence(row)
    source = row["recorded_source"]
    if source == "provider_timeout":
        intent = recommend(evidence, RecordedClient(exc=TimeoutError("recorded timeout")))
    else:
        intent = parse_model_output(evidence, row["recorded_model_output"])
    if intent.mode != row["expect_mode"] or intent.fallback != row["expect_fallback"] or intent.cause != row["expect_cause"]:
        raise SystemExit(
            f"{row['name']}: got mode={intent.mode} fallback={intent.fallback} cause={intent.cause}"
        )
    if row["expect_signable"]:
        signed = sign_intent(intent, POLICY, 102031, RESPONDER, 2_000_000_000, DEMO_KEY)
        if len(bytes.fromhex(signed["payload"][2:])) != 224:
            raise SystemExit(f"{row['name']}: signed payload is not 224 bytes")
        print(f"[PASS] {row['name']}: recorded {source} -> {intent.mode} signed")
    else:
        try:
            sign_intent(intent, POLICY, 102031, RESPONDER, 2_000_000_000, DEMO_KEY)
        except ValueError:
            print(f"[PASS] {row['name']}: recorded {source} -> fallback {intent.mode} not signed")
            return
        raise SystemExit(f"{row['name']}: fallback intent was signed")


def main() -> int:
    rows = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    print("AIR recorded-model scenarios (no live provider, no chain txs)")
    for row in rows:
        run_scenario(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
