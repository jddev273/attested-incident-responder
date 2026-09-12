#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.foundry/bin:${PATH}"

echo "[PASS] running contract invariants"
forge test -q

echo "[PASS] running bounded recommender and signer"
python3 -m unittest discover -s agent -p 'test_*.py' -q

echo "[PASS] running recorded AI scenarios"
python3 scripts/air_scenarios.py

echo "[PASS] checking public Creditcoin receipts"
python3 scripts/check_public_receipts.py

echo
echo "AIR lifecycle: source policy -> destination containment -> payment stop -> proved recovery -> payment resume"
echo "Safe Guard and PauseTarget are additional IAirContainmentTarget sinks; SentryVault remains the live CC3 receipt target."
