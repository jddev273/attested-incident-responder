# AIR — Attested Incident Responder

Proven incident. Money stops. Proven recovery. Money moves again.

AIR turns verified reserve distress on Ethereum into an enforceable spending restriction on Creditcoin. A recommender may only tighten containment. Recovery needs a later, separate proof. The model never gets custody.

Product page: [https://jddev273.github.io/attested-incident-responder/](https://jddev273.github.io/attested-incident-responder/)

## Why it exists

A reserve can deteriorate on one chain while treasury spend authority on another stays wide open. Most “AI incident response” stops at a dashboard, a chat message, or a model instruction. AIR closes that gap in the money path itself.

**What you get**

- **Cross-chain policy that actually binds funds.** Finalized Ethereum evidence can change what a Creditcoin vault is allowed to pay.
- **Economic proof, not a simulated UI.** The same payment class succeeds, then reverts (status 0) while frozen, then succeeds again after verified recovery.
- **AI that is useful without being sovereign.** The model may recommend stricter containment. It cannot sign, pick destinations, weaken the floor, invent proof, or authorize recovery.
- **Fail-closed judgment.** If the model is offline, malformed, or asks for a weaker mode, deterministic policy still holds.
- **Recovery as a second proof, not a prompt.** Returning to `NORMAL` requires a later verified source resolution.

## How it works

1. **Source condition** — An objective protected-balance threshold on Ethereum defines WARNING vs CRITICAL. A guardian can trigger evaluation; they cannot invent severity.
2. **Proof + freshness** — Creditcoin verifies the finalized source transaction and checks it against attested source height. A stale or future *transaction* is rejected without burning the incident. While risk remains, the source can emit a fresh observation of that same incident so a current proof can still land.
3. **Policy floor** — Severity maps to a minimum vault mode: `NORMAL`, `LIMITED` (cumulative incident budget), or `FROZEN` (no outbound value).
4. **Bounded strengthening** — For a warning, an authenticated equal-or-stricter recommendation may raise containment. Effective mode is `max(deterministic floor, bounded recommendation)`.
5. **Creditcoin enforcement** — `SentryVault` is the spend path. There is no owner withdrawal that bypasses mode checks.
6. **Verified recovery** — Only a later proved source resolution can relax containment. The model cannot clear it.

```text
Ethereum distress (verified)
        │
        ▼
AIR responder  →  SentryVault  NORMAL | LIMITED | FROZEN
        │
        ▼
Creditcoin payments succeed, stop, or resume with the policy
```

## Public receipts

| Network | Component | Address |
| --- | --- | --- |
| Ethereum Sepolia | Source emitter | `0x833b956992C61Aa0321F8EC2a1185f7cED3887e3` |
| Creditcoin CC3 | Sentry vault | `0x1EF3B69DaF030b41449c5E1a31720fb28A8767Cc` |
| Creditcoin CC3 | AIR responder | `0xD3B5C411C69708256291b678BFf0C7Fc5Ec1ec4F` |

Same payment class on Creditcoin CC3:

- Baseline success: [`0xba66…b811`](https://creditcoin-testnet.blockscout.com/tx/0xba66fbf831af4000e112ea2332939d37062728d259a6daf7348e930fd275b811)
- FROZEN revert (status 0): [`0x752f…548c`](https://creditcoin-testnet.blockscout.com/tx/0x752f9297ecd39f07235d67baad69375796a53ae158f8d2b90bc11af8a63f548c)
- After proved recovery: [`0x3e7c…b046`](https://creditcoin-testnet.blockscout.com/tx/0x3e7cc159a42483a0b1545f41d3bf0fd00c2d08f0e3e128190ee89ce153a2b046)

## Repo

| Path | Role |
| --- | --- |
| `index.html` | Product page (GitHub Pages) |
| `src/AttestedIncidentResponder.sol` | Source emitter, responder, and `SentryVault` |
| `agent/air_recommender.py` | Bounded recommender (tighten only) |
| `test/` | Containment, strengthening, and recovery invariants |
| `scripts/live_chaininfo.py` | Live Creditcoin ChainInfo read |
| `vendor/asc-contracts-0.2.1/` | Gluwa ASC proof verifier used at compile time |

```bash
forge test -q
python3 -m unittest discover -s agent -p 'test_*.py' -q
python3 scripts/live_chaininfo.py
```
