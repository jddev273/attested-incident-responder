# AIR — Attested Incident Responder

Proven incident. Money stops. Proven recovery. Money moves again.

Verified Sepolia treasury distress becomes a real Creditcoin spend restriction. A recommender may only tighten containment. Recovery needs a later separate proof.

Product page: [`demo/index.html`](demo/index.html)

```bash
forge test -q
python3 -m unittest discover -s agent -p 'test_*.py' -q
python3 scripts/live_chaininfo.py
```

| Network | Component | Address |
| --- | --- | --- |
| Ethereum Sepolia | Source emitter | `0x833b956992C61Aa0321F8EC2a1185f7cED3887e3` |
| Creditcoin CC3 | Sentry vault | `0x1EF3B69DaF030b41449c5E1a31720fb28A8767Cc` |
| Creditcoin CC3 | AIR responder | `0xD3B5C411C69708256291b678BFf0C7Fc5Ec1ec4F` |

Same payment class on Creditcoin CC3:

- Baseline success: [`0xba66…b811`](https://creditcoin-testnet.blockscout.com/tx/0xba66fbf831af4000e112ea2332939d37062728d259a6daf7348e930fd275b811)
- FROZEN revert (status 0): [`0x752f…548c`](https://creditcoin-testnet.blockscout.com/tx/0x752f9297ecd39f07235d67baad69375796a53ae158f8d2b90bc11af8a63f548c)
- After proved recovery: [`0x3e7c…b046`](https://creditcoin-testnet.blockscout.com/tx/0x3e7cc159a42483a0b1545f41d3bf0fd00c2d08f0e3e128190ee89ce153a2b046)
