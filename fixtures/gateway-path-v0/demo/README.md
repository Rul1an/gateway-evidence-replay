# Gateway Path Demo Fixtures

These fixtures are synthetic retained gateway-path evidence bundles for the replay demo.

They are not live gateway logs, do not contain provider credentials, and do not claim provider honesty or response truth. The replay verifier computes a bounded verdict from the retained bytes.

Replay the full digest-pinned pack from the repository root:

```bash
cargo run --release -- replay-pack fixtures/gateway-path-v0/demo --json
```
