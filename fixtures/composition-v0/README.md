# Composition v0 Fixture

This fixture demonstrates the v1 composability boundary: one gateway-path record and one tool-surface record share an
action/run context, but each record is recomputed separately and keeps its own bounded verdict.

The gateway-path record is run-scoped: its existing `request_id` must match the manifest `run_id`. The tool-surface
record is action-and-run scoped: its `action_id` and `run_id` must both match the manifest. That keeps the fixture
compatible with `gateway-path.v0` while making the composition boundary explicit.

It deliberately emits no whole-action trust score. A downstream verifier may say "path verified and tool surface
unchanged" when both records support that statement. It must not turn that pair into "the whole action was safe."

Two asymmetric packs are included:

- `path-verified-tool-not-verifiable`: the gateway path verifies, while the tool-surface record is not verifiable.
- `tool-unchanged-path-mismatch`: the tool surface is unchanged, while the gateway path contradicts the claimed route.

Run:

```bash
cargo run --release -- replay-composition-pack fixtures/composition-v0/path-verified-tool-not-verifiable --json
cargo run --release -- replay-composition-pack fixtures/composition-v0/tool-unchanged-path-mismatch --json
```
