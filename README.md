# gateway-evidence-replay

A small offline tool that replays retained gateway-path evidence to a bounded verdict.

An LLM gateway decides the route, the fallback, the endpoint, the policy, and the stream, and it writes down what it
did. This tool takes that retained record and recomputes, off the gateway runtime, whether the bytes are enough to
back the path claim. It returns one of four verdicts and nothing else:

- `path_verified` - the retained evidence is complete and consistent with the claimed path.
- `path_mismatch` - the evidence contradicts the claimed path (route substitution, disallowed fallback, endpoint or
  policy mismatch, stream-commitment mismatch).
- `incomplete` - the evidence is not enough to confirm or refute (unverified, stale, missing stream evidence, or
  partial coverage with no contradiction).
- `invalid` - the input is malformed or its provenance is unknown.

It does not run a gateway, call a provider, verify a TEE root, or judge model output. Signature and
runtime-measurement results are treated as input facts inside the evidence, not recomputed here. The one thing it
checks is whether the retained bytes support the narrow gateway-path claim, and it returns `incomplete` rather than
guessing when they do not.

## Quickstart

Requires a recent stable Rust toolchain.

```bash
cargo build --release

# Verify one clean bundle
cargo run --release -- verify fixtures/gateway-path-v0/clean-route.json --json
```

Expected: status `path_verified`, ceiling `observed_in_path`.

## Five-minute demo

Four synthetic bundles under `fixtures/gateway-path-v0/demo/` exercise the four verdicts. A manifest pins each file
by SHA-256, so you can tell whether a bundle was tampered with:

| Bundle | Verdict | Reason |
|--------|---------|--------|
| `clean-route.json` | `path_verified` | (none) |
| `partial-route-substitution.json` | `path_mismatch` | `route_substitution` |
| `stale-attestation.json` | `incomplete` | `attestation_stale` |
| `unknown-source.json` | `invalid` | `unknown_source_class` |

```bash
cargo test    # replays every fixture and checks the manifest digests + tamper cases
```

The `partial-route-substitution` case is the load-bearing one: a bundle with only partial coverage still returns
`path_mismatch`, because partial evidence can refute a claim even when it cannot confirm one. Confirmation is the
strict direction, and it requires complete coverage.

## Reason classes

Every verdict other than `path_verified` carries one or more reason classes. For `path_mismatch` and `incomplete`,
examples are `route_substitution`, `route_not_allowed`, `fallback_mismatch`, `endpoint_mismatch`,
`policy_hash_mismatch`, `stream_commitment_mismatch`, `attestation_stale`, `stream_evidence_missing`,
`evidence_not_verified`, and `coverage_not_complete`; an `invalid` verdict carries `unknown_source_class` or
`malformed_input`. Reasons are sorted and deterministic, so two runs on the same bytes give the same list.

## Why offline replay

The verdict is recomputable by a relying party who was not the gateway and is not online. The manifest pins the demo
bytes by digest, so the same input gives the same verdict and a tampered bundle is caught. Keeping those digests
stable across platforms is the reason for the `eol=lf` rule in `.gitattributes`; line-ending drift will silently
change a hash otherwise.

## Scope and non-claims

This is an experimental v0 that deliberately does one narrow thing. It does NOT claim:

- provider honesty or response truth,
- gateway enforcement (it reads retained evidence, it does not gate anything),
- TEE-root or signature verification (those are input facts in the evidence),
- any safety or compliance judgement.

## Feedback

If you produce or consume gateway-path evidence: does an offline replay to a bounded verdict help you, and what is
missing? Issues and Discussions are open, and "no one would use this" is a useful answer too.

## License

Apache-2.0. Copyright 2026 Rul1an.
