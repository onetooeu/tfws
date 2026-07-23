# TFWS

TFWS is an open standard and engineering toolkit for publishing and verifying
machine-readable web evidence. TFWS 3.0 introduces mandatory hybrid
Ed25519 + ML-DSA-65 signatures, explicit capability negotiation, key lifecycle
rules, recovery policy, transparency evidence and offline verification.

> **Status: engineering alpha.** This repository is intentionally fail-closed.
> It is not a production certification, and unimplemented capabilities must not
> be represented as supported. Review `RELEASE-GATES.md` and
> `docs/IMPLEMENTATION-STATUS.md` before deployment.

The current public engineering-alpha prerelease is
[`v3.0.0-alpha.1`](https://github.com/onetooeu/tfws/releases/tag/v3.0.0-alpha.1).
It is source-only and remains subject to the release gates above.

## Local validation

```bash
make validate
```

The Python/OpenSSL reference requires OpenSSL 3.5 or newer with Ed25519 and
ML-DSA-65 support. The Rust workspace is the intended long-term source of truth;
its build remains a mandatory release gate.

## Repository map

- `spec/` — normative engineering drafts
- `schemas/` — JSON Schema 2020-12 contracts
- `registries/` — capabilities and cryptographic policy registry
- `crates/` — Rust core, CLI, provider adapter and WASM interface
- `reference/python/` — executable reference used for current conformance tests
- `sdks/typescript/` — thin client-side shape and presentation helpers
- `test-vectors/` — public positive and negative vectors
- `formal/` — security state-machine models
