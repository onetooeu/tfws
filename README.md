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

`make validate` is the complete Issue #9 local gate. Its explicit components
are `make test-python-cbor-cose`, `make test-vectors`,
`make test-rust-locked`, `make test-wasm-codec`, and
`make validate-repository`. Cargo commands use the locked, offline dependency
graph; vector regeneration occurs in a temporary directory and is compared
byte-for-byte with the committed corpus. The Make targets require a POSIX
shell (`mktemp` and `cmp`); on Windows, run them in Git Bash or an equivalent
environment after provisioning the Rust WASM target.

CI keeps the governance check names `python-node`, `rust (ubuntu-latest)`,
`rust (windows-latest)`, and `rust (macos-latest)`. The Python job runs the
CBOR/COSE reference and 19-case Issue #7 corpus (one positive plus 18 negative
vectors), deterministic regeneration, Node tests, and the repository
validator. Every Rust platform runs the deterministic CBOR codec, COSE hybrid
envelope, OpenSSL provider, Issue #7 vector, explicit CLI-format, workspace,
formatting, Clippy, and WASM codec-path gates.

The Python/OpenSSL reference requires OpenSSL 3.5 or newer with Ed25519 and
ML-DSA-65 support. The Rust workspace is the intended long-term source of truth;
its build remains a mandatory release gate.

The Rust CLI requires an explicit representation and never auto-detects or
downgrades the input format:

```bash
cargo run --locked --offline -p tfws-cli -- validate --input-format json manifest.json
cargo run --locked --offline -p tfws-cli -- validate --input-format cbor manifest.cbor
cargo run --locked --offline -p tfws-cli -- validate --input-format cose manifest.cose
cargo run --locked --offline -p tfws-cli -- validate --input-format cose --output-format json manifest.cose
```

Human-readable errors are the default; `--output-format json` returns a stable
machine-readable error code and message. Current COSE verification in this CLI
is limited to the committed deterministic conformance fixtures. Those fixtures
exercise structure, hybrid-profile, key-binding and rejection behavior; they
are not production cryptographic known-answer vectors or a production verifier.

The WASM interface likewise separates JSON from the explicit
`validate_manifest_cbor` export. That export calls the shared deterministic
core decoder, fails closed, and returns bounded JSON error categories; it does
not auto-detect COSE, perform hybrid signature verification, or turn malformed
CBOR into JSON. This remains engineering-alpha interoperability work, not a
production-complete, certified, or release-ready verifier.

## Repository map

- `spec/` — normative engineering drafts
- `schemas/` — JSON Schema 2020-12 contracts
- `registries/` — capabilities and cryptographic policy registry
- `crates/` — Rust core, CLI, provider adapter and WASM interface
- `reference/python/` — executable reference used for current conformance tests
- `sdks/typescript/` — thin client-side shape and presentation helpers
- `test-vectors/` — public positive and negative vectors
- `formal/` — security state-machine models
