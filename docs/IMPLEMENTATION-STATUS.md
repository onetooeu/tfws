# TFWS 3.0 implementation status

## Implemented and locally exercised

- integer-only RFC 8785-compatible canonical JSON profile,
- strict manifest and signature-bundle validation,
- signed public-key descriptors with exact public-key SHA-256 binding,
- real Ed25519 + ML-DSA-65 key generation, signing and verification through OpenSSL 3.5,
- deterministic manifest CBOR decoding and COSE_Sign envelope validation against
  the committed positive and 18 negative cross-language conformance vectors,
- explicit `json`, `cbor` or `cose` CLI input selection with fail-closed format
  mismatch handling and stable human/machine-readable errors,
- negative tests for payload modification, missing signatures, key replacement and URI mismatch,
- downgrade and unknown-mandatory-capability rejection,
- JSON Schema 2020-12 positive and negative vectors,
- event hash chains and deterministic Merkle roots,
- recovery threshold/time-lock policy and hybrid guardian approval checks,
- witness quorum and split-view rejection foundations,
- SSRF destination policy helper,
- Python package/CLI installation,
- TypeScript shape and presentation helpers,
- Rust workspace locally formatted, checked, tested, linted and built on Windows with Rust 1.86.0 and locked dependencies,
- `tfws-wasm` locally built for `wasm32-unknown-unknown`,
- explicit `tfws-wasm` deterministic-CBOR validation through the shared core
  decoder, with stable bounded error categories and fail-closed JSON mismatch,
- CI-integrated Python, Rust, vector-regeneration, repository-validator and
  WASM codec-path gates while preserving the four governed check names,
- ONETOO platform event-store, tenant, authentication, idempotency, search and agent-guard foundations,
- accessible static ONETOO and HGPeDU alpha sites with fail-closed production gates.

## Specified or scaffolded, not production-complete

- independent multi-platform verification and security audit of the Rust/WASM verifier,
- production cryptographic COSE signing and verification beyond the committed
  structural deterministic conformance fixtures,
- ML-KEM secure transport implementation,
- distributed transparency log, consistency proofs and witness gossip service,
- selective-disclosure credential integrations,
- production registry, crawler, search and agent orchestration,
- WebAuthn/OIDC/SAML/SCIM identity gateway,
- HSM/KMS production providers and guardian ceremony,
- TUF-style release metadata and reproducible multi-platform builds,
- independent security, interoperability, accessibility and legal review.

Unsupported capabilities must not be advertised. `3.0.0-alpha` is an
engineering foundation and migration package, not a completed TFWS 3.0 release.
The conformance-fixture verifier does not claim production cryptographic
completeness. Selective-disclosure work remains outside this CBOR/COSE scope.
Issue #9 adds CI and documentation integration plus the explicit WASM codec
path: the 19-case corpus remains one positive and 18 negative structural
fixtures, and the WASM export validates deterministic manifest CBOR but does
not verify COSE signatures. This remains engineering-alpha work. It is not
production-complete or certified, and it does not constitute a release claim.
