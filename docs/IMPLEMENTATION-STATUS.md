# TFWS 3.0 implementation status

## Implemented and locally exercised

- integer-only RFC 8785-compatible canonical JSON profile,
- strict manifest and signature-bundle validation,
- signed public-key descriptors with exact public-key SHA-256 binding,
- real Ed25519 + ML-DSA-65 key generation, signing and verification through OpenSSL 3.5,
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
- ONETOO platform event-store, tenant, authentication, idempotency, search and agent-guard foundations,
- accessible static ONETOO and HGPeDU alpha sites with fail-closed production gates.

## Specified or scaffolded, not production-complete

- independent multi-platform verification and security audit of the Rust/WASM verifier,
- CBOR/COSE envelope implementation,
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
