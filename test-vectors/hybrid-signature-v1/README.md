# TFWS hybrid-signature and CBOR/COSE conformance vectors

This directory contains two complementary public vector sets:

1. `manifest.json`, `tfws.sig.json`, and `public-keys/` are the existing public OpenSSL-backed hybrid-signature vector. Its private keys were destroyed after generation.
2. `issue7-cbor-cose-cross-language-v1.json` is the deterministic structural CBOR/COSE corpus for issue #7 (`A2-COSE-04`).

## Scope and security meaning

The issue #7 corpus proves byte-level interoperability for the strict TFWS deterministic CBOR codec and COSE hybrid envelope in Rust and Python. It commits:

- one valid manifest with exact canonical CBOR bytes and SHA-256 digest;
- one valid tagged COSE_Sign envelope with exact bytes and SHA-256 digest;
- negative vectors for malformed, truncated, non-canonical, and duplicate-key CBOR;
- payload and protected-header substitution;
- missing or duplicate hybrid-signature components;
- unknown, substituted, and mismatched algorithms;
- wrong key identifiers, descriptors, and SHA-256 key bindings;
- invalid Ed25519 and ML-DSA-65 signature bytes.

The corpus uses the deterministic `sha256-prefix-repeat-v1` fixture signature scheme. It preserves the exact Ed25519 and ML-DSA-65 signature lengths and signs the real COSE Sig_structure, but it is **not** a production cryptographic known-answer vector. Production cryptographic operations remain covered by the OpenSSL provider integration tests. This separation keeps the committed corpus deterministic and free of private keys, random inputs, timestamps, and network dependencies.

## Files

- `issue7-cbor-cose-cross-language-v1.json` — canonical corpus consumed by Rust and Python.
- `issue7-cbor-cose-cross-language-v1.schema.json` — JSON Schema for the corpus container.
- `issue7-cbor-cose-cross-language-v1.sha256` — SHA-256 binding for the exact corpus bytes.
- `../../scripts/generate_issue7_cbor_cose_vectors.py` — deterministic generator, validator, and Python reference codec.
- `../../crates/tfws-core/tests/issue7_cbor_cose_conformance_vectors.rs` — Rust consumer.
- `../../reference/python/tests/test_issue7_cbor_cose_conformance_vectors.py` — Python consumer.

## Provenance

The corpus is generated only from the committed `test-vectors/manifest.valid.json` source manifest and fixed profile constants. The generator records the source path and base commit in the corpus. It does not read the clock, use randomness, access the network, generate private keys, or depend on platform-specific paths.

The deterministic fixture signatures are:

1. Encode the exact COSE Sig_structure.
2. Prefix it with `0x13` for Ed25519 or `0x31` for ML-DSA-65.
3. Compute SHA-256.
4. Repeat the digest to exactly 64 or 3309 bytes.

Both language consumers independently recreate this operation and reject any byte difference.

## Regeneration

From the repository root with the project Python environment:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
python scripts/generate_issue7_cbor_cose_vectors.py `
  --manifest test-vectors/manifest.valid.json `
  --output test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.json `
  --digest-output test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.sha256 `
  --schema test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.schema.json `
  --self-test
```

Run the command a second time and require byte-identical corpus and digest output. To validate committed files without rewriting them:

```powershell
python scripts/generate_issue7_cbor_cose_vectors.py `
  --manifest test-vectors/manifest.valid.json `
  --output test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.json `
  --digest-output test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.sha256 `
  --schema test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.schema.json `
  --check `
  --self-test
```

## Validation

```powershell
cargo test --package tfws-core --test issue7_cbor_cose_conformance_vectors --locked
python -m unittest reference.python.tests.test_issue7_cbor_cose_conformance_vectors -v
```

A corpus update is valid only when:

- both regeneration runs are byte-identical;
- the digest file matches the exact committed corpus bytes;
- Rust and Python accept the positive vector and reject every negative vector with the committed category;
- the complete workspace and repository baseline gates remain successful;
- no dependency, lockfile, workflow, or unrelated source file changes are required.
