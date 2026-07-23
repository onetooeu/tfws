# Trust-First Web Standard 3.0 — Engineering Draft

## Status

This document is a non-normative engineering alpha. The English specification
becomes normative only after the public RFC process and every mandatory release
gate has completed.

## Security invariants

1. A baseline signature is valid only when both Ed25519 and ML-DSA-65 verify over exactly the same message.
2. Every signature is bound to public-key descriptors in the signed manifest, including the SHA-256 digest of each published public key.
3. Unknown mandatory capabilities or algorithms cause safe rejection.
4. Private root and recovery keys never enter CI, cloud runtimes or AI-model context.
5. Removing a key is not revocation. Revocation requires a signed, logged event.
6. Technical verification never claims content truthfulness, commercial honesty or absence of risk.
7. Event history is append-only, hash-linked and checkpointed.
8. Sensitive log details are commitment-bound and selectively disclosed.
9. The protocol is provider-neutral and remains usable offline.
10. Unsupported or unaudited capabilities must not be advertised.

## Discovery

The canonical JSON manifest is served from `/.well-known/tfws.json`. Its JSON
signature bundle is served from `/.well-known/tfws.sig.json`. Public release
keys are served from `/.well-known/keys/`. Optional compact encodings use CBOR
and COSE, but they must represent the same signed payload and security policy.

## Canonical payload

The JSON core profile uses RFC 8785 JCS with the additional TFWS restriction
that floating-point values are forbidden and integers must fit the interoperable
safe range `[-9007199254740991, 9007199254740991]`.

The signed message is the following UTF-8 byte sequence with `LF` line endings
and no blank lines:

```text
TFWS3-SIGNATURE-V1
subject=<absolute HTTPS origin>
media_type=application/tfws+json
payload_sha512=<128 lowercase hexadecimal characters>
created=<RFC3339 timestamp with timezone>
key_epoch=<positive safe integer>
policy=tfws.hybrid.baseline.v1
```

The exact bytes and expected signatures are defined by conformance vectors.
A valid baseline bundle contains two independent signatures over this same
message: Ed25519 and ML-DSA-65.

## Public-key binding

Every staging or production manifest contains exactly one active release-key
descriptor for each baseline algorithm. A descriptor contains:

- algorithm and key identifier,
- canonical publication URI,
- SHA-256 digest of the exact published PEM bytes,
- active status and release usage.

A verifier must reject the bundle if the downloaded key bytes do not match the
signed descriptor, even when the cryptographic signature itself verifies.
Development manifests may temporarily contain an empty `keys` array, but they
must not be signed or accepted by a production verifier until keys are bound.

## Identity levels

- **L1 Domain Control**
- **L2 Infrastructure Binding**
- **L3 Organization Identity**
- **L4 Federated Trust**

Each level is reported independently with evidence, freshness and confidence.

## Capabilities

Core security behavior is stable. Extensions are versioned capabilities.
Unknown optional capabilities may be ignored. Unknown mandatory capabilities
must fail closed.

## Verification result

Results are multi-dimensional. No single number represents absolute trust.
Content truthfulness is explicitly reported as `not_assessed` unless a separate,
scoped evidence system evaluates a specific claim.

## Normative foundations used by this draft

- NIST FIPS 203: ML-KEM
- NIST FIPS 204: ML-DSA
- NIST FIPS 205: SLH-DSA
- RFC 8785: JSON Canonicalization Scheme
- RFC 8615: Well-Known Uniform Resource Identifiers
- RFC 9964: ML-DSA serializations for JOSE and COSE

These references do not make this engineering alpha a certified or standardized
implementation. Independent interoperability, security and legal review remain
mandatory release gates.
