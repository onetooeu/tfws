# TFWS 3.0 CBOR/COSE Envelope Profile

Status: engineering draft for `v3.0.0-alpha.2`, tracked by issue #4.

This profile is not a production certification. Unsupported behavior remains
fail-closed, and production use remains blocked by `RELEASE-GATES.md`.

## 1. Scope

This document defines a deterministic CBOR representation of the TFWS 3.0
manifest and a tagged COSE_Sign envelope carrying exactly two required
signatures: Ed25519 and ML-DSA-65.

The CBOR/COSE path represents the same abstract manifest and enforces the same
hybrid-signature, public-key binding, capability and downgrade policy as the
canonical JSON path.

## 2. Requirements language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY and OPTIONAL are to be interpreted as
described in BCP 14 when, and only when, they appear in all capitals.

## 3. Normative references

- RFC 8949, Concise Binary Object Representation (CBOR).
- RFC 9052, COSE Structures and Process.
- RFC 9053, COSE Initial Algorithms.
- RFC 9596, the COSE `typ` header parameter.
- RFC 9864, fully specified Ed25519 for COSE.
- RFC 9964, ML-DSA for JOSE and COSE.
- BCP 14, RFC 2119 and RFC 8174.

## 4. Abstract manifest equivalence

A TFWS manifest has one abstract value independent of its wire encoding.

A publisher that emits both JSON and CBOR forms MUST ensure that decoding the
canonical JSON document and decoding the deterministic CBOR payload produce
the same abstract value recursively:

- JSON objects map to CBOR maps with text-string keys.
- JSON arrays map to CBOR arrays in the same order.
- JSON strings map to CBOR text strings without Unicode normalization.
- JSON booleans map to CBOR simple values `true` and `false`.
- JSON integers map to CBOR integers and MUST remain within the TFWS safe
  integer range.
- JSON null, floating-point values, CBOR byte strings inside the manifest,
  CBOR tags inside the manifest, undefined values and other CBOR simple values
  are not part of the TFWS manifest data model and MUST be rejected.

Map keys MUST be unique. A decoder MUST reject a duplicate key before semantic
validation.

## 5. Endpoints and media types

The compact envelope is served from:

```text
/.well-known/tfws.cose
```

Its HTTP media type is:

```text
application/cose; cose-type="cose-sign"
```

The embedded payload media type is:

```text
application/tfws+cbor
```

These identifiers describe the engineering profile and do not claim a new
IANA registration.

## 6. Deterministic CBOR requirements

Every envelope, protected-header map and embedded manifest MUST use the core
deterministic encoding requirements from RFC 8949:

- preferred serialization,
- shortest integer and length encodings,
- definite-length items only,
- deterministic map-key ordering,
- no duplicate map keys.

A verifier MUST reject an input whose decoded value can be re-encoded
deterministically to bytes different from the received bytes.

## 7. Envelope structure

The TFWS compact envelope MUST be a tagged COSE_Sign object using CBOR tag 98.
Untagged objects and COSE_Sign1 objects MUST be rejected.

The profile is equivalent to this CDDL-shaped structure:

```cddl
TFWS_COSE = #6.98([
  body_protected : bstr .cbor {
    3  : "application/tfws+cbor",
    16 : "application/cose; cose-type=\"cose-sign\""
  },
  body_unprotected : {},
  payload : bstr .cbor TFWS_Manifest,
  signatures : [
    [
      ed25519_protected : bstr .cbor {
        1 : -19,
        4 : bstr
      },
      ed25519_unprotected : {},
      ed25519_signature : bstr
    ],
    [
      ml_dsa_65_protected : bstr .cbor {
        1 : -49,
        4 : bstr
      },
      ml_dsa_65_unprotected : {},
      ml_dsa_65_signature : bstr
    ]
  ]
])
```

The body protected map MUST contain exactly:

- header label `3` (`content type`) with `application/tfws+cbor`,
- header label `16` (`typ`) with
  `application/cose; cose-type="cose-sign"`.

The body unprotected map MUST be empty.

The payload MUST be embedded as a byte string. Detached payloads are not
supported by this engineering profile.

The signatures array MUST contain exactly two entries in this order:

1. Ed25519 using COSE algorithm value `-19`,
2. ML-DSA-65 using COSE algorithm value `-49`.

Each signature protected map MUST contain exactly:

- header label `1` (`alg`) with the required algorithm value,
- header label `4` (`kid`) as the UTF-8 bytes of the manifest key descriptor's
  `key_id`.

Each signature unprotected map MUST be empty. The external AAD used by the
COSE signature computation MUST be the empty byte string.

Unknown headers, extra signatures, missing signatures, duplicate algorithms,
algorithm reordering and unsupported algorithms MUST be rejected.

## 8. Key and policy binding

The COSE algorithm value maps to the existing TFWS algorithm identifier:

| COSE value | TFWS identifier |
|---:|---|
| `-19` | `ed25519` |
| `-49` | `ml-dsa-65` |

For each signature, the verifier MUST locate exactly one manifest key
descriptor with the mapped algorithm and the UTF-8-decoded `kid`.

The verifier MUST apply the existing descriptor requirements, including:

- active release-key status,
- exact `key_id`,
- exact `public_key_uri`,
- exact lowercase public-key SHA-256 digest,
- the complete ordered hybrid baseline.

A valid signature from only one baseline algorithm is insufficient. Both
signatures MUST verify over their RFC 9052 COSE Sig_structure values and the
same embedded payload.

## 9. Validation sequence

A verifier MUST perform the following steps without automatic fallback:

1. enforce input-size and nesting limits,
2. decode CBOR while rejecting duplicate keys and unsupported data types,
3. verify CBOR tag 98 and the exact COSE_Sign shape,
4. verify deterministic encoding of the complete object and protected maps,
5. verify exact body headers and empty body unprotected headers,
6. decode and validate the embedded TFWS manifest,
7. verify exactly two ordered signature entries,
8. bind each protected `alg` and `kid` to one manifest key descriptor,
9. verify Ed25519 and ML-DSA-65 using the RFC 9052 Sig_structure,
10. return success only after both signatures and all manifest policy checks
    pass.

If the caller selected the COSE representation, any parsing, policy or
cryptographic failure is terminal. An implementation MUST NOT retry the JSON
path after a COSE failure. Selection of another representation is a separate,
explicit caller policy decision made before verification.

## 10. Resource limits

An implementation MUST enforce configurable resource limits. The engineering
profile defaults are:

- maximum complete envelope size: 8 MiB,
- maximum embedded manifest size: 4 MiB,
- maximum nesting depth: 32,
- maximum map pairs in one map: 1024,
- maximum array items in one array: 4096,
- maximum individual text or byte string: 4 MiB.

An implementation MAY use stricter limits. Exceeding a limit MUST fail before
cryptographic verification.

## 11. Error categories

Implementations SHOULD expose stable machine-readable categories while
keeping human-readable details:

- `malformed_cbor`
- `non_deterministic_cbor`
- `unsupported_cbor_type`
- `resource_limit`
- `invalid_cose_structure`
- `unsupported_header`
- `invalid_content_type`
- `invalid_type`
- `invalid_algorithm`
- `invalid_kid`
- `hybrid_baseline_incomplete`
- `key_binding_mismatch`
- `signature_invalid`
- `manifest_policy_invalid`

Error messages MUST NOT disclose private-key material or secret intermediate
values.

## 12. Conformance vectors

The profile requires committed byte-level positive and negative vectors.

Positive vectors MUST cover:

- deterministic manifest encoding,
- the complete tagged COSE_Sign envelope,
- Ed25519 plus ML-DSA-65 verification,
- semantic equivalence with the canonical JSON manifest.

Negative vectors MUST cover at least:

- non-preferred integer or length encoding,
- indefinite-length items,
- non-deterministic map ordering,
- duplicate map keys,
- unsupported manifest types,
- wrong tag or COSE structure,
- detached payload,
- altered payload,
- altered protected headers,
- unknown or unprotected mandatory headers,
- missing, duplicate, reordered or substituted algorithms,
- wrong `kid`,
- public-key replacement,
- one valid and one invalid signature,
- resource-limit violations.

Rust and the Python reference implementation MUST produce the same
accept/reject result for every committed vector.

## 13. Security considerations

The compact representation does not weaken the TFWS hybrid baseline.

Implementations MUST NOT:

- accept one signature as a substitute for the required pair,
- infer algorithms from key material,
- trust unprotected headers for policy decisions,
- normalize a malformed input into an acceptable input,
- silently fall back to JSON after a COSE failure,
- advertise unsupported COSE features.

Countersignatures, encryption, detached payloads, external AAD, embedded
COSE_Key objects and selective disclosure are outside this engineering
profile and MUST be rejected unless a later approved specification adds them.

## 14. Implementation status

At the time of this draft, the repository contains the JSON manifest and
signature-bundle path but no CBOR/COSE codec, implementation dependency or
conformance vectors.

This document defines the target profile for issues A2-COSE-02 through
A2-COSE-06. Production completion remains blocked by `RELEASE-GATES.md`.
