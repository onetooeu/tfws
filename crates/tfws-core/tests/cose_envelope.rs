use minicbor::Encoder;
use sha2::{Digest, Sha256};
use tfws_core::{
    encode_manifest_cbor, sign_manifest_cose, sign_manifest_cose_with_limits, verify_manifest_cose,
    verify_manifest_cose_with_limits, CoseAlgorithm, CoseCryptoError, CoseEnvelopeError,
    CoseLimits, CoseSigner, CoseVerifier, KeyDescriptor, Manifest, COSE_CONTENT_TYPE, COSE_TYPE,
    ED25519_COSE_ALGORITHM, ED25519_SIGNATURE_BYTES, ML_DSA_65_COSE_ALGORITHM,
    ML_DSA_65_SIGNATURE_BYTES,
};

#[derive(Default)]
struct DeterministicCrypto {
    rejected_algorithm: Option<CoseAlgorithm>,
    binding_failure: bool,
}

impl CoseSigner for DeterministicCrypto {
    fn sign(
        &self,
        algorithm: CoseAlgorithm,
        descriptor: &KeyDescriptor,
        message: &[u8],
    ) -> Result<Vec<u8>, CoseCryptoError> {
        if self.binding_failure || descriptor.algorithm != algorithm.tfws_identifier() {
            return Err(CoseCryptoError::KeyBindingMismatch);
        }

        Ok(signature_for(algorithm, message))
    }
}

impl CoseVerifier for DeterministicCrypto {
    fn verify(
        &self,
        algorithm: CoseAlgorithm,
        descriptor: &KeyDescriptor,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CoseCryptoError> {
        if self.binding_failure || descriptor.algorithm != algorithm.tfws_identifier() {
            return Err(CoseCryptoError::KeyBindingMismatch);
        }

        if self.rejected_algorithm == Some(algorithm)
            || signature != signature_for(algorithm, message)
        {
            return Err(CoseCryptoError::SignatureInvalid);
        }

        Ok(())
    }
}

struct WrongLengthSigner;

impl CoseSigner for WrongLengthSigner {
    fn sign(
        &self,
        algorithm: CoseAlgorithm,
        _descriptor: &KeyDescriptor,
        _message: &[u8],
    ) -> Result<Vec<u8>, CoseCryptoError> {
        Ok(vec![0x55; algorithm.expected_signature_len() - 1])
    }
}

fn sample() -> Manifest {
    serde_json::from_str(include_str!("../../../test-vectors/manifest.valid.json"))
        .expect("valid embedded manifest")
}

fn signature_for(algorithm: CoseAlgorithm, message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([match algorithm {
        CoseAlgorithm::Ed25519 => 0x13,
        CoseAlgorithm::MlDsa65 => 0x31,
    }]);
    hasher.update(message);
    let digest = hasher.finalize();

    digest
        .iter()
        .copied()
        .cycle()
        .take(algorithm.expected_signature_len())
        .collect()
}

fn body_protected(content_type: &str, cose_type: &str, extra_header: bool) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);

    encoder
        .map(if extra_header { 3 } else { 2 })
        .expect("body map")
        .u8(3)
        .expect("content label")
        .str(content_type)
        .expect("content")
        .u8(16)
        .expect("typ label")
        .str(cose_type)
        .expect("typ");

    if extra_header {
        encoder
            .u8(99)
            .expect("extra label")
            .bool(true)
            .expect("extra value");
    }

    output
}

fn signature_protected(algorithm: i64, kid: &[u8], critical_header: bool) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);

    encoder
        .map(if critical_header { 3 } else { 2 })
        .expect("signature map")
        .u8(1)
        .expect("alg label")
        .i64(algorithm)
        .expect("alg");

    if critical_header {
        encoder
            .u8(2)
            .expect("crit label")
            .array(1)
            .expect("crit array")
            .u8(99)
            .expect("crit value");
    }

    encoder.u8(4).expect("kid label").bytes(kid).expect("kid");

    output
}

fn raw_envelope(
    body: &[u8],
    payload: Option<&[u8]>,
    signatures: &[(&[u8], &[u8])],
    body_unprotected: bool,
    signature_unprotected: bool,
) -> Vec<u8> {
    let mut output = vec![0xd8, 0x62];
    let mut encoder = Encoder::new(&mut output);

    encoder
        .array(4)
        .expect("outer array")
        .bytes(body)
        .expect("body protected");

    if body_unprotected {
        encoder
            .map(1)
            .expect("body unprotected")
            .u8(99)
            .expect("body header")
            .bool(true)
            .expect("body header value");
    } else {
        encoder.map(0).expect("empty body unprotected");
    }

    match payload {
        Some(value) => {
            encoder.bytes(value).expect("payload");
        }
        None => {
            encoder.null().expect("detached payload");
        }
    }

    encoder.array(signatures.len() as u64).expect("signatures");

    for (protected, signature) in signatures {
        encoder
            .array(3)
            .expect("signature array")
            .bytes(protected)
            .expect("signature protected");

        if signature_unprotected {
            encoder
                .map(1)
                .expect("signature unprotected")
                .u8(99)
                .expect("signature header")
                .bool(true)
                .expect("signature header value");
        } else {
            encoder.map(0).expect("empty signature unprotected");
        }

        encoder.bytes(signature).expect("signature");
    }

    output
}

fn standard_raw_envelope(
    payload: Option<&[u8]>,
    first_protected: &[u8],
    second_protected: &[u8],
) -> Vec<u8> {
    let first_signature = vec![0x11; ED25519_SIGNATURE_BYTES];
    let second_signature = vec![0x22; ML_DSA_65_SIGNATURE_BYTES];

    raw_envelope(
        &body_protected(COSE_CONTENT_TYPE, COSE_TYPE, false),
        payload,
        &[
            (first_protected, first_signature.as_slice()),
            (second_protected, second_signature.as_slice()),
        ],
        false,
        false,
    )
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("subslice must exist")
}

#[test]
fn deterministic_hybrid_envelope_round_trips() {
    let manifest = sample();
    let crypto = DeterministicCrypto::default();

    let first = sign_manifest_cose(&manifest, &crypto).expect("first signing");
    let second = sign_manifest_cose(&manifest, &crypto).expect("second signing");

    assert_eq!(first, second);
    assert!(first.starts_with(&[0xd8, 0x62]));
    assert!(first.len() < CoseLimits::default().max_envelope_bytes);

    let verified = verify_manifest_cose(&first, &crypto).expect("verification");

    assert_eq!(
        serde_json::to_value(verified).expect("verified JSON"),
        serde_json::to_value(manifest).expect("source JSON")
    );
}

#[test]
fn signature_length_constants_match_the_fixed_profile() {
    assert_eq!(
        CoseAlgorithm::Ed25519.expected_signature_len(),
        ED25519_SIGNATURE_BYTES
    );
    assert_eq!(
        CoseAlgorithm::MlDsa65.expected_signature_len(),
        ML_DSA_65_SIGNATURE_BYTES
    );
    assert_eq!(ED25519_SIGNATURE_BYTES, 64);
    assert_eq!(ML_DSA_65_SIGNATURE_BYTES, 3309);
}

#[test]
fn wrong_signature_lengths_are_rejected() {
    assert_eq!(
        sign_manifest_cose(&sample(), &WrongLengthSigner),
        Err(CoseEnvelopeError::SignatureInvalid)
    );

    let crypto = DeterministicCrypto::default();
    let payload = encode_manifest_cbor(&sample()).expect("payload");
    let ed = signature_protected(ED25519_COSE_ALGORITHM, b"release-1", false);
    let ml = signature_protected(ML_DSA_65_COSE_ALGORITHM, b"release-1", false);
    let short_ed = vec![0x11; ED25519_SIGNATURE_BYTES - 1];
    let exact_ml = vec![0x22; ML_DSA_65_SIGNATURE_BYTES];
    let short_ml = vec![0x22; ML_DSA_65_SIGNATURE_BYTES - 1];
    let exact_ed = vec![0x11; ED25519_SIGNATURE_BYTES];

    let short_ed_envelope = raw_envelope(
        &body_protected(COSE_CONTENT_TYPE, COSE_TYPE, false),
        Some(&payload),
        &[
            (ed.as_slice(), short_ed.as_slice()),
            (ml.as_slice(), exact_ml.as_slice()),
        ],
        false,
        false,
    );

    assert!(matches!(
        verify_manifest_cose(&short_ed_envelope, &crypto),
        Err(CoseEnvelopeError::SignatureInvalid)
    ));

    let short_ml_envelope = raw_envelope(
        &body_protected(COSE_CONTENT_TYPE, COSE_TYPE, false),
        Some(&payload),
        &[
            (ed.as_slice(), exact_ed.as_slice()),
            (ml.as_slice(), short_ml.as_slice()),
        ],
        false,
        false,
    );

    assert!(matches!(
        verify_manifest_cose(&short_ml_envelope, &crypto),
        Err(CoseEnvelopeError::SignatureInvalid)
    ));
}

#[test]
fn preferred_tag_98_is_required() {
    let crypto = DeterministicCrypto::default();
    let mut envelope = sign_manifest_cose(&sample(), &crypto).expect("signing");
    envelope[1] = 0x61;

    assert!(matches!(
        verify_manifest_cose(&envelope, &crypto),
        Err(CoseEnvelopeError::InvalidCoseStructure(_))
    ));
}

#[test]
fn untagged_envelope_is_rejected() {
    let crypto = DeterministicCrypto::default();
    let envelope = sign_manifest_cose(&sample(), &crypto).expect("signing");

    assert!(matches!(
        verify_manifest_cose(&envelope[2..], &crypto),
        Err(CoseEnvelopeError::InvalidCoseStructure(_)) | Err(CoseEnvelopeError::MalformedCbor(_))
    ));
}

#[test]
fn detached_payload_is_rejected() {
    let crypto = DeterministicCrypto::default();
    let ed = signature_protected(ED25519_COSE_ALGORITHM, b"release-1", false);
    let ml = signature_protected(ML_DSA_65_COSE_ALGORITHM, b"release-1", false);
    let envelope = standard_raw_envelope(None, &ed, &ml);

    assert!(matches!(
        verify_manifest_cose(&envelope, &crypto),
        Err(CoseEnvelopeError::InvalidCoseStructure(_))
    ));
}

#[test]
fn wrong_content_type_and_typ_are_rejected() {
    let crypto = DeterministicCrypto::default();
    let payload = encode_manifest_cbor(&sample()).expect("payload");
    let ed = signature_protected(ED25519_COSE_ALGORITHM, b"release-1", false);
    let ml = signature_protected(ML_DSA_65_COSE_ALGORITHM, b"release-1", false);

    let wrong_content = raw_envelope(
        &body_protected("application/octet-stream", COSE_TYPE, false),
        Some(&payload),
        &[(&ed, &[0x11]), (&ml, &[0x22])],
        false,
        false,
    );
    assert!(matches!(
        verify_manifest_cose(&wrong_content, &crypto),
        Err(CoseEnvelopeError::InvalidContentType)
    ));

    let wrong_type = raw_envelope(
        &body_protected(COSE_CONTENT_TYPE, "application/cose", false),
        Some(&payload),
        &[(&ed, &[0x11]), (&ml, &[0x22])],
        false,
        false,
    );
    assert!(matches!(
        verify_manifest_cose(&wrong_type, &crypto),
        Err(CoseEnvelopeError::InvalidType)
    ));
}

#[test]
fn unknown_and_unprotected_headers_are_rejected() {
    let crypto = DeterministicCrypto::default();
    let payload = encode_manifest_cbor(&sample()).expect("payload");
    let ed = signature_protected(ED25519_COSE_ALGORITHM, b"release-1", false);
    let ml = signature_protected(ML_DSA_65_COSE_ALGORITHM, b"release-1", false);

    let unknown_body = raw_envelope(
        &body_protected(COSE_CONTENT_TYPE, COSE_TYPE, true),
        Some(&payload),
        &[(&ed, &[0x11]), (&ml, &[0x22])],
        false,
        false,
    );
    assert!(matches!(
        verify_manifest_cose(&unknown_body, &crypto),
        Err(CoseEnvelopeError::UnsupportedHeader)
    ));

    let body_unprotected = raw_envelope(
        &body_protected(COSE_CONTENT_TYPE, COSE_TYPE, false),
        Some(&payload),
        &[(&ed, &[0x11]), (&ml, &[0x22])],
        true,
        false,
    );
    assert!(matches!(
        verify_manifest_cose(&body_unprotected, &crypto),
        Err(CoseEnvelopeError::UnsupportedHeader)
    ));

    let signature_unprotected = raw_envelope(
        &body_protected(COSE_CONTENT_TYPE, COSE_TYPE, false),
        Some(&payload),
        &[(&ed, &[0x11]), (&ml, &[0x22])],
        false,
        true,
    );
    assert!(matches!(
        verify_manifest_cose(&signature_unprotected, &crypto),
        Err(CoseEnvelopeError::UnsupportedHeader)
    ));
}

#[test]
fn unknown_mandatory_signature_header_is_rejected() {
    let crypto = DeterministicCrypto::default();
    let payload = encode_manifest_cbor(&sample()).expect("payload");
    let ed = signature_protected(ED25519_COSE_ALGORITHM, b"release-1", true);
    let ml = signature_protected(ML_DSA_65_COSE_ALGORITHM, b"release-1", false);
    let envelope = standard_raw_envelope(Some(&payload), &ed, &ml);

    assert!(matches!(
        verify_manifest_cose(&envelope, &crypto),
        Err(CoseEnvelopeError::UnsupportedHeader)
    ));
}

#[test]
fn missing_duplicate_and_reordered_algorithms_are_rejected() {
    let crypto = DeterministicCrypto::default();
    let payload = encode_manifest_cbor(&sample()).expect("payload");
    let ed = signature_protected(ED25519_COSE_ALGORITHM, b"release-1", false);
    let ml = signature_protected(ML_DSA_65_COSE_ALGORITHM, b"release-1", false);
    let one_signature = [0x11];

    let missing = raw_envelope(
        &body_protected(COSE_CONTENT_TYPE, COSE_TYPE, false),
        Some(&payload),
        &[(ed.as_slice(), one_signature.as_slice())],
        false,
        false,
    );
    assert!(matches!(
        verify_manifest_cose(&missing, &crypto),
        Err(CoseEnvelopeError::InvalidCoseStructure(_))
    ));

    let duplicate = standard_raw_envelope(Some(&payload), &ed, &ed);
    assert!(matches!(
        verify_manifest_cose(&duplicate, &crypto),
        Err(CoseEnvelopeError::InvalidAlgorithm)
    ));

    let reordered = standard_raw_envelope(Some(&payload), &ml, &ed);
    assert!(matches!(
        verify_manifest_cose(&reordered, &crypto),
        Err(CoseEnvelopeError::InvalidAlgorithm)
    ));
}

#[test]
fn wrong_kid_is_rejected_before_crypto() {
    let crypto = DeterministicCrypto::default();
    let payload = encode_manifest_cbor(&sample()).expect("payload");
    let ed = signature_protected(ED25519_COSE_ALGORITHM, b"wrong-key", false);
    let ml = signature_protected(ML_DSA_65_COSE_ALGORITHM, b"release-1", false);
    let envelope = standard_raw_envelope(Some(&payload), &ed, &ml);

    assert!(matches!(
        verify_manifest_cose(&envelope, &crypto),
        Err(CoseEnvelopeError::InvalidKid)
    ));
}

#[test]
fn altered_payload_is_rejected() {
    let crypto = DeterministicCrypto::default();
    let manifest = sample();
    let payload = encode_manifest_cbor(&manifest).expect("payload");
    let mut envelope = sign_manifest_cose(&manifest, &crypto).expect("signing");
    let offset = find_subslice(&envelope, &payload);

    envelope[offset + payload.len() - 1] ^= 0x01;

    assert!(verify_manifest_cose(&envelope, &crypto).is_err());
}

#[test]
fn one_invalid_signature_rejects_complete_baseline() {
    let signer = DeterministicCrypto::default();
    let verifier = DeterministicCrypto {
        rejected_algorithm: Some(CoseAlgorithm::MlDsa65),
        binding_failure: false,
    };
    let envelope = sign_manifest_cose(&sample(), &signer).expect("signing");

    assert!(matches!(
        verify_manifest_cose(&envelope, &verifier),
        Err(CoseEnvelopeError::SignatureInvalid)
    ));
}

#[test]
fn signer_key_binding_failure_is_propagated() {
    let signer = DeterministicCrypto {
        rejected_algorithm: None,
        binding_failure: true,
    };

    assert_eq!(
        sign_manifest_cose(&sample(), &signer),
        Err(CoseEnvelopeError::KeyBindingMismatch)
    );
}

#[test]
fn complete_envelope_size_limit_is_enforced() {
    let crypto = DeterministicCrypto::default();
    let envelope = sign_manifest_cose(&sample(), &crypto).expect("signing");
    let limits = CoseLimits {
        max_envelope_bytes: envelope.len() - 1,
        ..CoseLimits::default()
    };

    assert!(matches!(
        verify_manifest_cose_with_limits(&envelope, &crypto, limits),
        Err(CoseEnvelopeError::ResourceLimit("complete envelope bytes"))
    ));

    assert_eq!(
        sign_manifest_cose_with_limits(&sample(), &crypto, limits),
        Err(CoseEnvelopeError::ResourceLimit("complete envelope bytes"))
    );
}

#[test]
fn stable_error_categories_match_profile() {
    assert_eq!(
        CoseEnvelopeError::InvalidCoseStructure("shape").category(),
        "invalid_cose_structure"
    );
    assert_eq!(
        CoseEnvelopeError::UnsupportedHeader.category(),
        "unsupported_header"
    );
    assert_eq!(
        CoseEnvelopeError::InvalidAlgorithm.category(),
        "invalid_algorithm"
    );
    assert_eq!(CoseEnvelopeError::InvalidKid.category(), "invalid_kid");
    assert_eq!(
        CoseEnvelopeError::KeyBindingMismatch.category(),
        "key_binding_mismatch"
    );
    assert_eq!(
        CoseEnvelopeError::SignatureInvalid.category(),
        "signature_invalid"
    );
}
