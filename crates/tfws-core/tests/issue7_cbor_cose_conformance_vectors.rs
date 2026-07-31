use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tfws_core::{
    decode_manifest_cbor, encode_manifest_cbor, sign_manifest_cose, verify_manifest_cose,
    CborLimits, CoseAlgorithm, CoseCryptoError, CoseSigner, CoseVerifier, KeyDescriptor, Manifest,
};

const CORPUS: &str = include_str!(
    "../../../test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.json"
);
const EXPECTED_ED_SHA256: &str = "7fe64728f1a7bb8c6c103f49c0e2ed0e999678229256c7aab813634cc6c85ba9";
const EXPECTED_ML_SHA256: &str = "85acf51bf7260bc7009f1b3d6b8a4f6d0442bf21ea91a86fe7cbb282edb317cb";

#[derive(Debug, Deserialize)]
struct Corpus {
    corpus_version: String,
    profile: String,
    positive: PositiveVector,
    negative: Vec<NegativeVector>,
}

#[derive(Debug, Deserialize)]
struct PositiveVector {
    id: String,
    manifest: Value,
    manifest_cbor_hex: String,
    manifest_cbor_sha256: String,
    cose_hex: String,
    cose_sha256: String,
    expected_category: String,
}

#[derive(Debug, Deserialize)]
struct NegativeVector {
    id: String,
    #[serde(rename = "class")]
    case_class: String,
    input_type: String,
    bytes_hex: String,
    sha256: String,
    expected_category: String,
}

#[derive(Default)]
struct FixtureCrypto;

impl CoseSigner for FixtureCrypto {
    fn sign(
        &self,
        algorithm: CoseAlgorithm,
        descriptor: &KeyDescriptor,
        message: &[u8],
    ) -> Result<Vec<u8>, CoseCryptoError> {
        validate_binding(algorithm, descriptor)?;
        Ok(signature_for(algorithm, message))
    }
}

impl CoseVerifier for FixtureCrypto {
    fn verify(
        &self,
        algorithm: CoseAlgorithm,
        descriptor: &KeyDescriptor,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CoseCryptoError> {
        validate_binding(algorithm, descriptor)?;
        if signature != signature_for(algorithm, message) {
            return Err(CoseCryptoError::SignatureInvalid);
        }
        Ok(())
    }
}

fn validate_binding(
    algorithm: CoseAlgorithm,
    descriptor: &KeyDescriptor,
) -> Result<(), CoseCryptoError> {
    let expected_sha = match algorithm {
        CoseAlgorithm::Ed25519 => EXPECTED_ED_SHA256,
        CoseAlgorithm::MlDsa65 => EXPECTED_ML_SHA256,
    };
    if descriptor.algorithm != algorithm.tfws_identifier()
        || descriptor.key_id != "release-1"
        || descriptor.public_key_uri
            != format!("/.well-known/keys/{}.pem", algorithm.tfws_identifier())
        || descriptor.public_key_sha256 != expected_sha
        || descriptor.status != "active"
        || descriptor.usage.as_slice() != ["release"]
    {
        return Err(CoseCryptoError::KeyBindingMismatch);
    }
    Ok(())
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

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex length must be even");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            (high << 4) | low
        })
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid lowercase hex byte: {value}"),
    }
}

fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn load_corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("valid issue #7 corpus JSON")
}

#[test]
fn committed_positive_vector_is_byte_exact_in_rust() {
    let corpus = load_corpus();
    assert_eq!(corpus.corpus_version, "1");
    assert_eq!(corpus.profile, "A2-COSE-04");
    assert_eq!(corpus.positive.id, "positive-hybrid-envelope-v1");
    assert_eq!(corpus.positive.expected_category, "valid");

    let manifest: Manifest =
        serde_json::from_value(corpus.positive.manifest).expect("valid corpus manifest");
    let expected_payload = decode_hex(&corpus.positive.manifest_cbor_hex);
    let expected_envelope = decode_hex(&corpus.positive.cose_hex);

    let payload = encode_manifest_cbor(&manifest).expect("deterministic manifest CBOR");
    assert_eq!(payload, expected_payload);
    assert_eq!(sha256(&payload), corpus.positive.manifest_cbor_sha256);

    let crypto = FixtureCrypto;
    let envelope = sign_manifest_cose(&manifest, &crypto).expect("deterministic fixture COSE");
    assert_eq!(envelope, expected_envelope);
    assert_eq!(sha256(&envelope), corpus.positive.cose_sha256);

    let verified = verify_manifest_cose(&envelope, &crypto).expect("positive vector verification");
    assert_eq!(
        serde_json::to_value(verified).expect("verified manifest JSON"),
        serde_json::to_value(manifest).expect("source manifest JSON")
    );
}

#[test]
fn every_negative_vector_fails_with_the_committed_category() {
    let corpus = load_corpus();
    let crypto = FixtureCrypto;
    assert_eq!(corpus.negative.len(), 18);

    for case in corpus.negative {
        let bytes = decode_hex(&case.bytes_hex);
        assert_eq!(sha256(&bytes), case.sha256, "digest: {}", case.id);

        let actual = match case.input_type.as_str() {
            "manifest_cbor" => decode_manifest_cbor(&bytes, CborLimits::default())
                .expect_err(&format!("negative manifest vector accepted: {}", case.id))
                .category(),
            "cose" => verify_manifest_cose(&bytes, &crypto)
                .expect_err(&format!("negative COSE vector accepted: {}", case.id))
                .category(),
            other => panic!("unknown input type {other}: {}", case.id),
        };

        assert_eq!(
            actual, case.expected_category,
            "{} / {}",
            case.id, case.case_class
        );
    }
}

#[test]
fn committed_inventory_covers_all_required_negative_classes() {
    let corpus = load_corpus();
    let mut classes = corpus
        .negative
        .iter()
        .map(|case| case.case_class.as_str())
        .collect::<Vec<_>>();
    classes.sort_unstable();

    let mut expected = vec![
        "algorithm_mismatch",
        "algorithm_substitution",
        "duplicate_key",
        "duplicate_signature_component",
        "invalid_ed25519_signature",
        "invalid_ml_dsa_65_signature",
        "malformed_cbor",
        "missing_ed25519_signature",
        "missing_ml_dsa_65_signature",
        "noncanonical_cbor",
        "payload_substitution",
        "protected_header_substitution",
        "truncated_cbor",
        "unknown_mandatory_algorithm",
        "unsupported_mandatory_field",
        "wrong_key_identifier",
        "wrong_public_key_descriptor",
        "wrong_sha256_key_binding",
    ];
    expected.sort_unstable();
    assert_eq!(classes, expected);
}
