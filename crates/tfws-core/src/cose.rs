use crate::{
    decode_manifest_cbor, encode_manifest_cbor_with_limits, CborCodecError, CborLimits,
    KeyDescriptor, Manifest,
};
use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use std::fmt;
use thiserror::Error;

pub const COSE_SIGN_TAG: u64 = 98;
pub const COSE_CONTENT_TYPE: &str = "application/tfws+cbor";
pub const COSE_TYPE: &str = "application/cose; cose-type=\"cose-sign\"";
pub const ED25519_COSE_ALGORITHM: i64 = -19;
pub const ML_DSA_65_COSE_ALGORITHM: i64 = -49;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

const REQUIRED_SIGNATURES: [CoseAlgorithm; 2] = [CoseAlgorithm::Ed25519, CoseAlgorithm::MlDsa65];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoseLimits {
    pub max_envelope_bytes: usize,
    pub cbor: CborLimits,
}

impl Default for CoseLimits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: 8 * 1024 * 1024,
            cbor: CborLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseAlgorithm {
    Ed25519,
    MlDsa65,
}

impl CoseAlgorithm {
    pub const fn cose_value(self) -> i64 {
        match self {
            Self::Ed25519 => ED25519_COSE_ALGORITHM,
            Self::MlDsa65 => ML_DSA_65_COSE_ALGORITHM,
        }
    }

    pub const fn tfws_identifier(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa65 => "ml-dsa-65",
        }
    }

    pub const fn expected_signature_len(self) -> usize {
        match self {
            Self::Ed25519 => ED25519_SIGNATURE_BYTES,
            Self::MlDsa65 => ML_DSA_65_SIGNATURE_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoseCryptoError {
    #[error("public-key binding mismatch")]
    KeyBindingMismatch,
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("cryptographic operation failed: {0}")]
    OperationFailed(String),
}

pub trait CoseSigner {
    fn sign(
        &self,
        algorithm: CoseAlgorithm,
        descriptor: &KeyDescriptor,
        message: &[u8],
    ) -> Result<Vec<u8>, CoseCryptoError>;
}

pub trait CoseVerifier {
    fn verify(
        &self,
        algorithm: CoseAlgorithm,
        descriptor: &KeyDescriptor,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CoseCryptoError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoseEnvelopeError {
    #[error("manifest CBOR invalid: {0}")]
    ManifestCbor(#[from] CborCodecError),
    #[error("malformed CBOR: {0}")]
    MalformedCbor(String),
    #[error("CBOR representation is not deterministic")]
    NonDeterministicCbor,
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("invalid COSE structure: {0}")]
    InvalidCoseStructure(&'static str),
    #[error("unsupported COSE header")]
    UnsupportedHeader,
    #[error("invalid COSE content type")]
    InvalidContentType,
    #[error("invalid COSE typ header")]
    InvalidType,
    #[error("invalid or reordered COSE algorithm")]
    InvalidAlgorithm,
    #[error("invalid COSE key identifier")]
    InvalidKid,
    #[error("hybrid signature baseline is incomplete")]
    HybridBaselineIncomplete,
    #[error("public-key binding mismatch")]
    KeyBindingMismatch,
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("manifest policy invalid: {0}")]
    ManifestPolicyInvalid(String),
    #[error("CBOR encoding failed: {0}")]
    EncodeFailure(String),
    #[error("cryptographic operation failed: {0}")]
    CryptoOperation(String),
}

impl CoseEnvelopeError {
    pub fn category(&self) -> &'static str {
        match self {
            Self::ManifestCbor(error) => error.category(),
            Self::MalformedCbor(_) | Self::EncodeFailure(_) => "malformed_cbor",
            Self::NonDeterministicCbor => "non_deterministic_cbor",
            Self::ResourceLimit(_) => "resource_limit",
            Self::InvalidCoseStructure(_) => "invalid_cose_structure",
            Self::UnsupportedHeader => "unsupported_header",
            Self::InvalidContentType => "invalid_content_type",
            Self::InvalidType => "invalid_type",
            Self::InvalidAlgorithm => "invalid_algorithm",
            Self::InvalidKid => "invalid_kid",
            Self::HybridBaselineIncomplete => "hybrid_baseline_incomplete",
            Self::KeyBindingMismatch => "key_binding_mismatch",
            Self::SignatureInvalid | Self::CryptoOperation(_) => "signature_invalid",
            Self::ManifestPolicyInvalid(_) => "manifest_policy_invalid",
        }
    }
}

struct EncodedSignature {
    protected: Vec<u8>,
    signature: Vec<u8>,
}

struct ParsedSignature {
    algorithm: CoseAlgorithm,
    protected: Vec<u8>,
    kid: Vec<u8>,
    signature: Vec<u8>,
}

struct ParsedEnvelope {
    body_protected: Vec<u8>,
    payload: Vec<u8>,
    signatures: Vec<ParsedSignature>,
}

pub fn sign_manifest_cose<S: CoseSigner + ?Sized>(
    manifest: &Manifest,
    signer: &S,
) -> Result<Vec<u8>, CoseEnvelopeError> {
    sign_manifest_cose_with_limits(manifest, signer, CoseLimits::default())
}

pub fn sign_manifest_cose_with_limits<S: CoseSigner + ?Sized>(
    manifest: &Manifest,
    signer: &S,
    limits: CoseLimits,
) -> Result<Vec<u8>, CoseEnvelopeError> {
    validate_fixed_shape_limits(limits)?;

    let payload = encode_manifest_cbor_with_limits(manifest, limits.cbor)?;
    let body_protected = encode_body_protected()?;
    let mut signatures = Vec::with_capacity(REQUIRED_SIGNATURES.len());

    for algorithm in REQUIRED_SIGNATURES {
        let descriptor = descriptor_for(manifest, algorithm)?;
        let protected = encode_signature_protected(algorithm, descriptor.key_id.as_bytes())?;
        let message = encode_sig_structure(&body_protected, &protected, &payload)?;
        let signature = signer
            .sign(algorithm, descriptor, &message)
            .map_err(map_crypto_error)?;

        validate_signature_length(algorithm, signature.len())?;

        if signature.len() > limits.cbor.max_string_bytes {
            return Err(CoseEnvelopeError::ResourceLimit("signature bytes"));
        }

        signatures.push(EncodedSignature {
            protected,
            signature,
        });
    }

    let encoded = encode_envelope(&body_protected, &payload, &signatures)?;

    if encoded.len() > limits.max_envelope_bytes {
        return Err(CoseEnvelopeError::ResourceLimit("complete envelope bytes"));
    }

    parse_envelope(&encoded, limits)?;

    Ok(encoded)
}

pub fn verify_manifest_cose<V: CoseVerifier + ?Sized>(
    envelope: &[u8],
    verifier: &V,
) -> Result<Manifest, CoseEnvelopeError> {
    verify_manifest_cose_with_limits(envelope, verifier, CoseLimits::default())
}

pub fn verify_manifest_cose_with_limits<V: CoseVerifier + ?Sized>(
    envelope: &[u8],
    verifier: &V,
    limits: CoseLimits,
) -> Result<Manifest, CoseEnvelopeError> {
    let parsed = parse_envelope(envelope, limits)?;
    let manifest = decode_manifest_cbor(&parsed.payload, limits.cbor)?;

    if parsed.signatures.len() != REQUIRED_SIGNATURES.len() {
        return Err(CoseEnvelopeError::HybridBaselineIncomplete);
    }

    for (signature, expected_algorithm) in parsed.signatures.iter().zip(REQUIRED_SIGNATURES) {
        if signature.algorithm != expected_algorithm {
            return Err(CoseEnvelopeError::InvalidAlgorithm);
        }

        let descriptor = descriptor_for(&manifest, expected_algorithm)?;

        if signature.kid.as_slice() != descriptor.key_id.as_bytes() {
            return Err(CoseEnvelopeError::InvalidKid);
        }

        let message = encode_sig_structure(
            &parsed.body_protected,
            &signature.protected,
            &parsed.payload,
        )?;

        verifier
            .verify(
                expected_algorithm,
                descriptor,
                &message,
                &signature.signature,
            )
            .map_err(map_crypto_error)?;
    }

    Ok(manifest)
}

fn descriptor_for(
    manifest: &Manifest,
    algorithm: CoseAlgorithm,
) -> Result<&KeyDescriptor, CoseEnvelopeError> {
    let mut matching = manifest
        .keys
        .iter()
        .filter(|descriptor| descriptor.algorithm == algorithm.tfws_identifier());

    let descriptor = matching
        .next()
        .ok_or(CoseEnvelopeError::HybridBaselineIncomplete)?;

    if matching.next().is_some() {
        return Err(CoseEnvelopeError::HybridBaselineIncomplete);
    }

    if descriptor.key_id.is_empty() {
        return Err(CoseEnvelopeError::KeyBindingMismatch);
    }

    Ok(descriptor)
}

fn parse_envelope(input: &[u8], limits: CoseLimits) -> Result<ParsedEnvelope, CoseEnvelopeError> {
    validate_fixed_shape_limits(limits)?;

    if input.len() > limits.max_envelope_bytes {
        return Err(CoseEnvelopeError::ResourceLimit("complete envelope bytes"));
    }

    if input.len() < 3 {
        return Err(CoseEnvelopeError::MalformedCbor(
            "input is too short".into(),
        ));
    }

    if input[..2] != [0xd8, 0x62] {
        return Err(CoseEnvelopeError::InvalidCoseStructure(
            "preferred CBOR tag 98 is required",
        ));
    }

    let mut decoder = Decoder::new(&input[2..]);
    expect_array(&mut decoder, 4, "COSE_Sign outer array")?;

    let body_protected = read_bytes(&mut decoder, limits.cbor.max_string_bytes, "body protected")?;
    validate_body_protected(&body_protected, limits)?;

    expect_empty_map(&mut decoder, "body unprotected")?;

    let payload = read_bytes(
        &mut decoder,
        limits.cbor.max_manifest_bytes,
        "embedded manifest",
    )?;

    expect_array(&mut decoder, 2, "signatures array")?;

    let mut signatures = Vec::with_capacity(REQUIRED_SIGNATURES.len());

    for expected_algorithm in REQUIRED_SIGNATURES {
        signatures.push(parse_signature(&mut decoder, expected_algorithm, limits)?);
    }

    if decoder.position() != input.len() - 2 {
        return Err(CoseEnvelopeError::MalformedCbor(
            "trailing data after COSE_Sign".into(),
        ));
    }

    let encoded_signatures: Vec<EncodedSignature> = signatures
        .iter()
        .map(|signature| EncodedSignature {
            protected: signature.protected.clone(),
            signature: signature.signature.clone(),
        })
        .collect();

    let deterministic = encode_envelope(&body_protected, &payload, &encoded_signatures)?;

    if deterministic != input {
        return Err(CoseEnvelopeError::NonDeterministicCbor);
    }

    Ok(ParsedEnvelope {
        body_protected,
        payload,
        signatures,
    })
}

fn parse_signature(
    decoder: &mut Decoder<'_>,
    expected_algorithm: CoseAlgorithm,
    limits: CoseLimits,
) -> Result<ParsedSignature, CoseEnvelopeError> {
    expect_array(decoder, 3, "COSE_Signature array")?;

    let protected = read_bytes(decoder, limits.cbor.max_string_bytes, "signature protected")?;
    let kid = validate_signature_protected(&protected, expected_algorithm, limits)?;

    expect_empty_map(decoder, "signature unprotected")?;

    let signature = read_bytes(decoder, limits.cbor.max_string_bytes, "signature")?;
    validate_signature_length(expected_algorithm, signature.len())?;

    Ok(ParsedSignature {
        algorithm: expected_algorithm,
        protected,
        kid,
        signature,
    })
}

fn validate_signature_length(
    algorithm: CoseAlgorithm,
    actual: usize,
) -> Result<(), CoseEnvelopeError> {
    if actual != algorithm.expected_signature_len() {
        return Err(CoseEnvelopeError::SignatureInvalid);
    }

    Ok(())
}

fn validate_body_protected(input: &[u8], limits: CoseLimits) -> Result<(), CoseEnvelopeError> {
    let mut decoder = Decoder::new(input);
    let length = read_map_length(&mut decoder, "body protected map")?;

    if length != 2 {
        return Err(CoseEnvelopeError::UnsupportedHeader);
    }

    if read_header_label(&mut decoder)? != 3 {
        return Err(CoseEnvelopeError::UnsupportedHeader);
    }

    let content_type = read_text(&mut decoder, limits.cbor.max_string_bytes, "content type")?;

    if content_type != COSE_CONTENT_TYPE {
        return Err(CoseEnvelopeError::InvalidContentType);
    }

    if read_header_label(&mut decoder)? != 16 {
        return Err(CoseEnvelopeError::UnsupportedHeader);
    }

    let cose_type = read_text(&mut decoder, limits.cbor.max_string_bytes, "typ")?;

    if cose_type != COSE_TYPE {
        return Err(CoseEnvelopeError::InvalidType);
    }

    if decoder.position() != input.len() {
        return Err(CoseEnvelopeError::MalformedCbor(
            "trailing body protected data".into(),
        ));
    }

    if encode_body_protected()? != input {
        return Err(CoseEnvelopeError::NonDeterministicCbor);
    }

    Ok(())
}

fn validate_signature_protected(
    input: &[u8],
    expected_algorithm: CoseAlgorithm,
    limits: CoseLimits,
) -> Result<Vec<u8>, CoseEnvelopeError> {
    let mut decoder = Decoder::new(input);
    let length = read_map_length(&mut decoder, "signature protected map")?;

    if length != 2 {
        return Err(CoseEnvelopeError::UnsupportedHeader);
    }

    if read_header_label(&mut decoder)? != 1 {
        return Err(CoseEnvelopeError::UnsupportedHeader);
    }

    let algorithm = decoder
        .i64()
        .map_err(|_| CoseEnvelopeError::InvalidAlgorithm)?;

    if algorithm != expected_algorithm.cose_value() {
        return Err(CoseEnvelopeError::InvalidAlgorithm);
    }

    if read_header_label(&mut decoder)? != 4 {
        return Err(CoseEnvelopeError::UnsupportedHeader);
    }

    let kid = read_bytes(&mut decoder, limits.cbor.max_string_bytes, "signature kid")?;

    if kid.is_empty() || std::str::from_utf8(&kid).is_err() {
        return Err(CoseEnvelopeError::InvalidKid);
    }

    if decoder.position() != input.len() {
        return Err(CoseEnvelopeError::MalformedCbor(
            "trailing signature protected data".into(),
        ));
    }

    if encode_signature_protected(expected_algorithm, &kid)? != input {
        return Err(CoseEnvelopeError::NonDeterministicCbor);
    }

    Ok(kid)
}

fn validate_fixed_shape_limits(limits: CoseLimits) -> Result<(), CoseEnvelopeError> {
    if limits.cbor.max_depth < 4 {
        return Err(CoseEnvelopeError::ResourceLimit("nesting depth"));
    }

    if limits.cbor.max_array_items < 4 {
        return Err(CoseEnvelopeError::ResourceLimit("array items"));
    }

    if limits.cbor.max_map_pairs < 2 {
        return Err(CoseEnvelopeError::ResourceLimit("map pairs"));
    }

    Ok(())
}

fn expect_array(
    decoder: &mut Decoder<'_>,
    expected: u64,
    name: &'static str,
) -> Result<(), CoseEnvelopeError> {
    match decoder.datatype().map_err(malformed_decode_error)? {
        Type::Array => {}
        Type::ArrayIndef => return Err(CoseEnvelopeError::NonDeterministicCbor),
        _ => return Err(CoseEnvelopeError::InvalidCoseStructure(name)),
    }

    let length = decoder
        .array()
        .map_err(malformed_decode_error)?
        .ok_or(CoseEnvelopeError::NonDeterministicCbor)?;

    if length != expected {
        return Err(CoseEnvelopeError::InvalidCoseStructure(name));
    }

    Ok(())
}

fn read_map_length(
    decoder: &mut Decoder<'_>,
    name: &'static str,
) -> Result<u64, CoseEnvelopeError> {
    match decoder.datatype().map_err(malformed_decode_error)? {
        Type::Map => {}
        Type::MapIndef => return Err(CoseEnvelopeError::NonDeterministicCbor),
        _ => return Err(CoseEnvelopeError::InvalidCoseStructure(name)),
    }

    decoder
        .map()
        .map_err(malformed_decode_error)?
        .ok_or(CoseEnvelopeError::NonDeterministicCbor)
}

fn expect_empty_map(
    decoder: &mut Decoder<'_>,
    name: &'static str,
) -> Result<(), CoseEnvelopeError> {
    let length = read_map_length(decoder, name)?;

    if length != 0 {
        return Err(CoseEnvelopeError::UnsupportedHeader);
    }

    Ok(())
}

fn read_bytes(
    decoder: &mut Decoder<'_>,
    maximum: usize,
    name: &'static str,
) -> Result<Vec<u8>, CoseEnvelopeError> {
    match decoder.datatype().map_err(malformed_decode_error)? {
        Type::Bytes => {}
        Type::BytesIndef => return Err(CoseEnvelopeError::NonDeterministicCbor),
        _ => return Err(CoseEnvelopeError::InvalidCoseStructure(name)),
    }

    let value = decoder.bytes().map_err(malformed_decode_error)?;

    if value.len() > maximum {
        return Err(CoseEnvelopeError::ResourceLimit(name));
    }

    Ok(value.to_vec())
}

fn read_text<'a>(
    decoder: &mut Decoder<'a>,
    maximum: usize,
    name: &'static str,
) -> Result<&'a str, CoseEnvelopeError> {
    match decoder.datatype().map_err(malformed_decode_error)? {
        Type::String => {}
        Type::StringIndef => return Err(CoseEnvelopeError::NonDeterministicCbor),
        _ => return Err(CoseEnvelopeError::InvalidCoseStructure(name)),
    }

    let value = decoder.str().map_err(malformed_decode_error)?;

    if value.len() > maximum {
        return Err(CoseEnvelopeError::ResourceLimit(name));
    }

    Ok(value)
}

fn read_header_label(decoder: &mut Decoder<'_>) -> Result<i64, CoseEnvelopeError> {
    decoder
        .i64()
        .map_err(|_| CoseEnvelopeError::UnsupportedHeader)
}

fn encode_body_protected() -> Result<Vec<u8>, CoseEnvelopeError> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);

    encoder
        .map(2)
        .map_err(encode_error)?
        .u8(3)
        .map_err(encode_error)?
        .str(COSE_CONTENT_TYPE)
        .map_err(encode_error)?
        .u8(16)
        .map_err(encode_error)?
        .str(COSE_TYPE)
        .map_err(encode_error)?;

    Ok(output)
}

fn encode_signature_protected(
    algorithm: CoseAlgorithm,
    kid: &[u8],
) -> Result<Vec<u8>, CoseEnvelopeError> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);

    encoder
        .map(2)
        .map_err(encode_error)?
        .u8(1)
        .map_err(encode_error)?
        .i64(algorithm.cose_value())
        .map_err(encode_error)?
        .u8(4)
        .map_err(encode_error)?
        .bytes(kid)
        .map_err(encode_error)?;

    Ok(output)
}

fn encode_sig_structure(
    body_protected: &[u8],
    signature_protected: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CoseEnvelopeError> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);

    encoder
        .array(5)
        .map_err(encode_error)?
        .str("Signature")
        .map_err(encode_error)?
        .bytes(body_protected)
        .map_err(encode_error)?
        .bytes(signature_protected)
        .map_err(encode_error)?
        .bytes(&[])
        .map_err(encode_error)?
        .bytes(payload)
        .map_err(encode_error)?;

    Ok(output)
}

fn encode_envelope(
    body_protected: &[u8],
    payload: &[u8],
    signatures: &[EncodedSignature],
) -> Result<Vec<u8>, CoseEnvelopeError> {
    if signatures.len() != REQUIRED_SIGNATURES.len() {
        return Err(CoseEnvelopeError::HybridBaselineIncomplete);
    }

    let mut output = vec![0xd8, 0x62];
    let mut encoder = Encoder::new(&mut output);

    encoder
        .array(4)
        .map_err(encode_error)?
        .bytes(body_protected)
        .map_err(encode_error)?
        .map(0)
        .map_err(encode_error)?
        .bytes(payload)
        .map_err(encode_error)?
        .array(2)
        .map_err(encode_error)?;

    for signature in signatures {
        encoder
            .array(3)
            .map_err(encode_error)?
            .bytes(&signature.protected)
            .map_err(encode_error)?
            .map(0)
            .map_err(encode_error)?
            .bytes(&signature.signature)
            .map_err(encode_error)?;
    }

    Ok(output)
}

fn map_crypto_error(error: CoseCryptoError) -> CoseEnvelopeError {
    match error {
        CoseCryptoError::KeyBindingMismatch => CoseEnvelopeError::KeyBindingMismatch,
        CoseCryptoError::SignatureInvalid => CoseEnvelopeError::SignatureInvalid,
        CoseCryptoError::OperationFailed(message) => CoseEnvelopeError::CryptoOperation(message),
    }
}

fn malformed_decode_error(error: minicbor::decode::Error) -> CoseEnvelopeError {
    CoseEnvelopeError::MalformedCbor(error.to_string())
}

fn encode_error<E: fmt::Display>(error: minicbor::encode::Error<E>) -> CoseEnvelopeError {
    CoseEnvelopeError::EncodeFailure(error.to_string())
}
