use crate::Manifest;
use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Configurable limits for one deterministic TFWS CBOR manifest payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborLimits {
    pub max_manifest_bytes: usize,
    pub max_depth: usize,
    pub max_map_pairs: usize,
    pub max_array_items: usize,
    pub max_string_bytes: usize,
}

impl Default for CborLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 4 * 1024 * 1024,
            max_depth: 32,
            max_map_pairs: 1024,
            max_array_items: 4096,
            max_string_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Stable, typed failures for the strict TFWS CBOR manifest codec.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CborCodecError {
    #[error("malformed CBOR: {0}")]
    MalformedCbor(String),
    #[error("CBOR input has trailing data")]
    TrailingData,
    #[error("CBOR uses a non-deterministic or non-preferred representation")]
    NonDeterministicCbor,
    #[error("indefinite-length {0} is not supported")]
    IndefiniteLength(&'static str),
    #[error("unsupported CBOR type: {0}")]
    UnsupportedCborType(String),
    #[error("CBOR integer is outside the TFWS safe integer range")]
    IntegerOutOfRange,
    #[error("duplicate CBOR map key: {0}")]
    DuplicateKey(String),
    #[error("CBOR map keys are not in deterministic order")]
    MapKeyOrder,
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("manifest schema violation: {0}")]
    SchemaViolation(String),
    #[error("manifest policy invalid: {0}")]
    ManifestPolicy(String),
    #[error("CBOR encoding failed: {0}")]
    EncodeFailure(String),
}

impl CborCodecError {
    /// Machine-readable category aligned with the CBOR/COSE profile.
    pub fn category(&self) -> &'static str {
        match self {
            Self::MalformedCbor(_) | Self::TrailingData => "malformed_cbor",
            Self::NonDeterministicCbor
            | Self::IndefiniteLength(_)
            | Self::DuplicateKey(_)
            | Self::MapKeyOrder => "non_deterministic_cbor",
            Self::UnsupportedCborType(_) | Self::IntegerOutOfRange => "unsupported_cbor_type",
            Self::ResourceLimit(_) => "resource_limit",
            Self::SchemaViolation(_) | Self::ManifestPolicy(_) => "manifest_policy_invalid",
            Self::EncodeFailure(_) => "malformed_cbor",
        }
    }
}

/// Encode a validated TFWS manifest using the engineering-profile defaults.
pub fn encode_manifest_cbor(manifest: &Manifest) -> Result<Vec<u8>, CborCodecError> {
    encode_manifest_cbor_with_limits(manifest, CborLimits::default())
}

/// Encode a validated TFWS manifest with explicit resource limits.
pub fn encode_manifest_cbor_with_limits(
    manifest: &Manifest,
    limits: CborLimits,
) -> Result<Vec<u8>, CborCodecError> {
    let value = manifest_to_value(manifest, limits)?;
    let encoded = encode_value_to_vec(&value, limits)?;

    if encoded.len() > limits.max_manifest_bytes {
        return Err(CborCodecError::ResourceLimit("manifest bytes"));
    }

    Ok(encoded)
}

/// Decode one strict deterministic CBOR manifest and apply existing policy checks.
pub fn decode_manifest_cbor(input: &[u8], limits: CborLimits) -> Result<Manifest, CborCodecError> {
    if input.len() > limits.max_manifest_bytes {
        return Err(CborCodecError::ResourceLimit("manifest bytes"));
    }

    if input.is_empty() {
        return Err(CborCodecError::MalformedCbor("empty input".into()));
    }

    let mut decoder = Decoder::new(input);
    let value = decode_value(&mut decoder, limits, 0)?;

    if decoder.position() != input.len() {
        return Err(CborCodecError::TrailingData);
    }

    let deterministic = encode_value_to_vec(&value, limits)?;

    if deterministic != input {
        return Err(CborCodecError::NonDeterministicCbor);
    }

    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|error| CborCodecError::SchemaViolation(error.to_string()))?;

    if let Some(identity) = &manifest.identity {
        if !identity.is_object() {
            return Err(CborCodecError::SchemaViolation(
                "identity must be an object".into(),
            ));
        }
    }

    manifest
        .validate()
        .map_err(|error| CborCodecError::ManifestPolicy(error.to_string()))?;

    Ok(manifest)
}

fn manifest_to_value(manifest: &Manifest, limits: CborLimits) -> Result<Value, CborCodecError> {
    manifest
        .validate()
        .map_err(|error| CborCodecError::ManifestPolicy(error.to_string()))?;

    if let Some(identity) = &manifest.identity {
        if !identity.is_object() {
            return Err(CborCodecError::SchemaViolation(
                "identity must be an object".into(),
            ));
        }
    }

    let mut value = serde_json::to_value(manifest)
        .map_err(|error| CborCodecError::SchemaViolation(error.to_string()))?;

    let root = value
        .as_object_mut()
        .ok_or_else(|| CborCodecError::SchemaViolation("manifest must be an object".into()))?;

    if manifest.identity.is_none() {
        root.remove("identity");
    }

    if manifest.expires_at.is_none() {
        root.remove("expires_at");
    }

    if manifest.operator.jurisdiction.is_none() {
        let operator = root
            .get_mut("operator")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| CborCodecError::SchemaViolation("operator must be an object".into()))?;
        operator.remove("jurisdiction");
    }

    validate_value_profile(&value, limits, 0)?;
    Ok(value)
}

fn validate_value_profile(
    value: &Value,
    limits: CborLimits,
    depth: usize,
) -> Result<(), CborCodecError> {
    if depth > limits.max_depth {
        return Err(CborCodecError::ResourceLimit("nesting depth"));
    }

    match value {
        Value::Null => Err(CborCodecError::UnsupportedCborType("null".into())),
        Value::Bool(_) => Ok(()),
        Value::Number(number) => validate_number(number),
        Value::String(text) => {
            if text.len() > limits.max_string_bytes {
                return Err(CborCodecError::ResourceLimit("text string bytes"));
            }
            Ok(())
        }
        Value::Array(items) => {
            if items.len() > limits.max_array_items {
                return Err(CborCodecError::ResourceLimit("array items"));
            }

            for item in items {
                validate_value_profile(item, limits, depth + 1)?;
            }

            Ok(())
        }
        Value::Object(entries) => {
            if entries.len() > limits.max_map_pairs {
                return Err(CborCodecError::ResourceLimit("map pairs"));
            }

            for (key, item) in entries {
                if key.len() > limits.max_string_bytes {
                    return Err(CborCodecError::ResourceLimit("map key bytes"));
                }
                validate_value_profile(item, limits, depth + 1)?;
            }

            Ok(())
        }
    }
}

fn validate_number(number: &Number) -> Result<(), CborCodecError> {
    if let Some(unsigned) = number.as_u64() {
        if unsigned <= MAX_SAFE_INTEGER {
            return Ok(());
        }
        return Err(CborCodecError::IntegerOutOfRange);
    }

    if let Some(signed) = number.as_i64() {
        if signed.unsigned_abs() <= MAX_SAFE_INTEGER {
            return Ok(());
        }
        return Err(CborCodecError::IntegerOutOfRange);
    }

    Err(CborCodecError::UnsupportedCborType(
        "floating-point number".into(),
    ))
}

fn decode_value(
    decoder: &mut Decoder<'_>,
    limits: CborLimits,
    depth: usize,
) -> Result<Value, CborCodecError> {
    if depth > limits.max_depth {
        return Err(CborCodecError::ResourceLimit("nesting depth"));
    }

    let data_type = decoder.datatype().map_err(malformed_decode_error)?;

    match data_type {
        Type::Bool => decoder
            .bool()
            .map(Value::Bool)
            .map_err(malformed_decode_error),
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            let value = decoder.u64().map_err(malformed_decode_error)?;

            if value > MAX_SAFE_INTEGER {
                return Err(CborCodecError::IntegerOutOfRange);
            }

            Ok(Value::Number(Number::from(value)))
        }
        Type::I8 | Type::I16 | Type::I32 | Type::I64 => {
            let value = decoder.i64().map_err(malformed_decode_error)?;

            if value.unsigned_abs() > MAX_SAFE_INTEGER {
                return Err(CborCodecError::IntegerOutOfRange);
            }

            Ok(Value::Number(Number::from(value)))
        }
        Type::Int => Err(CborCodecError::IntegerOutOfRange),
        Type::String => {
            let text = decoder.str().map_err(malformed_decode_error)?;

            if text.len() > limits.max_string_bytes {
                return Err(CborCodecError::ResourceLimit("text string bytes"));
            }

            Ok(Value::String(text.to_owned()))
        }
        Type::Array => decode_array(decoder, limits, depth),
        Type::Map => decode_map(decoder, limits, depth),
        Type::StringIndef => Err(CborCodecError::IndefiniteLength("text string")),
        Type::BytesIndef => Err(CborCodecError::IndefiniteLength("byte string")),
        Type::ArrayIndef => Err(CborCodecError::IndefiniteLength("array")),
        Type::MapIndef => Err(CborCodecError::IndefiniteLength("map")),
        other => Err(CborCodecError::UnsupportedCborType(format!("{other:?}"))),
    }
}

fn decode_array(
    decoder: &mut Decoder<'_>,
    limits: CborLimits,
    depth: usize,
) -> Result<Value, CborCodecError> {
    let length = decoder
        .array()
        .map_err(malformed_decode_error)?
        .ok_or(CborCodecError::IndefiniteLength("array"))?;
    let length =
        usize::try_from(length).map_err(|_| CborCodecError::ResourceLimit("array items"))?;

    if length > limits.max_array_items {
        return Err(CborCodecError::ResourceLimit("array items"));
    }

    let mut items = Vec::with_capacity(length);

    for _ in 0..length {
        items.push(decode_value(decoder, limits, depth + 1)?);
    }

    Ok(Value::Array(items))
}

fn decode_map(
    decoder: &mut Decoder<'_>,
    limits: CborLimits,
    depth: usize,
) -> Result<Value, CborCodecError> {
    let length = decoder
        .map()
        .map_err(malformed_decode_error)?
        .ok_or(CborCodecError::IndefiniteLength("map"))?;
    let length = usize::try_from(length).map_err(|_| CborCodecError::ResourceLimit("map pairs"))?;

    if length > limits.max_map_pairs {
        return Err(CborCodecError::ResourceLimit("map pairs"));
    }

    let mut entries = Map::new();
    let mut seen = BTreeSet::new();
    let mut previous_key_bytes: Option<Vec<u8>> = None;

    for _ in 0..length {
        let key_type = decoder.datatype().map_err(malformed_decode_error)?;

        if key_type == Type::StringIndef {
            return Err(CborCodecError::IndefiniteLength("map key"));
        }

        if key_type != Type::String {
            return Err(CborCodecError::UnsupportedCborType(
                "map key must be a text string".into(),
            ));
        }

        let key_start = decoder.position();
        let key = decoder.str().map_err(malformed_decode_error)?;
        let key_end = decoder.position();

        if key.len() > limits.max_string_bytes {
            return Err(CborCodecError::ResourceLimit("map key bytes"));
        }

        let key = key.to_owned();

        if !seen.insert(key.clone()) {
            return Err(CborCodecError::DuplicateKey(key));
        }

        let key_bytes = decoder.input()[key_start..key_end].to_vec();

        if let Some(previous) = &previous_key_bytes {
            if compare_encoded_keys(previous, &key_bytes) != std::cmp::Ordering::Less {
                return Err(CborCodecError::MapKeyOrder);
            }
        }

        previous_key_bytes = Some(key_bytes);
        let value = decode_value(decoder, limits, depth + 1)?;
        entries.insert(key, value);
    }

    Ok(Value::Object(entries))
}

fn encode_value_to_vec(value: &Value, limits: CborLimits) -> Result<Vec<u8>, CborCodecError> {
    validate_value_profile(value, limits, 0)?;

    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encode_value(value, &mut encoder, limits, 0)?;
    Ok(output)
}

fn encode_value<W: minicbor::encode::Write>(
    value: &Value,
    encoder: &mut Encoder<W>,
    limits: CborLimits,
    depth: usize,
) -> Result<(), CborCodecError>
where
    W::Error: fmt::Display,
{
    if depth > limits.max_depth {
        return Err(CborCodecError::ResourceLimit("nesting depth"));
    }

    match value {
        Value::Null => Err(CborCodecError::UnsupportedCborType("null".into())),
        Value::Bool(value) => {
            encoder.bool(*value).map_err(encode_error)?;
            Ok(())
        }
        Value::Number(number) => {
            validate_number(number)?;

            if let Some(unsigned) = number.as_u64() {
                encoder.u64(unsigned).map_err(encode_error)?;
                return Ok(());
            }

            if let Some(signed) = number.as_i64() {
                encoder.i64(signed).map_err(encode_error)?;
                return Ok(());
            }

            Err(CborCodecError::UnsupportedCborType(
                "floating-point number".into(),
            ))
        }
        Value::String(text) => {
            if text.len() > limits.max_string_bytes {
                return Err(CborCodecError::ResourceLimit("text string bytes"));
            }
            encoder.str(text).map_err(encode_error)?;
            Ok(())
        }
        Value::Array(items) => {
            if items.len() > limits.max_array_items {
                return Err(CborCodecError::ResourceLimit("array items"));
            }

            encoder.array(items.len() as u64).map_err(encode_error)?;

            for item in items {
                encode_value(item, encoder, limits, depth + 1)?;
            }

            Ok(())
        }
        Value::Object(entries) => {
            if entries.len() > limits.max_map_pairs {
                return Err(CborCodecError::ResourceLimit("map pairs"));
            }

            let mut ordered = Vec::with_capacity(entries.len());

            for (key, item) in entries {
                if key.len() > limits.max_string_bytes {
                    return Err(CborCodecError::ResourceLimit("map key bytes"));
                }

                ordered.push((encoded_text_key(key)?, key.as_str(), item));
            }

            ordered.sort_by(|left, right| compare_encoded_keys(&left.0, &right.0));

            encoder.map(ordered.len() as u64).map_err(encode_error)?;

            for (_, key, item) in ordered {
                encoder.str(key).map_err(encode_error)?;
                encode_value(item, encoder, limits, depth + 1)?;
            }

            Ok(())
        }
    }
}

fn encoded_text_key(key: &str) -> Result<Vec<u8>, CborCodecError> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded).str(key).map_err(encode_error)?;
    Ok(encoded)
}

fn compare_encoded_keys(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn malformed_decode_error(error: minicbor::decode::Error) -> CborCodecError {
    CborCodecError::MalformedCbor(error.to_string())
}

fn encode_error<E: fmt::Display>(error: minicbor::encode::Error<E>) -> CborCodecError {
    CborCodecError::EncodeFailure(error.to_string())
}
