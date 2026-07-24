use minicbor::Encoder;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tfws_core::{
    decode_manifest_cbor, encode_manifest_cbor, encode_manifest_cbor_with_limits, CborCodecError,
    CborLimits, Manifest,
};

const EXPECTED_CBOR_LENGTH: usize = 764;
const EXPECTED_CBOR_SHA256: &str =
    "80ab8301a0625193deb83fe065f73028464b1ceac61e8fc57b34c1d58358f0b5";

fn sample() -> Manifest {
    serde_json::from_str(include_str!("../../../test-vectors/manifest.valid.json"))
        .expect("valid embedded manifest")
}

fn sample_value() -> Value {
    let manifest = sample();
    let mut value = serde_json::to_value(manifest).expect("manifest JSON value");
    let root = value.as_object_mut().expect("manifest object");

    root.remove("identity");

    let operator = root
        .get_mut("operator")
        .and_then(Value::as_object_mut)
        .expect("operator object");

    if operator.get("jurisdiction") == Some(&Value::Null) {
        operator.remove("jurisdiction");
    }

    value
}

fn encode_test_value(value: &Value) -> Vec<u8> {
    fn encoded_key(key: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes).str(key).expect("encode test key");
        bytes
    }

    fn encode(value: &Value, encoder: &mut Encoder<&mut Vec<u8>>) {
        match value {
            Value::Null => panic!("test helper does not encode null"),
            Value::Bool(value) => {
                encoder.bool(*value).expect("encode bool");
            }
            Value::Number(number) => {
                if let Some(value) = number.as_u64() {
                    encoder.u64(value).expect("encode unsigned integer");
                } else if let Some(value) = number.as_i64() {
                    encoder.i64(value).expect("encode signed integer");
                } else {
                    panic!("test helper does not encode floating-point numbers");
                }
            }
            Value::String(value) => {
                encoder.str(value).expect("encode text");
            }
            Value::Array(items) => {
                encoder
                    .array(items.len() as u64)
                    .expect("encode array length");

                for item in items {
                    encode(item, encoder);
                }
            }
            Value::Object(entries) => {
                let mut ordered = entries
                    .iter()
                    .map(|(key, value)| (encoded_key(key), key.as_str(), value))
                    .collect::<Vec<_>>();

                ordered.sort_by(|left, right| {
                    left.0
                        .len()
                        .cmp(&right.0.len())
                        .then_with(|| left.0.cmp(&right.0))
                });

                encoder
                    .map(ordered.len() as u64)
                    .expect("encode map length");

                for (_, key, value) in ordered {
                    encoder.str(key).expect("encode map key");
                    encode(value, encoder);
                }
            }
        }
    }

    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encode(value, &mut encoder);
    output
}

#[test]
fn deterministic_manifest_vector_is_byte_exact() {
    let first = encode_manifest_cbor(&sample()).expect("first encoding");
    let second = encode_manifest_cbor(&sample()).expect("second encoding");

    assert_eq!(first, second);
    assert_eq!(first.len(), EXPECTED_CBOR_LENGTH);
    assert_eq!(
        format!("{:x}", Sha256::digest(&first)),
        EXPECTED_CBOR_SHA256
    );
}

#[test]
fn deterministic_round_trip_preserves_manifest() {
    let original = sample();
    let encoded = encode_manifest_cbor(&original).expect("encoding");
    let decoded = decode_manifest_cbor(&encoded, CborLimits::default()).expect("decoding");

    assert_eq!(
        serde_json::to_value(decoded).expect("decoded JSON"),
        serde_json::to_value(original).expect("original JSON")
    );
}

#[test]
fn duplicate_map_key_is_rejected_before_schema_validation() {
    let mut input = Vec::new();
    let mut encoder = Encoder::new(&mut input);

    encoder
        .map(2)
        .expect("map")
        .str("a")
        .expect("key")
        .u8(1)
        .expect("value")
        .str("a")
        .expect("duplicate key")
        .u8(2)
        .expect("value");

    assert!(matches!(
        decode_manifest_cbor(&input, CborLimits::default()),
        Err(CborCodecError::DuplicateKey(key)) if key == "a"
    ));
}

#[test]
fn out_of_order_map_keys_are_rejected() {
    let mut input = Vec::new();
    let mut encoder = Encoder::new(&mut input);

    encoder
        .map(2)
        .expect("map")
        .str("bb")
        .expect("first key")
        .u8(1)
        .expect("first value")
        .str("a")
        .expect("second key")
        .u8(2)
        .expect("second value");

    let error = decode_manifest_cbor(&input, CborLimits::default())
        .expect_err("out-of-order keys must fail");
    assert_eq!(error, CborCodecError::MapKeyOrder);
}

#[test]
fn non_preferred_map_length_is_rejected() {
    let input = [0xb8, 0x00];

    let error = decode_manifest_cbor(&input, CborLimits::default())
        .expect_err("non-preferred map length must fail");
    assert_eq!(error, CborCodecError::NonDeterministicCbor);
}

#[test]
fn non_preferred_integer_is_rejected() {
    let input = [0xa1, 0x61, b'a', 0x18, 0x00];

    let error = decode_manifest_cbor(&input, CborLimits::default())
        .expect_err("non-preferred integer must fail");
    assert_eq!(error, CborCodecError::NonDeterministicCbor);
}

#[test]
fn indefinite_length_items_are_rejected() {
    let array_error = decode_manifest_cbor(&[0x9f, 0xff], CborLimits::default())
        .expect_err("indefinite array must fail");
    assert_eq!(array_error, CborCodecError::IndefiniteLength("array"));

    let map_error = decode_manifest_cbor(&[0xbf, 0xff], CborLimits::default())
        .expect_err("indefinite map must fail");
    assert_eq!(map_error, CborCodecError::IndefiniteLength("map"));
}

#[test]
fn unsupported_manifest_types_are_rejected() {
    let float = [0xfa, 0x00, 0x00, 0x00, 0x00];
    let byte_string = [0x41, 0x00];
    let tagged = [0xc0, 0x00];
    let null = [0xf6];

    for input in [&float[..], &byte_string[..], &tagged[..], &null[..]] {
        assert!(matches!(
            decode_manifest_cbor(input, CborLimits::default()),
            Err(CborCodecError::UnsupportedCborType(_))
        ));
    }
}

#[test]
fn trailing_data_is_rejected() {
    let error = decode_manifest_cbor(&[0xa0, 0x00], CborLimits::default())
        .expect_err("trailing data must fail");
    assert_eq!(error, CborCodecError::TrailingData);
}

#[test]
fn input_limit_is_enforced_before_parsing() {
    let limits = CborLimits {
        max_manifest_bytes: 1,
        ..CborLimits::default()
    };

    let error = decode_manifest_cbor(&[0xa0, 0x00], limits)
        .expect_err("input limit must fail before parsing");
    assert_eq!(error, CborCodecError::ResourceLimit("manifest bytes"));
}

#[test]
fn null_identity_is_rejected_on_encode() {
    let mut manifest = sample();
    manifest.identity = Some(Value::Null);

    assert!(matches!(
        encode_manifest_cbor(&manifest),
        Err(CborCodecError::SchemaViolation(message))
            if message == "identity must be an object"
    ));
}

#[test]
fn explicit_encode_limits_are_enforced() {
    let limits = CborLimits {
        max_string_bytes: 20,
        ..CborLimits::default()
    };

    assert_eq!(
        encode_manifest_cbor_with_limits(&sample(), limits),
        Err(CborCodecError::ResourceLimit("text string bytes"))
    );
}

#[test]
fn invalid_utf8_is_rejected() {
    let input = [0xa1, 0x61, b'a', 0x61, 0xff];

    assert!(matches!(
        decode_manifest_cbor(&input, CborLimits::default()),
        Err(CborCodecError::MalformedCbor(_))
    ));
}

#[test]
fn truncated_input_sweep_rejects_every_prefix() {
    let encoded = encode_manifest_cbor(&sample()).expect("encoding");

    for end in 0..encoded.len() {
        assert!(
            decode_manifest_cbor(&encoded[..end], CborLimits::default()).is_err(),
            "truncated prefix of length {end} was accepted"
        );
    }
}

#[test]
fn integer_out_of_range_is_rejected() {
    let mut input = Vec::new();
    let mut encoder = Encoder::new(&mut input);

    encoder
        .map(1)
        .expect("map")
        .str("a")
        .expect("key")
        .u64(9_007_199_254_740_992)
        .expect("out-of-range integer");

    let error = decode_manifest_cbor(&input, CborLimits::default())
        .expect_err("out-of-range integer must fail");
    assert_eq!(error, CborCodecError::IntegerOutOfRange);
}

#[test]
fn nesting_limit_is_enforced() {
    let input = [0x81, 0x81, 0x81, 0xf5];
    let limits = CborLimits {
        max_depth: 2,
        ..CborLimits::default()
    };

    let error = decode_manifest_cbor(&input, limits).expect_err("excessive nesting must fail");
    assert_eq!(error, CborCodecError::ResourceLimit("nesting depth"));
}

#[test]
fn map_pair_limit_is_enforced() {
    let mut input = Vec::new();
    let mut encoder = Encoder::new(&mut input);

    encoder
        .map(2)
        .expect("map")
        .str("a")
        .expect("first key")
        .bool(true)
        .expect("first value")
        .str("b")
        .expect("second key")
        .bool(false)
        .expect("second value");

    let limits = CborLimits {
        max_map_pairs: 1,
        ..CborLimits::default()
    };

    let error = decode_manifest_cbor(&input, limits).expect_err("map pair limit must fail");
    assert_eq!(error, CborCodecError::ResourceLimit("map pairs"));
}

#[test]
fn array_item_limit_is_enforced() {
    let mut input = Vec::new();
    let mut encoder = Encoder::new(&mut input);

    encoder
        .array(2)
        .expect("array")
        .bool(true)
        .expect("first item")
        .bool(false)
        .expect("second item");

    let limits = CborLimits {
        max_array_items: 1,
        ..CborLimits::default()
    };

    let error = decode_manifest_cbor(&input, limits).expect_err("array item limit must fail");
    assert_eq!(error, CborCodecError::ResourceLimit("array items"));
}

#[test]
fn decoded_string_limit_is_enforced() {
    let mut input = Vec::new();
    let mut encoder = Encoder::new(&mut input);

    encoder
        .map(1)
        .expect("map")
        .str("a")
        .expect("key")
        .str("four")
        .expect("value");

    let limits = CborLimits {
        max_string_bytes: 3,
        ..CborLimits::default()
    };

    let error = decode_manifest_cbor(&input, limits).expect_err("decoded string limit must fail");
    assert_eq!(error, CborCodecError::ResourceLimit("text string bytes"));
}

#[test]
fn nested_identity_round_trip_is_preserved() {
    let mut manifest = sample();
    manifest.identity = Some(json!({
        "active": true,
        "assurance": {
            "level": 2,
            "methods": ["domain", "registry"]
        },
        "issuer": "https://issuer.example",
        "revision": -1
    }));

    let encoded = encode_manifest_cbor(&manifest).expect("identity encoding");
    let decoded = decode_manifest_cbor(&encoded, CborLimits::default()).expect("identity decoding");

    assert_eq!(decoded.identity, manifest.identity);
}

#[test]
fn missing_required_field_is_rejected() {
    let mut value = sample_value();
    value
        .as_object_mut()
        .expect("manifest object")
        .remove("subject");

    let input = encode_test_value(&value);

    assert!(matches!(
        decode_manifest_cbor(&input, CborLimits::default()),
        Err(CborCodecError::SchemaViolation(_))
    ));
}

#[test]
fn unknown_manifest_field_is_rejected() {
    let mut value = sample_value();
    value
        .as_object_mut()
        .expect("manifest object")
        .insert("unexpected".into(), Value::Bool(true));

    let input = encode_test_value(&value);

    assert!(matches!(
        decode_manifest_cbor(&input, CborLimits::default()),
        Err(CborCodecError::SchemaViolation(_))
    ));
}

#[test]
fn map_key_limit_is_enforced_before_allocation() {
    let mut input = Vec::new();
    let mut encoder = Encoder::new(&mut input);

    encoder
        .map(1)
        .expect("map")
        .str("four")
        .expect("oversized key")
        .bool(true)
        .expect("value");

    let limits = CborLimits {
        max_string_bytes: 3,
        ..CborLimits::default()
    };

    let error = decode_manifest_cbor(&input, limits).expect_err("map key limit must fail");
    assert_eq!(error, CborCodecError::ResourceLimit("map key bytes"));
}

#[test]
fn non_text_map_key_is_rejected() {
    let mut input = Vec::new();
    let mut encoder = Encoder::new(&mut input);

    encoder
        .map(1)
        .expect("map")
        .u8(1)
        .expect("integer key")
        .bool(true)
        .expect("value");

    assert!(matches!(
        decode_manifest_cbor(&input, CborLimits::default()),
        Err(CborCodecError::UnsupportedCborType(message))
            if message == "map key must be a text string"
    ));
}

#[test]
fn indefinite_text_and_byte_strings_are_rejected() {
    let text_error = decode_manifest_cbor(&[0x7f, 0xff], CborLimits::default())
        .expect_err("indefinite text must fail");
    assert_eq!(text_error, CborCodecError::IndefiniteLength("text string"));

    let bytes_error = decode_manifest_cbor(&[0x5f, 0xff], CborLimits::default())
        .expect_err("indefinite bytes must fail");
    assert_eq!(bytes_error, CborCodecError::IndefiniteLength("byte string"));
}

#[test]
fn safe_integer_boundaries_round_trip() {
    let mut manifest = sample();
    manifest.identity = Some(json!({
        "maximum": 9_007_199_254_740_991_u64,
        "minimum": -9_007_199_254_740_991_i64
    }));

    let encoded = encode_manifest_cbor(&manifest).expect("boundary encoding");
    let decoded = decode_manifest_cbor(&encoded, CborLimits::default()).expect("boundary decoding");

    assert_eq!(decoded.identity, manifest.identity);
}

#[test]
fn non_preferred_text_length_is_rejected() {
    let input = [0xa1, 0x78, 0x01, b'a', 0x00];

    let error = decode_manifest_cbor(&input, CborLimits::default())
        .expect_err("non-preferred text length must fail");
    assert_eq!(error, CborCodecError::NonDeterministicCbor);
}

#[test]
fn negative_integer_out_of_range_is_rejected() {
    let mut input = Vec::new();
    let mut encoder = Encoder::new(&mut input);

    encoder
        .map(1)
        .expect("map")
        .str("a")
        .expect("key")
        .i64(-9_007_199_254_740_992)
        .expect("negative out-of-range integer");

    let error = decode_manifest_cbor(&input, CborLimits::default())
        .expect_err("negative out-of-range integer must fail");
    assert_eq!(error, CborCodecError::IntegerOutOfRange);
}

#[test]
fn encoded_manifest_size_limit_is_enforced() {
    let encoded = encode_manifest_cbor(&sample()).expect("baseline encoding");
    let limits = CborLimits {
        max_manifest_bytes: encoded.len() - 1,
        ..CborLimits::default()
    };

    assert_eq!(
        encode_manifest_cbor_with_limits(&sample(), limits),
        Err(CborCodecError::ResourceLimit("manifest bytes"))
    );
}

#[test]
fn stable_error_categories_match_the_profile() {
    assert_eq!(
        CborCodecError::DuplicateKey("a".into()).category(),
        "non_deterministic_cbor"
    );
    assert_eq!(
        CborCodecError::UnsupportedCborType("Bytes".into()).category(),
        "unsupported_cbor_type"
    );
    assert_eq!(
        CborCodecError::ResourceLimit("array items").category(),
        "resource_limit"
    );
}
