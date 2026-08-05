#![forbid(unsafe_code)]

use tfws_core::{decode_manifest_cbor, CborLimits, Manifest};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn validate_manifest(json: &str) -> bool {
    match serde_json::from_str::<Manifest>(json) {
        Ok(manifest) => manifest.validate().is_ok(),
        Err(_) => false,
    }
}

/// Validate only an explicitly selected deterministic CBOR manifest.
///
/// The returned JSON string is a stable machine-readable boundary. Detailed
/// parser diagnostics are deliberately not exposed.
#[wasm_bindgen]
pub fn validate_manifest_cbor(input: &[u8]) -> String {
    match decode_manifest_cbor(input, CborLimits::default()) {
        Ok(_) => serde_json::json!({
            "format": "cbor",
            "valid": true
        })
        .to_string(),
        Err(error) => {
            let code = error.category();
            serde_json::json!({
                "error": {
                    "code": code,
                    "message": category_message(code)
                },
                "format": "cbor",
                "valid": false
            })
            .to_string()
        }
    }
}

fn category_message(category: &str) -> &'static str {
    match category {
        "malformed_cbor" => "input is not well-formed CBOR",
        "non_deterministic_cbor" => "input is not deterministic CBOR",
        "unsupported_cbor_type" => "input uses an unsupported CBOR type",
        "resource_limit" => "input exceeds a CBOR resource limit",
        "manifest_policy_invalid" => "manifest violates the TFWS profile",
        _ => "input was rejected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const CORPUS: &str = include_str!(
        "../../../test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.json"
    );

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let nibble = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid lowercase hex"),
                };
                (nibble(pair[0]) << 4) | nibble(pair[1])
            })
            .collect()
    }

    fn result(input: &[u8]) -> Value {
        serde_json::from_str(&validate_manifest_cbor(input)).expect("valid diagnostic JSON")
    }

    #[test]
    fn committed_cbor_vector_executes_the_core_decoder() {
        let corpus: Value = serde_json::from_str(CORPUS).expect("valid issue 7 corpus");
        let input = decode_hex(
            corpus["positive"]["manifest_cbor_hex"]
                .as_str()
                .expect("CBOR hex"),
        );
        assert_eq!(result(&input)["valid"], true);
        assert_eq!(result(&input)["format"], "cbor");
    }

    #[test]
    fn malformed_cbor_fails_closed_with_a_stable_category() {
        let diagnostic = result(&[0xa1]);
        assert_eq!(diagnostic["valid"], false);
        assert_eq!(diagnostic["error"]["code"], "malformed_cbor");
        assert_eq!(diagnostic["format"], "cbor");
    }

    #[test]
    fn json_is_not_downgraded_through_the_cbor_export() {
        let diagnostic = result(br#"{"tfws_version":"3.0"}"#);
        assert_eq!(diagnostic["valid"], false);
        assert_eq!(diagnostic["error"]["code"], "malformed_cbor");
    }
}
