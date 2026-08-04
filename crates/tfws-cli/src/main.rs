#![forbid(unsafe_code)]

use std::{env, fs, process::ExitCode};
use tfws_core::{
    decode_manifest_cbor, verify_manifest_cose, CborLimits, CoseAlgorithm, CoseCryptoError,
    CoseVerifier, KeyDescriptor, Manifest,
};

const USAGE: &str = "usage: tfws-cli validate --input-format <json|cbor|cose> [--output-format <human|json>] <path>";
const EXPECTED_ED_SHA256: &str = "7fe64728f1a7bb8c6c103f49c0e2ed0e999678229256c7aab813634cc6c85ba9";
const EXPECTED_ML_SHA256: &str = "85acf51bf7260bc7009f1b3d6b8a4f6d0442bf21ea91a86fe7cbb282edb317cb";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputFormat {
    Json,
    Cbor,
    Cose,
}

impl InputFormat {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "json" => Ok(Self::Json),
            "cbor" => Ok(Self::Cbor),
            "cose" => Ok(Self::Cose),
            _ => Err(CliError::new(
                "unsupported_input_format",
                "input format must be exactly json, cbor, or cose",
            )),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Cbor => "cbor",
            Self::Cose => "cose",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Human,
    Json,
}

impl OutputFormat {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "human" => Ok(Self::Human),
            "json" => Ok(Self::Json),
            _ => Err(CliError::new(
                "invalid_arguments",
                "output format must be exactly human or json",
            )),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Config {
    input_format: InputFormat,
    output_format: OutputFormat,
    path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliError {
    code: &'static str,
    message: &'static str,
}

impl CliError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

#[derive(Default)]
struct ConformanceFixtureVerifier;

impl CoseVerifier for ConformanceFixtureVerifier {
    fn verify(
        &self,
        algorithm: CoseAlgorithm,
        descriptor: &KeyDescriptor,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CoseCryptoError> {
        validate_fixture_binding(algorithm, descriptor)?;
        if signature != fixture_signature(algorithm, message) {
            return Err(CoseCryptoError::SignatureInvalid);
        }
        Ok(())
    }
}

fn validate_fixture_binding(
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

fn fixture_signature(algorithm: CoseAlgorithm, message: &[u8]) -> Vec<u8> {
    let mut fixture_input = Vec::with_capacity(message.len() + 1);
    fixture_input.push(match algorithm {
        CoseAlgorithm::Ed25519 => 0x13,
        CoseAlgorithm::MlDsa65 => 0x31,
    });
    fixture_input.extend_from_slice(message);
    let digest = sha256(&fixture_input);
    digest
        .iter()
        .copied()
        .cycle()
        .take(algorithm.expected_signature_len())
        .collect()
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL;
    for block in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sigma0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut digest = [0_u8; 32];
    for (chunk, value) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    digest
}

fn parse_args<I>(args: I) -> Result<Config, CliError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    if args.next().as_deref() != Some("validate") {
        return Err(CliError::new("invalid_arguments", USAGE));
    }
    let mut input_format = None;
    let mut output_format = OutputFormat::Human;
    let mut output_seen = false;
    let mut path = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--input-format" => {
                if input_format.is_some() {
                    return Err(CliError::new(
                        "invalid_arguments",
                        "input format must be provided exactly once",
                    ));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::new(
                        "invalid_arguments",
                        "input format value is required",
                    ));
                };
                input_format = Some(InputFormat::parse(&value)?);
            }
            "--output-format" => {
                if output_seen {
                    return Err(CliError::new(
                        "invalid_arguments",
                        "output format must be provided at most once",
                    ));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::new(
                        "invalid_arguments",
                        "output format value is required",
                    ));
                };
                output_format = OutputFormat::parse(&value)?;
                output_seen = true;
            }
            value if value.starts_with('-') => {
                return Err(CliError::new(
                    "invalid_arguments",
                    "unknown command-line option",
                ));
            }
            value => {
                if path.replace(value.to_owned()).is_some() {
                    return Err(CliError::new(
                        "invalid_arguments",
                        "exactly one input path is required",
                    ));
                }
            }
        }
    }
    let input_format = input_format.ok_or_else(|| {
        CliError::new(
            "invalid_arguments",
            "explicit --input-format json|cbor|cose is required",
        )
    })?;
    let path = path.ok_or_else(|| CliError::new("invalid_arguments", "input path is required"))?;
    Ok(Config {
        input_format,
        output_format,
        path,
    })
}

fn output_format_hint(args: &[String]) -> OutputFormat {
    args.windows(2)
        .find_map(|pair| {
            (pair[0] == "--output-format" && pair[1] == "json").then_some(OutputFormat::Json)
        })
        .unwrap_or(OutputFormat::Human)
}

fn category_message(category: &str) -> &'static str {
    match category {
        "malformed_cbor" => "input is not well-formed CBOR",
        "non_deterministic_cbor" => "input is not deterministic CBOR",
        "unsupported_cbor_type" => "input uses an unsupported CBOR type",
        "resource_limit" => "input exceeds a CBOR or COSE resource limit",
        "manifest_policy_invalid" => "manifest violates the TFWS profile",
        "invalid_cose_structure" => "input has an invalid COSE structure",
        "unsupported_header" => "input contains an unsupported COSE header",
        "invalid_content_type" => "input has an invalid COSE content type",
        "invalid_type" => "input has an invalid COSE type",
        "invalid_algorithm" => "input violates the hybrid algorithm profile",
        "invalid_kid" => "input has an invalid key identifier",
        "key_binding_mismatch" => "input has an invalid public-key binding",
        "signature_invalid" => "one or more conformance signatures are invalid",
        _ => "input was rejected",
    }
}

fn validate_bytes(input_format: InputFormat, bytes: &[u8]) -> Result<Manifest, CliError> {
    match input_format {
        InputFormat::Json => {
            let manifest: Manifest = serde_json::from_slice(bytes)
                .map_err(|_| CliError::new("invalid_json", "input is not valid manifest JSON"))?;
            manifest.validate().map_err(|_| {
                CliError::new(
                    "manifest_policy_invalid",
                    "manifest violates the TFWS profile",
                )
            })?;
            Ok(manifest)
        }
        InputFormat::Cbor => decode_manifest_cbor(bytes, CborLimits::default()).map_err(|error| {
            let category = error.category();
            CliError::new(category, category_message(category))
        }),
        InputFormat::Cose => {
            let verifier = ConformanceFixtureVerifier;
            verify_manifest_cose(bytes, &verifier).map_err(|error| {
                let category = error.category();
                CliError::new(category, category_message(category))
            })
        }
    }
}

fn format_success(config: &Config) -> String {
    match config.output_format {
        OutputFormat::Human => "valid".to_owned(),
        OutputFormat::Json => serde_json::json!({
            "input_format": config.input_format.name(),
            "valid": true
        })
        .to_string(),
    }
}

fn format_error(error: &CliError, output_format: OutputFormat) -> String {
    match output_format {
        OutputFormat::Human => format!("error[{}]: {}", error.code, error.message),
        OutputFormat::Json => serde_json::json!({
            "error": {
                "code": error.code,
                "message": error.message
            },
            "valid": false
        })
        .to_string(),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let error_output_format = output_format_hint(&args);
    let config = match parse_args(args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{}", format_error(&error, error_output_format));
            return ExitCode::from(2);
        }
    };
    let bytes = match fs::read(&config.path) {
        Ok(bytes) => bytes,
        Err(_) => {
            let error = CliError::new("input_read_failed", "unable to read input");
            eprintln!("{}", format_error(&error, config.output_format));
            return ExitCode::from(1);
        }
    };
    match validate_bytes(config.input_format, &bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("{}", format_error(&error, config.output_format));
            return ExitCode::from(1);
        }
    };
    println!("{}", format_success(&config));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const CORPUS: &str = include_str!(
        "../../../test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.json"
    );

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
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

    fn corpus() -> Value {
        serde_json::from_str(CORPUS).expect("valid issue 7 corpus")
    }

    #[test]
    fn local_sha256_matches_the_standard_known_answer() {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn explicit_format_is_required_and_detection_is_forbidden() {
        let missing = parse_args(["validate", "manifest.json"].map(str::to_owned))
            .expect_err("format must be explicit");
        assert_eq!(missing.code, "invalid_arguments");

        let unknown =
            parse_args(["validate", "--input-format", "auto", "manifest.json"].map(str::to_owned))
                .expect_err("automatic detection must be rejected");
        assert_eq!(unknown.code, "unsupported_input_format");
    }

    #[test]
    fn positive_json_cbor_and_cose_inputs_validate() {
        let corpus = corpus();
        let positive = &corpus["positive"];
        let json = serde_json::to_vec(&positive["manifest"]).expect("manifest JSON");
        let cbor = decode_hex(positive["manifest_cbor_hex"].as_str().expect("CBOR hex"));
        let cose = decode_hex(positive["cose_hex"].as_str().expect("COSE hex"));

        validate_bytes(InputFormat::Json, &json).expect("JSON compatibility");
        validate_bytes(InputFormat::Cbor, &cbor).expect("CBOR interoperability");
        validate_bytes(InputFormat::Cose, &cose).expect("COSE interoperability");
    }

    #[test]
    fn every_negative_vector_matches_the_rust_category() {
        let corpus = corpus();
        let cases = corpus["negative"].as_array().expect("negative cases");
        assert_eq!(cases.len(), 18);
        for case in cases {
            let format = match case["input_type"].as_str().expect("input type") {
                "manifest_cbor" => InputFormat::Cbor,
                "cose" => InputFormat::Cose,
                other => panic!("unknown input type: {other}"),
            };
            let bytes = decode_hex(case["bytes_hex"].as_str().expect("bytes hex"));
            let error = validate_bytes(format, &bytes).expect_err("negative must fail");
            assert_eq!(
                error.code,
                case["expected_category"].as_str().expect("category"),
                "{}",
                case["id"].as_str().expect("id")
            );
        }
    }

    #[test]
    fn mismatched_formats_fail_closed() {
        let corpus = corpus();
        let positive = &corpus["positive"];
        let cbor = decode_hex(positive["manifest_cbor_hex"].as_str().expect("CBOR hex"));
        let json = serde_json::to_vec(&positive["manifest"]).expect("manifest JSON");
        assert_eq!(
            validate_bytes(InputFormat::Json, &cbor)
                .expect_err("CBOR must not downgrade to JSON")
                .code,
            "invalid_json"
        );
        assert_eq!(
            validate_bytes(InputFormat::Cbor, &json)
                .expect_err("JSON must not downgrade to CBOR")
                .code,
            "malformed_cbor"
        );
    }

    #[test]
    fn human_and_machine_errors_are_stable() {
        let error = CliError::new("invalid_cose_structure", "deterministic message");
        assert_eq!(
            format_error(&error, OutputFormat::Human),
            "error[invalid_cose_structure]: deterministic message"
        );
        let machine: Value =
            serde_json::from_str(&format_error(&error, OutputFormat::Json)).expect("JSON error");
        assert_eq!(machine["valid"], false);
        assert_eq!(machine["error"]["code"], "invalid_cose_structure");
        assert_eq!(machine["error"]["message"], "deterministic message");

        let arguments = ["validate", "--output-format", "json"]
            .map(str::to_owned)
            .to_vec();
        let parse_error = parse_args(arguments.clone()).expect_err("input is missing");
        let parse_machine: Value =
            serde_json::from_str(&format_error(&parse_error, output_format_hint(&arguments)))
                .expect("argument error is JSON");
        assert_eq!(parse_machine["valid"], false);
        assert_eq!(parse_machine["error"]["code"], "invalid_arguments");
    }
}
