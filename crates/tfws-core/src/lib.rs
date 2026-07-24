#![forbid(unsafe_code)]

pub mod cbor;
pub mod cose;

pub use cbor::{
    decode_manifest_cbor, encode_manifest_cbor, encode_manifest_cbor_with_limits, CborCodecError,
    CborLimits,
};
pub use cose::{
    sign_manifest_cose, sign_manifest_cose_with_limits, verify_manifest_cose,
    verify_manifest_cose_with_limits, CoseAlgorithm, CoseCryptoError, CoseEnvelopeError,
    CoseLimits, CoseSigner, CoseVerifier, COSE_CONTENT_TYPE, COSE_SIGN_TAG, COSE_TYPE,
    ED25519_COSE_ALGORITHM, ED25519_SIGNATURE_BYTES, ML_DSA_65_COSE_ALGORITHM,
    ML_DSA_65_SIGNATURE_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;
use thiserror::Error;
use url::Url;

pub const BASELINE_POLICY: &str = "tfws.hybrid.baseline.v1";
pub const BASELINE_ALGORITHMS: [&str; 2] = ["ed25519", "ml-dsa-65"];
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("unsupported mandatory capability: {0}")]
    UnsupportedCapability(String),
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    pub name: String,
    pub jurisdiction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignaturePolicy {
    pub policy_id: String,
    pub required_algorithms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub required: Vec<String>,
    pub optional: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub uri: String,
    pub media_type: String,
    pub sha512: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyDescriptor {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_uri: String,
    pub public_key_sha256: String,
    pub status: String,
    pub usage: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub tfws_version: String,
    pub subject: String,
    pub environment: String,
    pub operator: Operator,
    pub key_epoch: u64,
    pub keys: Vec<KeyDescriptor>,
    pub signature_policy: SignaturePolicy,
    pub capabilities: Capabilities,
    #[serde(default)]
    pub identity: Option<serde_json::Value>,
    pub artifacts: Vec<Artifact>,
    pub updated_at: String,
    pub expires_at: Option<String>,
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_json_number_profile(value: &serde_json::Value) -> Result<(), Error> {
    match value {
        serde_json::Value::Number(number) => {
            let valid = number
                .as_i64()
                .map(|integer| integer.unsigned_abs() <= MAX_SAFE_INTEGER)
                .or_else(|| number.as_u64().map(|integer| integer <= MAX_SAFE_INTEGER))
                .unwrap_or(false);
            if !valid {
                return Err(Error::InvalidManifest(
                    "floating-point or out-of-range JSON number".into(),
                ));
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                validate_json_number_profile(item)?;
            }
        }
        serde_json::Value::Object(entries) => {
            for item in entries.values() {
                validate_json_number_profile(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl Manifest {
    pub fn validate(&self) -> Result<(), Error> {
        if self.tfws_version != "3.0" {
            return Err(Error::InvalidManifest("unsupported version".into()));
        }
        let subject =
            Url::parse(&self.subject).map_err(|error| Error::InvalidManifest(error.to_string()))?;
        if subject.scheme() != "https"
            || subject.cannot_be_a_base()
            || subject.path() != "/"
            || subject.query().is_some()
            || subject.fragment().is_some()
            || !subject.username().is_empty()
            || subject.password().is_some()
        {
            return Err(Error::InvalidManifest(
                "subject must be an HTTPS origin".into(),
            ));
        }
        if !matches!(
            self.environment.as_str(),
            "development" | "staging" | "production"
        ) {
            return Err(Error::InvalidManifest("invalid environment".into()));
        }
        if self.key_epoch == 0 || self.key_epoch > MAX_SAFE_INTEGER {
            return Err(Error::InvalidManifest("invalid key epoch".into()));
        }
        if self.operator.name.trim().is_empty() {
            return Err(Error::InvalidManifest("operator name is required".into()));
        }
        if let Some(jurisdiction) = &self.operator.jurisdiction {
            if jurisdiction.len() != 2
                || !jurisdiction.bytes().all(|byte| byte.is_ascii_uppercase())
            {
                return Err(Error::InvalidManifest("invalid jurisdiction".into()));
            }
        }
        if self.keys.is_empty() && self.environment != "development" {
            return Err(Error::InvalidManifest(
                "staging and production manifests require bound keys".into(),
            ));
        }
        if !self.keys.is_empty() {
            if self.keys.len() != BASELINE_ALGORITHMS.len() {
                return Err(Error::InvalidManifest(
                    "hybrid baseline requires two key descriptors".into(),
                ));
            }
            let mut seen = BTreeSet::new();
            for key in &self.keys {
                if !BASELINE_ALGORITHMS.contains(&key.algorithm.as_str())
                    || !seen.insert(key.algorithm.as_str())
                    || key.key_id.trim().is_empty()
                    || key.status != "active"
                    || key.usage.as_slice() != ["release"]
                    || !is_lower_hex(&key.public_key_sha256, 64)
                    || key.public_key_uri != format!("/.well-known/keys/{}.pem", key.algorithm)
                {
                    return Err(Error::InvalidManifest(
                        "invalid baseline key descriptor".into(),
                    ));
                }
            }
        }
        let required: Vec<&str> = self
            .signature_policy
            .required_algorithms
            .iter()
            .map(String::as_str)
            .collect();
        if self.signature_policy.policy_id != BASELINE_POLICY
            || required.as_slice() != BASELINE_ALGORITHMS
        {
            return Err(Error::InvalidManifest("hybrid baseline downgrade".into()));
        }
        let known: BTreeSet<&str> = ["core.v1", "identity.v1", "recovery.v1", "transparency.v1"]
            .into_iter()
            .collect();
        let required_set: BTreeSet<&str> = self
            .capabilities
            .required
            .iter()
            .map(String::as_str)
            .collect();
        if required_set.len() != self.capabilities.required.len() {
            return Err(Error::InvalidManifest(
                "duplicate mandatory capability".into(),
            ));
        }
        let optional_set: BTreeSet<&str> = self
            .capabilities
            .optional
            .iter()
            .map(String::as_str)
            .collect();
        if optional_set.len() != self.capabilities.optional.len()
            || !required_set.is_disjoint(&optional_set)
        {
            return Err(Error::InvalidManifest(
                "duplicate or conflicting optional capability".into(),
            ));
        }
        for capability in &self.capabilities.required {
            if !known.contains(capability.as_str()) {
                return Err(Error::UnsupportedCapability(capability.clone()));
            }
        }
        for artifact in &self.artifacts {
            Url::parse(&artifact.uri)
                .map_err(|error| Error::InvalidManifest(format!("artifact URI: {error}")))?;
            if artifact.media_type.trim().is_empty() || !is_lower_hex(&artifact.sha512, 128) {
                return Err(Error::InvalidManifest("invalid artifact".into()));
            }
        }
        validate_json_number_profile(
            &serde_json::to_value(self)
                .map_err(|error| Error::Canonicalization(error.to_string()))?,
        )?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|error| Error::Canonicalization(error.to_string()))
    }

    pub fn payload_sha512(&self) -> Result<String, Error> {
        let mut hasher = Sha512::new();
        hasher.update(self.canonical_bytes()?);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

pub fn signature_message(
    subject: &str,
    digest: &str,
    created: &str,
    key_epoch: u64,
) -> Result<Vec<u8>, Error> {
    if [subject, created, digest]
        .iter()
        .any(|value| value.contains('\n') || value.contains('\r'))
    {
        return Err(Error::InvalidManifest(
            "newline in signature metadata".into(),
        ));
    }
    if !is_lower_hex(digest, 128) || key_epoch == 0 || key_epoch > MAX_SAFE_INTEGER {
        return Err(Error::InvalidManifest("invalid signature metadata".into()));
    }
    Ok(format!(
        "TFWS3-SIGNATURE-V1\nsubject={subject}\nmedia_type=application/tfws+json\npayload_sha512={digest}\ncreated={created}\nkey_epoch={key_epoch}\npolicy={BASELINE_POLICY}\n"
    )
    .into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        serde_json::from_str(include_str!("../../../test-vectors/manifest.valid.json"))
            .expect("valid embedded test vector")
    }

    #[test]
    fn valid_manifest() {
        sample().validate().expect("manifest must validate");
    }

    #[test]
    fn downgrade_rejected() {
        let mut manifest = sample();
        manifest.signature_policy.required_algorithms = vec!["ed25519".into()];
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn deterministic_hash() {
        assert_eq!(
            sample().payload_sha512().expect("first hash"),
            sample().payload_sha512().expect("second hash")
        );
    }
}
