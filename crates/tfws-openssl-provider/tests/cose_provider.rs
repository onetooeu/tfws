use sha2::{Digest, Sha256};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tfws_core::{
    sign_manifest_cose, verify_manifest_cose, CoseAlgorithm, CoseEnvelopeError, CoseSigner,
    Manifest, ED25519_SIGNATURE_BYTES, ML_DSA_65_SIGNATURE_BYTES,
};
use tfws_openssl_provider::OpenSslProvider;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const PRIMARY_KEY_ID: &str = "release-1";

struct TestKeys {
    root: PathBuf,
    private_dir: PathBuf,
    public_dir: PathBuf,
    scratch_dir: PathBuf,
    openssl: PathBuf,
}

impl TestKeys {
    fn create() -> Self {
        let openssl = env::var_os("TFWS_OPENSSL")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("openssl"));
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "tfws-openssl-provider-test-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        let private_dir = root.join("private");
        let public_dir = root.join("public");
        let scratch_dir = root.join("scratch");

        fs::create_dir_all(&private_dir).expect("private directory");
        fs::create_dir_all(&public_dir).expect("public directory");
        fs::create_dir_all(&scratch_dir).expect("scratch directory");

        let keys = Self {
            root,
            private_dir,
            public_dir,
            scratch_dir,
            openssl,
        };

        for (tfws_name, openssl_name) in [("ed25519", "ED25519"), ("ml-dsa-65", "ML-DSA-65")] {
            keys.generate_pair(tfws_name, openssl_name, PRIMARY_KEY_ID);
        }

        keys
    }

    fn provider(&self) -> OpenSslProvider {
        OpenSslProvider::with_scratch_root(
            &self.openssl,
            &self.private_dir,
            &self.public_dir,
            &self.scratch_dir,
        )
    }

    fn private_key_path(&self, algorithm: &str, key_id: &str) -> PathBuf {
        self.private_dir
            .join(algorithm)
            .join(format!("{key_id}.pem"))
    }

    fn public_key_path(&self, algorithm: &str, key_id: &str) -> PathBuf {
        self.public_dir
            .join(algorithm)
            .join(format!("{key_id}.pem"))
    }

    fn generate_pair(&self, tfws_name: &str, openssl_name: &str, key_id: &str) {
        let private_key = self.private_key_path(tfws_name, key_id);
        let public_key = self.public_key_path(tfws_name, key_id);

        fs::create_dir_all(private_key.parent().expect("private parent"))
            .expect("private algorithm directory");
        fs::create_dir_all(public_key.parent().expect("public parent"))
            .expect("public algorithm directory");

        run(
            &self.openssl,
            ["genpkey", "-algorithm", openssl_name, "-out"],
            &private_key,
        );

        let status = Command::new(&self.openssl)
            .args(["pkey", "-in"])
            .arg(&private_key)
            .args(["-pubout", "-out"])
            .arg(&public_key)
            .status()
            .expect("derive public key");

        assert!(status.success(), "public-key derivation failed");
    }

    fn bound_manifest(&self) -> Manifest {
        self.bound_manifest_for(PRIMARY_KEY_ID)
    }

    fn bound_manifest_for(&self, key_id: &str) -> Manifest {
        let mut manifest: Manifest =
            serde_json::from_str(include_str!("../../../test-vectors/manifest.valid.json"))
                .expect("valid embedded manifest");

        for descriptor in &mut manifest.keys {
            descriptor.key_id = key_id.into();
            let path = self.public_key_path(&descriptor.algorithm, key_id);
            let bytes = fs::read(path).expect("public key");
            descriptor.public_key_sha256 = lower_hex(&Sha256::digest(bytes));
        }

        manifest.validate().expect("bound manifest");
        manifest
    }
}

impl Drop for TestKeys {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run<const N: usize>(openssl: &Path, arguments: [&str; N], output_path: &Path) {
    let status = Command::new(openssl)
        .args(arguments)
        .arg(output_path)
        .status()
        .expect("OpenSSL command");

    assert!(status.success(), "OpenSSL command failed");
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn real_hybrid_cose_sign_and_verify() {
    let keys = TestKeys::create();
    let provider = keys.provider();
    let manifest = keys.bound_manifest();

    let envelope = sign_manifest_cose(&manifest, &provider).expect("real signing");
    let verified = verify_manifest_cose(&envelope, &provider).expect("real verification");

    assert!(envelope.starts_with(&[0xd8, 0x62]));
    assert_eq!(
        serde_json::to_value(verified).expect("verified JSON"),
        serde_json::to_value(manifest).expect("source JSON")
    );
}

#[test]
fn provider_trait_signatures_have_exact_profile_lengths() {
    let keys = TestKeys::create();
    let provider = keys.provider();
    let manifest = keys.bound_manifest();
    let ed_descriptor = manifest
        .keys
        .iter()
        .find(|descriptor| descriptor.algorithm == "ed25519")
        .expect("Ed25519 descriptor");
    let ml_descriptor = manifest
        .keys
        .iter()
        .find(|descriptor| descriptor.algorithm == "ml-dsa-65")
        .expect("ML-DSA-65 descriptor");

    let ed_signature = provider
        .sign(CoseAlgorithm::Ed25519, ed_descriptor, b"test message")
        .expect("Ed25519 signature");
    let ml_signature = provider
        .sign(CoseAlgorithm::MlDsa65, ml_descriptor, b"test message")
        .expect("ML-DSA-65 signature");

    assert_eq!(ed_signature.len(), ED25519_SIGNATURE_BYTES);
    assert_eq!(ml_signature.len(), ML_DSA_65_SIGNATURE_BYTES);
}

#[test]
fn key_id_specific_resolution_supports_rotation() {
    let keys = TestKeys::create();

    for algorithm in ["ed25519", "ml-dsa-65"] {
        let private_source = keys.private_key_path(algorithm, PRIMARY_KEY_ID);
        let public_source = keys.public_key_path(algorithm, PRIMARY_KEY_ID);
        let private_target = keys.private_key_path(algorithm, "release-2");
        let public_target = keys.public_key_path(algorithm, "release-2");

        fs::copy(private_source, private_target).expect("copy rotated private key");
        fs::copy(public_source, public_target).expect("copy rotated public key");
    }

    let provider = keys.provider();
    let manifest = keys.bound_manifest_for("release-2");
    let envelope = sign_manifest_cose(&manifest, &provider).expect("rotated signing");

    verify_manifest_cose(&envelope, &provider).expect("rotated verification");
}

#[test]
fn key_id_path_traversal_is_rejected() {
    let keys = TestKeys::create();
    let provider = keys.provider();
    let mut manifest = keys.bound_manifest();

    manifest.keys[0].key_id = "../escape".into();

    assert!(matches!(
        sign_manifest_cose(&manifest, &provider),
        Err(CoseEnvelopeError::KeyBindingMismatch)
    ));
}

#[test]
fn public_key_substitution_is_a_binding_failure() {
    let keys = TestKeys::create();
    let provider = keys.provider();
    let manifest = keys.bound_manifest();
    let envelope = sign_manifest_cose(&manifest, &provider).expect("real signing");

    fs::copy(
        keys.public_key_path("ml-dsa-65", PRIMARY_KEY_ID),
        keys.public_key_path("ed25519", PRIMARY_KEY_ID),
    )
    .expect("replace public key");

    assert!(matches!(
        verify_manifest_cose(&envelope, &provider),
        Err(CoseEnvelopeError::KeyBindingMismatch)
    ));
}

#[test]
fn mismatched_private_and_public_keys_are_rejected() {
    let keys = TestKeys::create();
    let provider = keys.provider();
    let manifest = keys.bound_manifest();
    let replacement = keys.root.join("replacement-ed25519.pem");

    run(
        &keys.openssl,
        ["genpkey", "-algorithm", "ED25519", "-out"],
        &replacement,
    );

    fs::copy(
        replacement,
        keys.private_key_path("ed25519", PRIMARY_KEY_ID),
    )
    .expect("replace Ed25519 private key");

    assert!(matches!(
        sign_manifest_cose(&manifest, &provider),
        Err(CoseEnvelopeError::SignatureInvalid)
    ));
}

#[test]
fn tampered_signature_is_rejected() {
    let keys = TestKeys::create();
    let provider = keys.provider();
    let manifest = keys.bound_manifest();
    let mut envelope = sign_manifest_cose(&manifest, &provider).expect("real signing");
    let last = envelope.last_mut().expect("envelope has signature bytes");

    *last ^= 0x01;

    assert!(matches!(
        verify_manifest_cose(&envelope, &provider),
        Err(CoseEnvelopeError::SignatureInvalid)
    ));
}

#[test]
fn private_key_in_public_directory_is_rejected() {
    let keys = TestKeys::create();
    let provider = keys.provider();
    let mut manifest = keys.bound_manifest();
    let replacement = keys.private_key_path("ed25519", PRIMARY_KEY_ID);
    let public_path = keys.public_key_path("ed25519", PRIMARY_KEY_ID);

    fs::copy(&replacement, &public_path).expect("copy private key to public directory");
    let replacement_bytes = fs::read(&public_path).expect("replacement bytes");

    manifest
        .keys
        .iter_mut()
        .find(|descriptor| descriptor.algorithm == "ed25519")
        .expect("Ed25519 descriptor")
        .public_key_sha256 = lower_hex(&Sha256::digest(replacement_bytes));

    assert!(matches!(
        sign_manifest_cose(&manifest, &provider),
        Err(CoseEnvelopeError::KeyBindingMismatch)
    ));
}

#[test]
fn missing_private_key_fails_without_partial_envelope() {
    let keys = TestKeys::create();
    let provider = keys.provider();
    let manifest = keys.bound_manifest();

    fs::remove_file(keys.private_key_path("ml-dsa-65", PRIMARY_KEY_ID))
        .expect("remove ML-DSA-65 private key");

    let error = sign_manifest_cose(&manifest, &provider)
        .expect_err("complete baseline must not be emitted");

    assert_eq!(error.category(), "signature_invalid");
}

#[test]
fn scratch_directories_are_removed_after_operations() {
    let keys = TestKeys::create();
    let provider = keys.provider();
    let manifest = keys.bound_manifest();
    let envelope = sign_manifest_cose(&manifest, &provider).expect("real signing");

    verify_manifest_cose(&envelope, &provider).expect("real verification");

    let entries = fs::read_dir(&keys.scratch_dir)
        .expect("scratch directory")
        .collect::<Result<Vec<_>, io::Error>>()
        .expect("scratch entries");

    assert!(entries.is_empty(), "scratch material was not removed");
}
