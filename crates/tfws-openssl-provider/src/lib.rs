#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tfws_core::{CoseAlgorithm, CoseCryptoError, CoseSigner, CoseVerifier, KeyDescriptor};
use thiserror::Error;

#[cfg(windows)]
use std::{
    ffi::OsString,
    os::windows::ffi::{OsStrExt, OsStringExt},
};

static SCRATCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_OPENSSL_DIAGNOSTIC_CHARS: usize = 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("OpenSSL operation failed")]
    OpenSsl,
}

pub fn verify(public_key: &Path, message: &Path, signature: &Path) -> Result<(), Error> {
    require_no_private_key(public_key)?;

    let public_key = external_command_path(public_key);
    let message = external_command_path(message);
    let signature = external_command_path(signature);
    let output = Command::new("openssl")
        .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
        .arg(&public_key)
        .args(["-rawin", "-in"])
        .arg(&message)
        .arg("-sigfile")
        .arg(&signature)
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(Error::OpenSsl)
    }
}

pub fn require_no_private_key(path: &Path) -> Result<(), Error> {
    let text = fs::read_to_string(path)?;

    if text.contains("PRIVATE KEY") {
        Err(Error::OpenSsl)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct OpenSslProvider {
    openssl: PathBuf,
    private_key_dir: PathBuf,
    public_key_dir: PathBuf,
    scratch_root: PathBuf,
}

struct BoundPublicKey {
    bytes: Vec<u8>,
}

impl OpenSslProvider {
    pub fn new(
        openssl: impl Into<PathBuf>,
        private_key_dir: impl Into<PathBuf>,
        public_key_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            openssl: openssl.into(),
            private_key_dir: private_key_dir.into(),
            public_key_dir: public_key_dir.into(),
            scratch_root: env::temp_dir(),
        }
    }

    pub fn with_scratch_root(
        openssl: impl Into<PathBuf>,
        private_key_dir: impl Into<PathBuf>,
        public_key_dir: impl Into<PathBuf>,
        scratch_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            openssl: openssl.into(),
            private_key_dir: private_key_dir.into(),
            public_key_dir: public_key_dir.into(),
            scratch_root: scratch_root.into(),
        }
    }

    fn public_key_path(
        &self,
        algorithm: CoseAlgorithm,
        key_id: &str,
    ) -> Result<PathBuf, CoseCryptoError> {
        resolve_key_path(&self.public_key_dir, algorithm, key_id, true)
    }

    fn private_key_path(
        &self,
        algorithm: CoseAlgorithm,
        key_id: &str,
    ) -> Result<PathBuf, CoseCryptoError> {
        resolve_key_path(&self.private_key_dir, algorithm, key_id, false)
    }

    fn validate_public_key_binding(
        &self,
        algorithm: CoseAlgorithm,
        descriptor: &KeyDescriptor,
    ) -> Result<BoundPublicKey, CoseCryptoError> {
        if descriptor.algorithm != algorithm.tfws_identifier()
            || descriptor.key_id.is_empty()
            || descriptor.status != "active"
            || descriptor.usage.len() != 1
            || descriptor.usage[0] != "release"
            || descriptor.public_key_uri
                != format!("/.well-known/keys/{}.pem", algorithm.tfws_identifier())
        {
            return Err(CoseCryptoError::KeyBindingMismatch);
        }

        let public_key = self.public_key_path(algorithm, &descriptor.key_id)?;
        let public_key_bytes =
            fs::read(public_key).map_err(|_| CoseCryptoError::KeyBindingMismatch)?;
        let public_key_text = String::from_utf8_lossy(&public_key_bytes);

        if public_key_text.contains("PRIVATE KEY") || !public_key_text.contains("PUBLIC KEY") {
            return Err(CoseCryptoError::KeyBindingMismatch);
        }

        let actual_digest = lower_hex(&Sha256::digest(&public_key_bytes));

        if actual_digest != descriptor.public_key_sha256 {
            return Err(CoseCryptoError::KeyBindingMismatch);
        }

        Ok(BoundPublicKey {
            bytes: public_key_bytes,
        })
    }

    fn validated_private_key(
        &self,
        algorithm: CoseAlgorithm,
        key_id: &str,
    ) -> Result<PathBuf, CoseCryptoError> {
        let private_key = self.private_key_path(algorithm, key_id)?;
        let text = fs::read_to_string(&private_key)
            .map_err(|_| CoseCryptoError::OperationFailed("private key is unavailable".into()))?;

        if !text.contains("PRIVATE KEY") {
            return Err(CoseCryptoError::OperationFailed(
                "private key file is invalid".into(),
            ));
        }

        Ok(private_key)
    }

    fn sign_bytes(
        &self,
        algorithm: CoseAlgorithm,
        private_key: &Path,
        public_key_bytes: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, CoseCryptoError> {
        let scratch = ScratchDirectory::new(&self.scratch_root).map_err(operation_error)?;
        let message_path = scratch.path().join("message.bin");
        let signature_path = scratch.path().join("signature.bin");
        let public_key_path = scratch.path().join("public-key.pem");

        fs::write(&message_path, message).map_err(operation_error)?;
        fs::write(&public_key_path, public_key_bytes).map_err(operation_error)?;

        let private_key_argument = external_command_path(private_key);
        let message_argument = external_command_path(&message_path);
        let signature_argument = external_command_path(&signature_path);
        let public_key_argument = external_command_path(&public_key_path);
        let output = Command::new(&self.openssl)
            .args(["pkeyutl", "-sign", "-inkey"])
            .arg(&private_key_argument)
            .args(["-rawin", "-in"])
            .arg(&message_argument)
            .arg("-out")
            .arg(&signature_argument)
            .output()
            .map_err(operation_error)?;

        if !output.status.success() {
            return Err(openssl_operation_error(
                "signing",
                &output,
                &[private_key, scratch.path()],
            ));
        }

        let signature = fs::read(&signature_path).map_err(operation_error)?;

        if signature.len() != algorithm.expected_signature_len() {
            return Err(CoseCryptoError::SignatureInvalid);
        }

        let verification = Command::new(&self.openssl)
            .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
            .arg(&public_key_argument)
            .args(["-rawin", "-in"])
            .arg(&message_argument)
            .arg("-sigfile")
            .arg(&signature_argument)
            .output()
            .map_err(operation_error)?;

        if !verification.status.success() {
            // A failed post-sign verification is a cryptographic key-binding
            // failure, matching the verifier contract. Process-launch errors
            // are still mapped above as operational failures, and native
            // diagnostics remain available for actual signing failures.
            return Err(CoseCryptoError::SignatureInvalid);
        }

        Ok(signature)
    }

    fn verify_bytes(
        &self,
        algorithm: CoseAlgorithm,
        public_key_bytes: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CoseCryptoError> {
        if signature.len() != algorithm.expected_signature_len() {
            return Err(CoseCryptoError::SignatureInvalid);
        }

        let scratch = ScratchDirectory::new(&self.scratch_root).map_err(operation_error)?;
        let message_path = scratch.path().join("message.bin");
        let signature_path = scratch.path().join("signature.bin");
        let public_key_path = scratch.path().join("public-key.pem");

        fs::write(&message_path, message).map_err(operation_error)?;
        fs::write(&signature_path, signature).map_err(operation_error)?;
        fs::write(&public_key_path, public_key_bytes).map_err(operation_error)?;

        let public_key_argument = external_command_path(&public_key_path);
        let message_argument = external_command_path(&message_path);
        let signature_argument = external_command_path(&signature_path);
        let output = Command::new(&self.openssl)
            .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
            .arg(&public_key_argument)
            .args(["-rawin", "-in"])
            .arg(&message_argument)
            .arg("-sigfile")
            .arg(&signature_argument)
            .output()
            .map_err(operation_error)?;

        if output.status.success() {
            Ok(())
        } else {
            Err(CoseCryptoError::SignatureInvalid)
        }
    }
}

impl CoseSigner for OpenSslProvider {
    fn sign(
        &self,
        algorithm: CoseAlgorithm,
        descriptor: &KeyDescriptor,
        message: &[u8],
    ) -> Result<Vec<u8>, CoseCryptoError> {
        let public_key = self.validate_public_key_binding(algorithm, descriptor)?;
        let private_key = self.validated_private_key(algorithm, &descriptor.key_id)?;

        self.sign_bytes(algorithm, &private_key, &public_key.bytes, message)
    }
}

impl CoseVerifier for OpenSslProvider {
    fn verify(
        &self,
        algorithm: CoseAlgorithm,
        descriptor: &KeyDescriptor,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CoseCryptoError> {
        let public_key = self.validate_public_key_binding(algorithm, descriptor)?;

        self.verify_bytes(algorithm, &public_key.bytes, message, signature)
    }
}

struct ScratchDirectory {
    path: PathBuf,
}

impl ScratchDirectory {
    fn new(root: &Path) -> io::Result<Self> {
        fs::create_dir_all(root)?;

        for _ in 0..64 {
            let sequence = SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = root.join(format!(
                "tfws-openssl-{}-{timestamp}-{sequence}",
                std::process::id()
            ));

            match fs::create_dir(&path) {
                Ok(()) => {
                    if let Err(error) = set_private_directory_permissions(&path) {
                        let _ = fs::remove_dir_all(&path);
                        return Err(error);
                    }

                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create unique OpenSSL scratch directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn set_private_directory_permissions(path: &Path) -> io::Result<()> {
    let identity_output = Command::new("whoami").output()?;

    if !identity_output.status.success() {
        return Err(io::Error::other(
            "could not resolve the current Windows identity",
        ));
    }

    let identity = String::from_utf8_lossy(&identity_output.stdout)
        .trim()
        .to_owned();

    if identity.is_empty() {
        return Err(io::Error::other("the current Windows identity is empty"));
    }

    let grant = format!("{identity}:(OI)(CI)F");
    let acl_output = Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(grant)
        .output()?;

    if acl_output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            "could not restrict the Windows scratch ACL",
        ))
    }
}

#[cfg(not(any(unix, windows)))]
fn set_private_directory_permissions(_path: &Path) -> io::Result<()> {
    Err(io::Error::other(
        "private scratch permissions are unsupported",
    ))
}

#[cfg(windows)]
fn external_command_path(path: &Path) -> PathBuf {
    let encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    const VERBATIM_PREFIX: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const UNC_PREFIX: &[u16] = &[b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16];

    if !encoded.starts_with(VERBATIM_PREFIX) {
        return path.to_path_buf();
    }

    let remainder = &encoded[VERBATIM_PREFIX.len()..];

    if remainder.starts_with(UNC_PREFIX) {
        let mut normalized = vec![b'\\' as u16, b'\\' as u16];
        normalized.extend_from_slice(&remainder[UNC_PREFIX.len()..]);
        PathBuf::from(OsString::from_wide(&normalized))
    } else {
        PathBuf::from(OsString::from_wide(remainder))
    }
}

#[cfg(not(windows))]
fn external_command_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

fn openssl_operation_error(
    operation: &str,
    output: &Output,
    redacted_paths: &[&Path],
) -> CoseCryptoError {
    let status = output.status.code().map_or_else(
        || "terminated without an exit code".to_owned(),
        |code| format!("exit code {code}"),
    );
    let diagnostic_source = if output.stderr.is_empty() {
        output.stdout.as_slice()
    } else {
        output.stderr.as_slice()
    };
    let diagnostic = sanitize_openssl_diagnostic(diagnostic_source, redacted_paths);
    let message = if diagnostic.is_empty() {
        format!("OpenSSL {operation} failed ({status})")
    } else {
        format!("OpenSSL {operation} failed ({status}): {diagnostic}")
    };

    CoseCryptoError::OperationFailed(message)
}

fn sanitize_openssl_diagnostic(bytes: &[u8], redacted_paths: &[&Path]) -> String {
    let mut diagnostic = String::from_utf8_lossy(bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    for path in redacted_paths {
        for candidate in [path.to_path_buf(), external_command_path(path)] {
            let candidate = candidate.to_string_lossy();

            if !candidate.is_empty() {
                diagnostic = diagnostic.replace(candidate.as_ref(), "<path>");
            }
        }
    }

    let mut characters = diagnostic.chars();
    let mut bounded = characters
        .by_ref()
        .take(MAX_OPENSSL_DIAGNOSTIC_CHARS)
        .collect::<String>();

    if characters.next().is_some() {
        bounded.push('…');
    }

    bounded
}

fn resolve_key_path(
    root: &Path,
    algorithm: CoseAlgorithm,
    key_id: &str,
    public_key: bool,
) -> Result<PathBuf, CoseCryptoError> {
    validate_key_id(key_id)?;

    let canonical_root = fs::canonicalize(root).map_err(|_| {
        if public_key {
            CoseCryptoError::KeyBindingMismatch
        } else {
            CoseCryptoError::OperationFailed("private key directory is unavailable".into())
        }
    })?;
    let candidate = root
        .join(algorithm.tfws_identifier())
        .join(format!("{key_id}.pem"));
    let canonical_candidate = fs::canonicalize(candidate).map_err(|_| {
        if public_key {
            CoseCryptoError::KeyBindingMismatch
        } else {
            CoseCryptoError::OperationFailed("private key is unavailable".into())
        }
    })?;

    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(CoseCryptoError::KeyBindingMismatch);
    }

    Ok(canonical_candidate)
}

fn validate_key_id(key_id: &str) -> Result<(), CoseCryptoError> {
    if key_id.is_empty()
        || key_id.len() > MAX_KEY_ID_BYTES
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(CoseCryptoError::KeyBindingMismatch);
    }

    Ok(())
}

fn operation_error(_error: io::Error) -> CoseCryptoError {
    CoseCryptoError::OperationFailed("local OpenSSL bridge I/O failed".into())
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_is_bounded_and_redacts_paths() {
        let private_key = Path::new(r"C:\sensitive\release-key.pem");
        let input = format!(
            "cannot open C:\\sensitive\\release-key.pem\n{}",
            "x".repeat(MAX_OPENSSL_DIAGNOSTIC_CHARS + 32)
        );
        let diagnostic = sanitize_openssl_diagnostic(input.as_bytes(), &[private_key]);

        assert!(diagnostic.contains("<path>"));
        assert!(!diagnostic.contains("release-key.pem"));
        assert!(diagnostic.ends_with('…'));
        assert!(diagnostic.chars().count() <= MAX_OPENSSL_DIAGNOSTIC_CHARS + 1);
    }

    #[cfg(windows)]
    #[test]
    fn external_command_path_removes_verbatim_drive_prefix() {
        assert_eq!(
            external_command_path(Path::new(r"\\?\C:\temp\key.pem")),
            PathBuf::from(r"C:\temp\key.pem")
        );
    }

    #[cfg(windows)]
    #[test]
    fn external_command_path_normalizes_verbatim_unc_prefix() {
        assert_eq!(
            external_command_path(Path::new(r"\\?\UNC\server\share\key.pem")),
            PathBuf::from(r"\\server\share\key.pem")
        );
    }
}
