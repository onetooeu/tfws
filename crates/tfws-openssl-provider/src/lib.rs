#![forbid(unsafe_code)]
use std::{fs, path::Path, process::Command};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("OpenSSL operation failed")]
    OpenSsl,
}

pub fn verify(public_key: &Path, message: &Path, signature: &Path) -> Result<(), Error> {
    let output = Command::new("openssl")
        .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
        .arg(public_key)
        .args(["-rawin", "-in"])
        .arg(message)
        .args(["-sigfile"])
        .arg(signature)
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
