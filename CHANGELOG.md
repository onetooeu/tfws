# Changelog

All notable changes to this repository will be documented in this file.

The format follows the principles of Keep a Changelog. TFWS uses Semantic
Versioning-style identifiers, including pre-release identifiers for engineering
alpha builds.

## [Unreleased]

### Added

- Initial public TFWS 3.0 engineering-alpha source tree.
- Rust workspace for the core, CLI, OpenSSL provider adapter, and WASM interface.
- Python reference implementation and TypeScript SDK helpers.
- Public schemas, registries, test vectors, specifications, and formal models.
- Locked multi-platform CI for Rust, Python, Node.js, and the WASM target.
- CodeQL, Dependabot security updates, secret scanning, push protection, and
  private vulnerability reporting.
- Signed-commit and required-status-check protection for the `main` branch.

### Security

- The repository is intentionally fail-closed.
- Ed25519 and ML-DSA-65 hybrid verification is exercised through OpenSSL 3.5 or
  newer.
- Production use remains blocked by the gates in `RELEASE-GATES.md`.

No production release has been made from this repository.
