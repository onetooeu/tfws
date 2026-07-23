# Contributing

TFWS 3.0 is an engineering alpha with fail-closed security invariants.
Contributions are welcome, but merged code must not overstate implementation or
production readiness.

## Before starting

- Search existing issues and pull requests.
- Open or reference an issue or RFC before protocol-affecting work.
- Read `RELEASE-GATES.md` and `docs/IMPLEMENTATION-STATUS.md`.
- Report suspected vulnerabilities privately according to `SECURITY.md`.

## Development requirements

The repository uses:

- Rust 1.86.0 as pinned by `rust-toolchain.toml`,
- Python 3.11 or newer,
- Node.js and npm for the TypeScript SDK,
- OpenSSL 3.5 or newer with Ed25519 and ML-DSA-65 support,
- GNU Make for the main validation entry point.

Run the complete local validation:

```bash
make validate
```

Changes must keep locked dependency resolution and must not weaken negative
tests, downgrade rejection, capability checks, or fail-closed behavior.

## Contribution workflow

1. Create a focused branch or fork.
2. Keep changes small and reviewable.
3. Add or update tests for every behavioral change.
4. Update specifications and documentation when behavior changes.
5. Run the complete validation suite.
6. Create signed commits.
7. Open a pull request using the repository template.

Maintainers with direct write access must preflight the exact signed commit on a
`ci/**` branch. Only after all required checks succeed may that same commit be
pushed to `main`.

## Security and cryptography

Never commit:

- production private keys,
- credentials, tokens, or secrets,
- real personal data,
- unreviewed generated cryptographic parameters.

Changes to cryptographic policy, signature verification, key lifecycle,
recovery, transparency, secure transport, or trust boundaries require explicit
security and architecture review.

## Style and scope

- Preserve LF line endings and UTF-8 without a byte-order mark.
- Keep public APIs and schemas backward-compatible unless an approved RFC says
  otherwise.
- Do not advertise scaffolded capabilities as implemented.
- Avoid unrelated formatting or dependency churn.
- Use clear commit messages that describe the reason for the change.

By participating, you agree to follow `CODE_OF_CONDUCT.md`.
