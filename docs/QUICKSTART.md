# TFWS 3.0 engineering-alpha quickstart

Requirements: Python 3.11+ and OpenSSL 3.5+ with Ed25519 and ML-DSA-65.

```bash
export PYTHONPATH="$PWD/reference/python"
python3 -m tfws3.cli init --domain example.com --operator "Example Ltd." --out tfws.json
python3 -m tfws3.cli keygen --out .tfws-local-keys
python3 -m tfws3.cli sign --manifest tfws.json --keys .tfws-local-keys --out tfws.sig.json
python3 -m tfws3.cli verify --manifest tfws.json --bundle tfws.sig.json --public-keys .tfws-local-keys/public
```

Private keys must stay outside the repository. Production root/recovery keys require the custody model in the specification; this bootstrap keyset is for controlled engineering use.

## Issue #9 local conformance gates

Install no dependencies while running the gates: use the committed Cargo lock,
an already provisioned `wasm32-unknown-unknown` target, Python test
dependencies, Node, and OpenSSL 3.5+ exposing both Ed25519 and ML-DSA-65.
The Make targets use a POSIX shell; on Windows, use Git Bash or run the
equivalent commands in the CI workflow.

```bash
make test-python-cbor-cose
make test-vectors
make test-rust-locked
make test-wasm-codec
make validate-repository
make issue9-validate
```

The commands run Python CBOR/COSE and Issue #7 regression tests, regenerate the
one positive and 18 negative committed vectors outside the repository and
compare bytes, run locked/offline Rust and explicit CLI-format tests, execute
the deterministic CBOR decoder through the WASM boundary, build the WASM
target, and run the repository validator. CI maps the same gates to
`python-node` and the governed Rust checks on Ubuntu, Windows, and macOS.

Select JSON, CBOR, or COSE explicitly at every CLI boundary.
Automatic format detection and downgrade are forbidden: malformed CBOR and COSE
failures are terminal and never downgrade to JSON. The WASM CBOR export validates
deterministic manifest CBOR only; COSE hybrid verification remains outside that
WASM boundary.

This is engineering-alpha validation, not certification, a release claim, or
evidence of production completeness.
