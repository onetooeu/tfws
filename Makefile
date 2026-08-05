.PHONY: test test-python test-python-cbor-cose test-node test-rust \
	test-rust-locked test-vectors test-wasm test-wasm-codec \
	validate-repository issue9-validate validate

PYTHON ?= python3
CARGO ?= cargo

test: issue9-validate

test-python:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=reference/python $(PYTHON) -m unittest discover -s reference/python/tests -v

test-python-cbor-cose:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=reference/python $(PYTHON) -m unittest discover -s reference/python/tests -p test_core.py -v
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=reference/python $(PYTHON) -m unittest discover -s reference/python/tests -p test_issue7_cbor_cose_conformance_vectors.py -v

test-node:
	node --test sdks/typescript/test/*.test.mjs

test-rust: test-rust-locked

test-rust-locked:
	$(CARGO) fmt --all -- --check
	$(CARGO) check --workspace --all-targets --locked --offline
	$(CARGO) test --package tfws-core --test cbor_codec --locked --offline
	$(CARGO) test --package tfws-core --test cose_envelope --locked --offline
	$(CARGO) test --package tfws-openssl-provider --locked --offline
	$(CARGO) test --package tfws-core --test issue7_cbor_cose_conformance_vectors --locked --offline
	$(CARGO) test --package tfws-cli --locked --offline
	$(CARGO) test --workspace --all-targets --locked --offline
	$(CARGO) clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
	$(CARGO) build --workspace --all-targets --locked --offline

test-vectors:
	@vector_temp=$$(mktemp -d); trap 'rm -rf "$$vector_temp"' EXIT; \
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=reference/python $(PYTHON) scripts/generate_issue7_cbor_cose_vectors.py \
		--manifest test-vectors/manifest.valid.json \
		--output "$$vector_temp/issue7-cbor-cose-cross-language-v1.json" \
		--digest-output "$$vector_temp/issue7-cbor-cose-cross-language-v1.sha256" \
		--schema test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.schema.json \
		--self-test; \
	cmp test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.json \
		"$$vector_temp/issue7-cbor-cose-cross-language-v1.json"; \
	cmp test-vectors/hybrid-signature-v1/issue7-cbor-cose-cross-language-v1.sha256 \
		"$$vector_temp/issue7-cbor-cose-cross-language-v1.sha256"

test-wasm: test-wasm-codec

test-wasm-codec:
	$(CARGO) test --package tfws-wasm --locked --offline
	$(CARGO) build --package tfws-wasm --target wasm32-unknown-unknown --locked --offline

validate-repository:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/validate_repository.py

issue9-validate: test-python-cbor-cose test-python test-node test-vectors test-rust-locked test-wasm-codec validate-repository

validate: issue9-validate
