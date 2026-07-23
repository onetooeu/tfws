.PHONY: test test-python test-node test-rust test-wasm validate

test: test-python test-node test-rust test-wasm

test-python:
	PYTHONPATH=reference/python python3 -m unittest discover -s reference/python/tests -v

test-node:
	node --test sdks/typescript/test/*.test.mjs

test-rust:
	cargo fmt --all -- --check
	cargo check --workspace --all-targets --locked
	cargo test --workspace --all-targets --locked
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
	cargo build --workspace --all-targets --locked

test-wasm:
	cargo build --package tfws-wasm --target wasm32-unknown-unknown --locked

validate: test
	python3 scripts/validate_repository.py
