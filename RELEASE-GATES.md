# Release gates

A production release is forbidden until all mandatory gates pass:

Current engineering-alpha evidence: the Rust workspace and WASM target have
passed a locked local Windows build with Rust 1.86.0. This does not yet satisfy
the multi-platform reproducibility, signed provenance or independent-review
gates below.

- no open critical or high security findings,
- reproducible builds and signed release provenance,
- conformance tests across Tier-1 platforms,
- independent interoperability and security review,
- tested backup, restore, rollback, key rotation and recovery,
- WCAG 2.2 AA for public interfaces,
- legal review of certification and privacy claims.
