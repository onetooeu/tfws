# TFWS 3.0 Secure Transport Profile

The optional transport profile combines X25519 and ML-KEM-768. Session secrets are derived from
both contributions with an approved KDF and used with AES-256-GCM or ChaCha20-Poly1305.

This alpha defines interfaces and test requirements only. A deployment MUST NOT advertise this
capability until an audited implementation and interoperability vectors are present.
