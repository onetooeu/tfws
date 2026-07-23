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
