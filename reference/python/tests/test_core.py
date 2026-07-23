import copy
import tempfile
import unittest
from pathlib import Path

from tfws3.canonical import canonicalize
from tfws3.cli import new_manifest
from tfws3.crypto import bind_public_keys, generate_keyset, sign_manifest, verify_bundle
from tfws3.errors import CryptoError, PolicyError, ValidationError
from tfws3.eventlog import append_event, merkle_root, read_events, verify_chain
from tfws3.models import validate_manifest
from tfws3.netpolicy import validate_public_https_url


class CoreTests(unittest.TestCase):
    def test_canonical_deterministic(self):
        self.assertEqual(
            canonicalize({"b": 1, "a": "ž"}),
            '{"a":"ž","b":1}'.encode("utf-8"),
        )
        self.assertEqual(
            canonicalize({"a": [True, None, 2]}),
            canonicalize({"a": [True, None, 2]}),
        )

    def test_floats_fail_closed(self):
        with self.assertRaises(ValidationError):
            canonicalize({"n": 1.5})

    def test_unknown_required_capability_fails(self):
        manifest = new_manifest("example.com", "Example", "development")
        manifest["capabilities"]["required"].append("unknown.v1")
        with self.assertRaises(PolicyError):
            validate_manifest(manifest)

    def test_downgrade_fails(self):
        manifest = new_manifest("example.com", "Example", "development")
        manifest["signature_policy"]["required_algorithms"] = ["ed25519"]
        with self.assertRaises(PolicyError):
            validate_manifest(manifest)

    def test_hybrid_sign_verify_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keys = root / "keys"
            generate_keyset(keys)
            manifest = bind_public_keys(
                new_manifest("example.com", "Example", "development"),
                keys / "public",
            )
            bundle = sign_manifest(
                manifest, keys, created="2026-07-21T12:00:00Z"
            )
            result = verify_bundle(manifest, bundle, keys / "public")
            self.assertTrue(result["valid"])

            tampered = copy.deepcopy(manifest)
            tampered["operator"]["name"] = "Attacker"
            with self.assertRaises(CryptoError):
                verify_bundle(tampered, bundle, keys / "public")

            missing = copy.deepcopy(bundle)
            missing["signatures"] = missing["signatures"][:1]
            with self.assertRaises(CryptoError):
                verify_bundle(manifest, missing, keys / "public")

            mismatched_uri = copy.deepcopy(bundle)
            mismatched_uri["signatures"][0]["public_key_uri"] = "/wrong.pem"
            with self.assertRaises(CryptoError):
                verify_bundle(manifest, mismatched_uri, keys / "public")

            replacement_keys = root / "replacement-keys"
            generate_keyset(replacement_keys)
            with self.assertRaises(CryptoError):
                verify_bundle(manifest, bundle, replacement_keys / "public")

    def test_event_chain_and_merkle(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "events.jsonl"
            append_event(
                log,
                event_type="publisher_registered",
                subject="https://example.com",
                payload={"v": 1},
            )
            append_event(
                log,
                event_type="key_rotated",
                subject="https://example.com",
                payload={"epoch": 2},
            )
            events = read_events(log)
            verify_chain(events)
            self.assertEqual(len(merkle_root(events)), 64)
            events[1]["previous_event_hash"] = "0" * 64
            with self.assertRaises(ValidationError):
                verify_chain(events)

    def test_public_hybrid_vector(self):
        import json
        root = Path(__file__).resolve().parents[3] / "test-vectors" / "hybrid-signature-v1"
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        bundle = json.loads((root / "tfws.sig.json").read_text(encoding="utf-8"))
        self.assertTrue(verify_bundle(manifest, bundle, root / "public-keys")["valid"])

    def test_network_policy(self):
        self.assertEqual(
            validate_public_https_url("https://example.com/a"),
            "https://example.com/a",
        )
        for url in (
            "http://example.com",
            "https://127.0.0.1",
            "https://localhost",
            "file:///etc/passwd",
            "https://example.com:444/",
        ):
            with self.subTest(url=url), self.assertRaises(PolicyError):
                validate_public_https_url(url)


if __name__ == "__main__":
    unittest.main()
