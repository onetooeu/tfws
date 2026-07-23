import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "schemas"
VECTORS = ROOT / "test-vectors"


class SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_schema = json.loads(
            (SCHEMAS / "tfws-manifest.schema.json").read_text()
        )
        cls.signature_schema = json.loads(
            (SCHEMAS / "tfws-signature-bundle.schema.json").read_text()
        )

    def test_schemas_are_valid_draft_2020_12(self):
        for path in SCHEMAS.glob("*.json"):
            Draft202012Validator.check_schema(json.loads(path.read_text()))

    def test_positive_vectors(self):
        manifest = json.loads((VECTORS / "manifest.valid.json").read_text())
        bundle = json.loads(
            (VECTORS / "hybrid-signature-v1/tfws.sig.json").read_text()
        )
        Draft202012Validator(self.manifest_schema).validate(manifest)
        Draft202012Validator(self.signature_schema).validate(bundle)

    def test_downgrade_vector_is_rejected(self):
        manifest = json.loads(
            (VECTORS / "manifest.invalid-downgrade.json").read_text()
        )
        with self.assertRaises(ValidationError):
            Draft202012Validator(self.manifest_schema).validate(manifest)

    def test_duplicate_signature_algorithm_is_rejected(self):
        bundle = json.loads(
            (VECTORS / "hybrid-signature-v1/tfws.sig.json").read_text()
        )
        bundle["signatures"][1]["algorithm"] = "ed25519"
        bundle["signatures"][1]["public_key_uri"] = "/.well-known/keys/ed25519.pem"
        with self.assertRaises(ValidationError):
            Draft202012Validator(self.signature_schema).validate(bundle)


if __name__ == "__main__":
    unittest.main()
