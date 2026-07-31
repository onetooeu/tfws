import importlib.util
import json
import tempfile
import unittest
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[3]
GENERATOR_PATH = ROOT / "scripts" / "generate_issue7_cbor_cose_vectors.py"
VECTOR_ROOT = ROOT / "test-vectors" / "hybrid-signature-v1"
CORPUS_PATH = VECTOR_ROOT / "issue7-cbor-cose-cross-language-v1.json"
SCHEMA_PATH = VECTOR_ROOT / "issue7-cbor-cose-cross-language-v1.schema.json"
DIGEST_PATH = VECTOR_ROOT / "issue7-cbor-cose-cross-language-v1.sha256"
MANIFEST_PATH = ROOT / "test-vectors" / "manifest.valid.json"

spec = importlib.util.spec_from_file_location("issue7_vector_generator", GENERATOR_PATH)
assert spec is not None and spec.loader is not None
vector_generator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = vector_generator
spec.loader.exec_module(vector_generator)


class Issue7CrossLanguageVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.by_class = {case["class"]: case for case in cls.corpus["negative"]}

    def assert_case_category(self, case_class):
        case = self.by_class[case_class]
        raw = bytes.fromhex(case["bytes_hex"])
        with self.assertRaises(vector_generator.VectorError) as captured:
            if case["input_type"] == "manifest_cbor":
                vector_generator.decode_manifest(raw)
            else:
                vector_generator.verify_cose(raw)
        self.assertEqual(captured.exception.category, case["expected_category"])

    def test_vec_001_schema(self):
        jsonschema.Draft202012Validator(self.schema).validate(self.corpus)
        vector_generator.validate_corpus(self.corpus)

    def test_vec_002_reproducibility(self):
        manifest = vector_generator.load_manifest(MANIFEST_PATH)
        rebuilt = vector_generator.build_corpus(manifest)
        self.assertEqual(vector_generator.corpus_bytes(rebuilt), CORPUS_PATH.read_bytes())
        expected_digest = vector_generator.sha256_hex(CORPUS_PATH.read_bytes())
        self.assertEqual(
            DIGEST_PATH.read_text(encoding="utf-8"),
            f"{expected_digest}  {CORPUS_PATH.name}\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            first_dir = Path(directory) / "first"
            second_dir = Path(directory) / "second"
            first = first_dir / CORPUS_PATH.name
            first_digest = first_dir / DIGEST_PATH.name
            second = second_dir / CORPUS_PATH.name
            second_digest = second_dir / DIGEST_PATH.name
            vector_generator.write_outputs(rebuilt, first, first_digest)
            vector_generator.write_outputs(rebuilt, second, second_digest)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_digest.read_text(), second_digest.read_text())

    def test_vec_003_canonical_cbor_bytes(self):
        positive = self.corpus["positive"]
        encoded = vector_generator.encode_manifest(positive["manifest"])
        self.assertEqual(encoded.hex(), positive["manifest_cbor_hex"])
        self.assertEqual(vector_generator.sha256_hex(encoded), positive["manifest_cbor_sha256"])

    def test_vec_004_decode_semantics(self):
        positive = self.corpus["positive"]
        decoded = vector_generator.decode_manifest(bytes.fromhex(positive["manifest_cbor_hex"]))
        self.assertEqual(decoded, positive["manifest"])

    def test_vec_005_positive_hybrid(self):
        positive = self.corpus["positive"]
        verified = vector_generator.verify_cose(bytes.fromhex(positive["cose_hex"]))
        self.assertEqual(verified, positive["manifest"])

    def test_vec_006_payload_substitution(self):
        self.assert_case_category("payload_substitution")

    def test_vec_007_protected_header_substitution(self):
        self.assert_case_category("protected_header_substitution")
        self.assert_case_category("unsupported_mandatory_field")

    def test_vec_008_missing_signatures(self):
        self.assert_case_category("missing_ed25519_signature")
        self.assert_case_category("missing_ml_dsa_65_signature")

    def test_vec_009_duplicate_signature(self):
        self.assert_case_category("duplicate_signature_component")

    def test_vec_010_algorithm_binding(self):
        self.assert_case_category("unknown_mandatory_algorithm")
        self.assert_case_category("algorithm_substitution")
        self.assert_case_category("algorithm_mismatch")

    def test_vec_011_key_binding(self):
        self.assert_case_category("wrong_key_identifier")
        self.assert_case_category("wrong_public_key_descriptor")
        self.assert_case_category("wrong_sha256_key_binding")

    def test_vec_012_malformed_and_signature_failures(self):
        for case_class in (
            "malformed_cbor",
            "truncated_cbor",
            "noncanonical_cbor",
            "duplicate_key",
            "invalid_ed25519_signature",
            "invalid_ml_dsa_65_signature",
        ):
            with self.subTest(case_class=case_class):
                self.assert_case_category(case_class)

    def test_vec_013_cross_language_inventory(self):
        results = vector_generator.self_test(self.corpus)
        self.assertEqual(len(results), 19)
        self.assertEqual(results["positive-hybrid-envelope-v1"], "valid")
        self.assertEqual(set(results), {self.corpus["positive"]["id"]} | {case["id"] for case in self.corpus["negative"]})
        self.assertEqual(self.corpus["profile"], "A2-COSE-04")
        self.assertEqual(self.corpus["provenance"]["network_input"], False)
        self.assertEqual(self.corpus["provenance"]["random_input"], False)
        self.assertEqual(self.corpus["provenance"]["timestamp_input"], False)


if __name__ == "__main__":
    unittest.main()
