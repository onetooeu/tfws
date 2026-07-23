import assert from "node:assert/strict";
import test from "node:test";
import { validateManifestShape, verificationSummary } from "../src/index.mjs";

const base = {
  tfws_version: "3.0",
  subject: "https://example.com",
  environment: "development",
  keys: [],
  signature_policy: {
    required_algorithms: ["ed25519", "ml-dsa-65"],
  },
  capabilities: { required: ["core.v1"] },
};

test("baseline validates", () => assert.equal(validateManifestShape(base), true));
test("downgrade fails", () =>
  assert.throws(() =>
    validateManifestShape({
      ...base,
      signature_policy: { required_algorithms: ["ed25519"] },
    })
  ));
test("unknown mandatory capability fails", () =>
  assert.throws(() =>
    validateManifestShape({
      ...base,
      capabilities: { required: ["unknown.v1"] },
    })
  ));
test("production requires bound keys", () =>
  assert.throws(() => validateManifestShape({ ...base, environment: "production" })));
test("truth is not assessed", () =>
  assert.equal(
    verificationSummary({ valid: true }).content_truthfulness,
    "not_assessed"
  ));
