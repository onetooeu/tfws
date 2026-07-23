const KNOWN_REQUIRED = new Set([
  "core.v1",
  "identity.v1",
  "recovery.v1",
  "transparency.v1",
]);
const BASELINE = ["ed25519", "ml-dsa-65"];

function fail(message) {
  throw new Error(message);
}

export function validateManifestShape(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    fail("manifest must be an object");
  }
  if (manifest.tfws_version !== "3.0") {
    fail("unsupported TFWS version");
  }
  let subject;
  try {
    subject = new URL(String(manifest.subject));
  } catch {
    fail("invalid subject");
  }
  if (
    subject.protocol !== "https:" ||
    subject.username ||
    subject.password ||
    subject.pathname !== "/" ||
    subject.search ||
    subject.hash
  ) {
    fail("subject must be an HTTPS origin");
  }
  const algorithms = manifest.signature_policy?.required_algorithms;
  if (
    !Array.isArray(algorithms) ||
    algorithms.length !== BASELINE.length ||
    algorithms.some((algorithm, index) => algorithm !== BASELINE[index])
  ) {
    fail("hybrid downgrade");
  }
  const requiredCapabilities = manifest.capabilities?.required;
  if (!Array.isArray(requiredCapabilities)) {
    fail("mandatory capabilities must be an array");
  }
  for (const capability of requiredCapabilities) {
    if (!KNOWN_REQUIRED.has(capability)) {
      fail(`unknown mandatory capability: ${capability}`);
    }
  }
  if (!Array.isArray(manifest.keys)) {
    fail("keys must be an array");
  }
  if (manifest.environment !== "development" && manifest.keys.length !== 2) {
    fail("non-development manifests require two bound keys");
  }
  return true;
}

export function verificationSummary(result) {
  return {
    technical_integrity: result.valid ? "verified" : "failed",
    content_truthfulness: "not_assessed",
  };
}
