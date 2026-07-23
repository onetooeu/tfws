# Security policy

TFWS 3.0 is currently an engineering alpha. It is not a production
certification, and no version is represented as production-ready.

## Supported versions

| Version | Security status |
| --- | --- |
| `main` | Best-effort security fixes for the current engineering alpha |
| `3.0.0-alpha.x` | Best-effort fixes when the issue is reproducible on `main` |
| Older snapshots | Not supported |

Review `RELEASE-GATES.md` and `docs/IMPLEMENTATION-STATUS.md` before any
deployment. Unsupported capabilities must not be advertised as implemented.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use either of these private channels:

1. Open the repository's **Security** tab and select **Report a vulnerability**.
2. Email `security@onetoo.eu`.

Include:

- the affected component and commit or version,
- a clear impact assessment,
- safe reproduction steps,
- relevant logs or a minimal proof of concept,
- whether the issue is already public,
- a preferred contact method.

Do not include production secrets, private keys, personal data, or destructive
payloads.

## Response targets

These are targets, not contractual service-level guarantees:

- critical reports: acknowledgement target within 24 hours,
- other reports: acknowledgement target within 3 business days,
- status updates: as meaningful information becomes available.

The maintainer may request additional evidence, reject reports that are not
security issues, or coordinate a private fix and disclosure timeline.

## Coordinated disclosure

Please allow reasonable time to investigate and publish a fix before public
disclosure. Do not access data that is not yours, disrupt services, or use
social engineering.

Good-faith research that follows this policy will not be treated as hostile by
the project maintainer. This statement does not bind third parties and is not
legal advice.
