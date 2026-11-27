# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. [Report a vulnerability privately through GitHub](https://github.com/draarivpatel-ui/secretsweep/security/advisories/new).

Please include:

- A minimal reproduction that uses synthetic input only.
- The affected project version, commit or action ref, and Node.js version.
- The expected security boundary and the observed violation.
- Logs, output, or proof-of-concept code needed to reproduce the finding, with real secrets removed.

Never include a real token, cookie, password, private key, production log line or real personal data in a report.

Vulnerability handling steps:

1. The maintainer acknowledges the private report within 72 hours.
2. The maintainer reproduces the finding against the latest supported version and confirms severity within 14 days when enough information is available.
3. A fix is developed privately, with regression coverage where practical.
4. The maintainer coordinates the advisory, affected versions, reporter credit and disclosure date with the reporter.
5. The target coordinated disclosure window is 90 days or less from acknowledgment. If more time is needed, the maintainer and reporter agree on a new date before disclosure.

## Scope

secretsweep is a static analysis tool. It is designed to reduce the chance that a secret is committed, not to replace a secret manager or a server-side revocation process. A clean scan is not a proof that no credential has leaked.

Reports deliberately omit raw values. If you believe a report exposes too much information, please report it privately.

## Safe test fixtures

All test credentials are constructed dynamically in test code, for example `'ghp_' + 'A'.repeat(36)`. Please keep it that way: never add a literal that could be mistaken for a live credential, even if it is fake.

## Supported versions

The latest published major version receives security fixes.
