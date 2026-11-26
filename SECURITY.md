# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability. Use the repository's private vulnerability reporting channel, or contact the maintainers privately through the contact method listed on the repository profile page.

Include:

- A description of the issue and the affected version.
- A minimal reproduction that does not include a live credential.
- The impact you believe the issue has.

You should receive an acknowledgement within seven days. We will work on a fix and coordinate disclosure with you.

## Scope

secretsweep is a static analysis tool. It is designed to reduce the chance that a secret is committed, not to replace a secret manager or a server-side revocation process. A clean scan is not a proof that no credential has leaked.

Reports deliberately omit raw values. If you believe a report exposes too much information, please report it privately.

## Safe test fixtures

All test credentials are constructed dynamically in test code, for example `'ghp_' + 'A'.repeat(36)`. Please keep it that way: never add a literal that could be mistaken for a live credential, even if it is fake.

## Supported versions

The latest published major version receives security fixes.
