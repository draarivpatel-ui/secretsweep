# secretsweep

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/secretsweep/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/secretsweep)

A zero-dependency secret and PII scanner for source trees and git diffs. It ships as both a CLI and a library, emits text, JSON or SARIF 2.1.0, supports baseline suppression, and never prints a raw secret value in a report.

**359 tests**. Zero runtime dependencies. Zero dev dependencies. Node.js 18 or newer.

## Why another scanner

Most secret scanners pull in a dependency tree, print the token they just found into CI logs, or choke on a large monorepo. secretsweep takes a different approach:

- No dependencies at all. Install size is the source code.
- Reports contain a masked preview and a SHA-256 fingerprint only.
- 32 provider detectors plus high-entropy generic rules.
- Linear-time patterns. A ReDoS lint validates every detector at registration.
- Deterministic output and exit codes, so diffs of reports are stable.

## Install

```sh
npm install --save-dev @aarivbuildz/secretsweep
```

Or run it without installing:

```sh
npx secretsweep .
```

## CLI usage

```sh
secretsweep [options] [path ...]
secretsweep [options] --diff
secretsweep [options] --stdin
```

Common options:

| Option | Meaning |
| --- | --- |
| `--format text|json|sarif` | Choose the output format. |
| `--diff` | Read a unified git diff from standard input. |
| `--stdin` | Scan standard input as plain text. |
| `--baseline <file>` | Suppress findings already recorded in the baseline. |
| `--write-baseline <file>` | Write current findings as a baseline and exit 0. |
| `--detectors <ids>` | Comma separated list of detector ids. |
| `--severity <level>` | Minimum severity: low, medium, high or critical. |
| `--max-file-bytes <n>` | Skip files larger than this many bytes. |
| `--exclude <pattern>` | Exclude a path prefix. Repeatable. |
| `--list-detectors` | Print all detector ids. |

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | No findings, or a baseline was written. |
| 1 | At least one finding. |
| 2 | Invalid usage or an input error. |

Examples:

```sh
# Scan a repository
secretsweep .

# Gate on a pull request diff
git diff origin/main...HEAD | secretsweep --diff --format sarif > results.sarif

# Accept known findings once, then fail only on new ones
secretsweep --write-baseline .secretsweep-baseline.json .
secretsweep --baseline .secretsweep-baseline.json .
```

Add an inline comment to suppress a single line:

```js
const token = process.env.API_TOKEN; // secretsweep:ignore
```

The plain form suppresses every detector on that line. Name one or more detector ids after the marker to suppress only those detectors:

```js
const token = process.env.API_TOKEN; // secretsweep:ignore github-pat,aws-access-key-id
```

## Library usage

```js
import { scanText, scanPath, scanDiff, formatSarif } from '@aarivbuildz/secretsweep';

const findings = scanText('const token = "ghp_..."');
console.log(findings[0].redacted, findings[0].fingerprint);

const { findings: inTree, skipped } = scanPath('.');
process.stdout.write(formatSarif(inTree));
```

CommonJS works too:

```js
const { scanText } = require('@aarivbuildz/secretsweep');
```

## Detectors

Run `secretsweep --list-detectors` for the exact ids. Built-in families include:

- Cloud and infrastructure: AWS, Google Cloud, Datadog, New Relic, SonarQube.
- Source control and CI: GitHub, GitLab-style tokens, npm, PyPI, Docker Hub.
- Payments and messaging: Stripe, Square, Twilio, SendGrid, Mailgun, Mailchimp, Slack, Discord, Telegram.
- AI providers: OpenAI, Anthropic, Hugging Face.
- Data at rest: PEM private keys, database URIs with passwords, JWTs in configuration.
- Generic: labelled high-entropy assignments and unlabelled high-entropy tokens.

Placeholder values such as `EXAMPLE`, `YOUR_API_KEY` and `changeme` are ignored by default.

## Ignoring files

secretsweep reads `.gitignore` and `.secretsweepignore` at the scan root, including glob patterns, anchored patterns and negations. Ignore files larger than 1 MiB are rejected rather than loaded without a bound. It always skips `.git/`, `node_modules/`, common build directories and files whose bytes look binary, including NUL bytes and dense control characters. File extensions alone never hide otherwise readable text from the scanner. Symlink loops are detected and reported in the skip list, and symlinks resolving outside the scan root are not followed.

## Contributing

New detectors are welcome and are usually a five minute change. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [good first issues](docs/good-first-issues.md).

## Security

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
