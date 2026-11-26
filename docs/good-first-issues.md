# Good first issues

These are starter tasks for new contributors. Each should fit in a single pull request. Comment on the issue before starting so work is not duplicated.

### 1. Add a GitLab personal access token detector

Add a detector for the `glpat-` prefix with a bounded pattern and a positive and negative test.

### 2. Add a DigitalOcean access token detector

Support the `dop_v1_` prefix. Follow the five minute guide in CONTRIBUTING.md.

### 3. Add a Hugging Face refresh token detector

Distinguish refresh tokens from the existing access token detector.

### 4. Detect Jenkins API tokens

Match the common Jenkins user plus API token assignment form. Add a test that ignores placeholder values.

### 5. Improve PEM fingerprint stability

Ensure two identical keys with different line endings produce the same fingerprint.

### 6. Add a `.secretsweepignore` documentation example

Add a short example file section to the README showing common ignore patterns.

### 7. Add a `--min-severity` alias

Accept `--min-severity` as an alias for `--severity` in the CLI parser, with a test.

### 8. Report skip reasons in text output

Add a `--show-skipped` flag that appends skipped paths to the text report.

### 9. Add a SARIF `helpUri` per rule

Point each generated rule at a documentation anchor for that provider.

### 10. Support `${VAR}` placeholder values

Expand the placeholder allowlist to cover common shell interpolation forms.

### 11. Add a test for Windows CRLF ignore files

Prove that `.gitignore` and `.secretsweepignore` parse with CRLF endings.

### 12. Add a detector for Firebase service account files

Detect the service account JSON shape without matching a generic JSON object.

### 13. Add a detector for SQLite database URIs with passwords

Extend the existing database URI detector to cover the sqlite variant.

### 14. Add an `--only-file` CLI filter

Allow scanning a single relative path inside a directory scan.

### 15. Add a JSON baseline schema description

Document the baseline file format in the README.

### 16. Add a test for Unicode separators in entropy values

Verify that Shannon entropy handles non-ASCII characters consistently.

### 17. Add a detector for Vercel tokens

Use a bounded character-class pattern and add a negative test for a short value.

### 18. Add a detector for Fly.io tokens

Support the `FlyV1` token prefix. Keep the pattern linear-time.

### 19. Add a detector for Render API keys

Match the provider prefix and add a placeholder test.

### 20. Add a contributor video walkthrough script

Write a short script outline for adding a detector, linking to the five minute guide.

### 21. Add a benchmark for large monorepo scans

Create a script under `scripts/` that generates synthetic files and times `scanPath`.

### 22. Improve diff hunk header parsing

Handle hunk headers with no comma count, such as `@@ -1 +1 @@`.
