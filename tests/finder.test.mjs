import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { scanText } from '../src/finder.mjs';

const GITHUB = () => 'ghp_' + 'A'.repeat(36);
const AWS = () => 'AKIA' + '0'.repeat(16);

describe('scanText', () => {
  test('rejects non-string input', () => {
    assert.throws(() => scanText(123), /expects a string/);
  });
  test('returns an empty array for safe text', () => {
    assert.deepEqual(scanText('const answer = 42;'), []);
  });
  test('finds a GitHub token', () => {
    assert.equal(scanText(`token = "${GITHUB()}"`).length, 1);
  });
  test('finds an AWS key', () => {
    assert.equal(scanText(`key = "${AWS()}"`).length, 1);
  });
  test('detector filter restricts which detectors run', () => {
    const text = `a = "${GITHUB()}"\nb = "${AWS()}"`;
    const findings = scanText(text, { detectors: ['github-pat'] });
    assert.ok(findings.every((f) => f.detector === 'github-pat'));
  });
  test('empty detector list finds nothing', () => {
    assert.equal(scanText(GITHUB(), { detectors: [] }).length, 0);
  });
  test('unknown detector ids are ignored', () => {
    assert.equal(scanText(GITHUB(), { detectors: ['bogus'] }).length, 0);
  });
  test('severity filter works', () => {
    const findings = scanText(GITHUB(), { minSeverity: 'critical' });
    assert.equal(findings.length, 0);
  });
  test('severity filter includes matching severity', () => {
    const findings = scanText(GITHUB(), { minSeverity: 'high' });
    assert.ok(findings.length >= 1);
  });
  test('inline hash ignore suppresses a finding', () => {
    const text = `const token = "${GITHUB()}"; # secretsweep:ignore`;
    assert.equal(scanText(text).length, 0);
  });
  test('inline slash ignore suppresses a finding', () => {
    const text = `const token = "${GITHUB()}"; // secretsweep:ignore`;
    assert.equal(scanText(text).length, 0);
  });
  test('inline ignore does not suppress other lines', () => {
    const text = `# secretsweep:ignore\n${GITHUB()}`;
    assert.equal(scanText(text).length, 1);
  });
  test('rule-scoped ignore suppresses the named detector', () => {
    const text = `${GITHUB()} # secretsweep:ignore github-pat`;
    assert.equal(scanText(text, { detectors: ['github-pat'] }).length, 0);
  });
  test('rule-scoped ignore does not suppress a different detector', () => {
    const text = `${GITHUB()} # secretsweep:ignore aws-access-key-id`;
    assert.equal(scanText(text, { detectors: ['github-pat'] }).length, 1);
  });
  test('rule-scoped ignore accepts comma separated detector ids', () => {
    const text = `${GITHUB()} # secretsweep:ignore aws-access-key-id,github-pat`;
    assert.equal(scanText(text, { detectors: ['github-pat'] }).length, 0);
  });
  test('placeholder values are ignored by default', () => {
    assert.equal(scanText('api_key = "YOUR_API_KEY"').length, 0);
  });
  test('allowPlaceholder option surfaces placeholders', () => {
    assert.ok(scanText('api_key = "YOUR_API_KEY"', { allowPlaceholder: true }).length >= 1);
  });
  test('findings are sorted by position', () => {
    const text = `${AWS()}\n${GITHUB()}`;
    const findings = scanText(text);
    assert.ok(findings[0].line <= findings[1].line);
  });
  test('same secret found by overlapping detectors is deduplicated', () => {
    const text = `sk-ant-${'A'.repeat(40)}`;
    const findings = scanText(text, { detectors: ['anthropic-api-key', 'openai-api-key'] });
    assert.equal(new Set(findings.map((f) => f.fingerprint)).size, findings.length);
  });
  test('findings have all required fields', () => {
    const finding = scanText(GITHUB())[0];
    for (const key of ['detector', 'provider', 'name', 'severity', 'line', 'column', 'redacted', 'fingerprint']) {
      assert.ok(key in finding, `missing ${key}`);
    }
  });
  test('handles CRLF line endings', () => {
    const finding = scanText(`a\r\nb\r\n${GITHUB()}`)[0];
    assert.equal(finding.line, 3);
  });
  test('handles very long lines', () => {
    const text = ' '.repeat(5000) + GITHUB();
    assert.equal(scanText(text).length, 1);
  });
  test('handles empty text', () => {
    assert.deepEqual(scanText(''), []);
  });
  test('redacted value never contains a long run of the secret', () => {
    const value = GITHUB();
    const finding = scanText(value)[0];
    assert.ok(!finding.redacted.includes(value.slice(4, 16)));
  });
  test('a late secret is not hidden behind a flood of duplicate matches', () => {
    const finalToken = 'ghp_' + 'B'.repeat(36);
    const input = Array.from({ length: 1000 }, () => GITHUB()).concat([finalToken]).join('\n');
    const findings = scanText(input, { detectors: ['github-pat'] });
    assert.ok(findings.some((finding) => finding.redacted.endsWith('BBBB')));
  });
});
