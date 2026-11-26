// Every fake credential below is constructed at runtime so scanners never
// mistake these fixtures for live credentials.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { listDetectors, getDetector, registerDetector, createPatternDetector } from '../src/detectors/index.mjs';
import { scanText } from '../src/finder.mjs';

const A = (n) => 'A'.repeat(n);
const D = (n) => '0'.repeat(n);
const HEX = (n) => 'a'.repeat(n);
// Deterministic mixed-alphabet fixture with real entropy, built at runtime.
const R = (n) => Array.from({ length: n }, (_, i) =>
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[(i * 17 + 3) % 62]).join('');

function detect(id, text) {
  return scanText(text, { detectors: [id] });
}

describe('detector registry', () => {
  test('at least 25 detectors are registered', () => {
    assert.ok(listDetectors().length >= 25);
  });
  test('all detector ids are unique', () => {
    const ids = listDetectors().map((d) => d.id);
    assert.equal(new Set(ids).size, ids.length);
  });
  test('all detector ids are kebab-case', () => {
    for (const detector of listDetectors()) assert.match(detector.id, /^[a-z0-9][a-z0-9-]*$/);
  });
  test('getDetector returns a detector', () => {
    assert.ok(getDetector('github-pat'));
  });
  test('getDetector returns null for unknown id', () => {
    assert.equal(getDetector('not-a-detector'), null);
  });
  test('detector descriptors include severity', () => {
    for (const detector of listDetectors()) assert.ok(['low', 'medium', 'high', 'critical'].includes(detector.severity));
  });
  test('duplicate ids are rejected', () => {
    assert.throws(() => registerDetector({ id: 'github-pat', check: () => [] }), /duplicate/);
  });
  test('invalid ids are rejected', () => {
    assert.throws(() => registerDetector({ id: 'Bad ID', check: () => [] }), /invalid detector id/);
  });
  test('missing check function is rejected', () => {
    assert.throws(() => registerDetector({ id: 'no-check' }), /no check function/);
  });
  test('unsafe custom pattern is rejected', () => {
    assert.throws(() => createPatternDetector({ id: 'unsafe', pattern: /([a-z]+)+/ }), /not linear-time safe/);
  });
  test('custom detector can be registered and used', () => {
    const detector = createPatternDetector({ id: 'custom-provider', provider: 'Custom', pattern: /\bCUSTOM-[A-Z0-9]{8}\b/g });
    assert.equal(detector.id, 'custom-provider');
    const findings = detect('custom-provider', 'CUSTOM-12345678');
    assert.equal(findings.length, 1);
  });
});

describe('provider detectors', () => {
  const cases = [
    ['aws-access-key-id', 'AKIA' + A(16)],
    ['github-pat', 'ghp_' + A(36)],
    ['github-fine-grained-pat', 'github_pat_' + A(40)],
    ['github-oauth-token', 'gho_' + A(36)],
    ['stripe-secret-key', 'sk_live_' + A(24)],
    ['stripe-restricted-key', 'rk_live_' + A(24)],
    ['stripe-publishable-key', 'pk_test_' + A(24)],
    ['slack-webhook', 'https://hooks.slack.com/services/' + A(30)],
    ['slack-token', 'xoxb-' + A(24)],
    ['google-api-key', 'AIza' + A(35)],
    ['google-oauth-client-secret', 'GOCSPX-' + A(28)],
    ['google-refresh-token', '1//0' + A(40)],
    ['openai-api-key', 'sk-proj-' + A(30)],
    ['anthropic-api-key', 'sk-ant-' + A(30)],
    ['huggingface-token', 'hf_' + A(32)],
    ['npm-token', 'npm_' + A(36)],
    ['pypi-token', 'pypi-' + A(40)],
    ['docker-token', 'dckr_pat_' + A(28)],
    ['twilio-api-key', 'SK' + HEX(32)],
    ['sendgrid-api-key', 'SG.' + A(20) + '.' + A(24)],
    ['mailgun-api-key', 'key-' + HEX(32)],
    ['mailchimp-api-key', HEX(32) + '-us12'],
    ['square-access-token', 'sq0atp-' + A(24)],
    ['sonarqube-token', 'squ_' + A(40)],
    ['jwt-in-config', 'eyJ' + A(20) + '.' + A(20) + '.' + A(20)],
    ['telegram-bot-token', '123456789:' + A(35)],
    ['discord-bot-token', A(24) + '.' + A(6) + '.' + A(30)],
  ];
  for (const [id, value] of cases) {
    test(`${id} detects a synthetic token`, () => {
      const findings = detect(id, `const token = '${value}';`);
      assert.equal(findings.length, 1, `expected a finding for ${id}`);
      assert.equal(findings[0].detector, id);
      assert.equal(findings[0].severity, getDetector(id).severity);
    });
  }

  test('aws secret access key is detected by assignment', () => {
    const value = R(40);
    const findings = detect('aws-secret-access-key', `aws_secret_access_key = "${value}"`);
    assert.equal(findings.length, 1);
  });
  test('database URI with password is detected', () => {
    const findings = detect('db-uri-password', 'postgres://admin:sup3rs3cr3t@db.example.internal:5432/app');
    assert.equal(findings.length, 1);
  });
  test('database URI without password is ignored', () => {
    assert.equal(detect('db-uri-password', 'postgres://db.example.internal:5432/app').length, 0);
  });
  test('datadog key is detected', () => {
    const findings = detect('datadog-api-key', 'ddapikey: ' + '0123456789abcdef'.repeat(2));
    assert.equal(findings.length, 1);
  });
  test('new relic license key is detected', () => {
    const findings = detect('new-relic-license-key', 'license_key: ' + R(32));
    assert.equal(findings.length, 1);
  });
  test('PEM private key is detected', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\n' + A(64) + '\n-----END RSA PRIVATE KEY-----';
    const findings = detect('pem-private-key', pem);
    assert.equal(findings.length, 1);
  });
  test('PEM public key is not detected', () => {
    const pem = '-----BEGIN PUBLIC KEY-----\n' + A(64) + '\n-----END PUBLIC KEY-----';
    assert.equal(detect('pem-private-key', pem).length, 0);
  });
  test('high entropy generic assignment is detected', () => {
    const findings = detect('generic-secret-assignment', 'api_key = "' + R(36) + '"');
    assert.ok(findings.length >= 1);
  });
  test('low entropy assignment is ignored', () => {
    assert.equal(detect('generic-secret-assignment', 'api_key = "aaaaaaaaaaaaaaaa"').length, 0);
  });
  test('placeholder assignment is ignored', () => {
    assert.equal(detect('generic-secret-assignment', 'api_key = "YOUR_API_KEY"').length, 0);
  });
  test('generic entropy detector reports values next to assignments', () => {
    const findings = detect('high-entropy-generic', 'secret="' + R(36) + '"');
    assert.equal(findings.length, 1);
  });
  test('detection is case sensitive for provider prefixes', () => {
    assert.equal(detect('github-pat', 'GHP_' + A(36)).length, 0);
  });
});

describe('detector output safety', () => {
  test('findings never include the raw value', () => {
    const value = 'ghp_' + A(36);
    const finding = detect('github-pat', value)[0];
    assert.ok(!JSON.stringify(finding).includes(value));
  });
  test('findings include a sha256 fingerprint', () => {
    const finding = detect('github-pat', 'ghp_' + A(36))[0];
    assert.match(finding.fingerprint, /^[0-9a-f]{64}$/);
  });
  test('findings include line and column', () => {
    const finding = detect('github-pat', '\n\n  ghp_' + A(36))[0];
    assert.equal(finding.line, 3);
    assert.ok(finding.column >= 3);
  });
  test('multiple tokens are found in one text', () => {
    const value = 'ghp_' + A(36);
    assert.equal(detect('github-pat', `${value}\n${value}`).length, 2);
  });
});
