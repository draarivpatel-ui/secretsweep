import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { scanText } from '../src/finder.mjs';
import { listDetectors, getDetector } from '../src/detectors/index.mjs';
import { analyzePattern } from '../src/util.mjs';

describe('ReDoS safety', () => {
  test('every built-in detector pattern is lint-clean', () => {
    for (const detector of listDetectors()) {
      const full = getDetector(detector.id);
      if (full.pattern) {
        const report = analyzePattern(full.pattern);
        assert.equal(report.safe, true, `${detector.id}: ${report.reasons.join(', ')}`);
      }
    }
  });
  test('analyzePattern rejects a nested repeat', () => {
    assert.equal(analyzePattern(/([a-z]+)+$/).safe, false);
  });
  test('analyzePattern accepts a bounded token pattern', () => {
    assert.equal(analyzePattern(/\bAKIA[A-Z0-9]{16}\b/).safe, true);
  });
  test('long non-matching input scans quickly', () => {
    const input = 'a'.repeat(200000);
    const started = performance.now();
    scanText(input);
    const elapsed = performance.now() - started;
    assert.ok(elapsed < 5000, `scan took ${elapsed.toFixed(0)} ms`);
  });
  test('long near-miss token does not blow up', () => {
    const input = 'ghp_' + 'a'.repeat(200000);
    const started = performance.now();
    scanText(input);
    const elapsed = performance.now() - started;
    assert.ok(elapsed < 5000, `scan took ${elapsed.toFixed(0)} ms`);
  });
  test('repeated braces do not hang', () => {
    const input = '{'.repeat(50000);
    const started = performance.now();
    scanText(input);
    assert.ok(performance.now() - started < 5000);
  });
  test('many newlines are handled', () => {
    const input = '\n'.repeat(50000) + 'ghp_' + 'A'.repeat(36);
    assert.equal(scanText(input).length, 1);
  });
  test('many candidate assignments remain linear', () => {
    const input = Array.from({ length: 5000 }, (_, i) => `api_key_${i}=${'x'.repeat(40)}`).join('\n');
    const started = performance.now();
    scanText(input);
    assert.ok(performance.now() - started < 8000);
  });
  test('PEM-like unterminated header is linear', () => {
    const input = '-----BEGIN RSA PRIVATE KEY-----\n' + 'A'.repeat(100000);
    const started = performance.now();
    scanText(input);
    assert.ok(performance.now() - started < 5000);
  });
  test('repeated unterminated PEM headers do not cause quadratic scans', () => {
    const marker = '-----BEGIN RSA PRIVATE KEY-----';
    const input = marker.repeat(Math.ceil(400000 / marker.length));
    const started = performance.now();
    scanText(input);
    assert.ok(performance.now() - started < 5000);
  });
  test('database URI pattern stays linear on scheme-like word boundaries', () => {
    const build = (length) => ('eyJ' + 'A'.repeat(100) + '.')
      .repeat(Math.ceil(length / 104)).slice(0, length);
    const time = (input) => {
      let best = Infinity;
      for (let round = 0; round < 2; round++) {
        const started = performance.now();
        scanText(input, { detectors: ['db-uri-password'] });
        best = Math.min(best, performance.now() - started);
      }
      return best;
    };
    const small = time(build(20000));
    const large = time(build(80000));
    assert.ok(large < small * 8 + 30, `4x input took ${large.toFixed(1)} ms versus ${small.toFixed(1)} ms`);
  });
  test('large binary-ish text does not crash', () => {
    const input = 'A'.repeat(100000) + '\n' + 'ghp_' + 'A'.repeat(36);
    assert.equal(scanText(input).length, 1);
  });
  test('dense findings on one long line scale linearly', () => {
    const build = (count) => {
      const separator = ' ' + 'x'.repeat(180) + ' ';
      return Array.from({ length: count }, (_, i) =>
        'ghp_' + String.fromCharCode(65 + (i % 26)) + 'B'.repeat(35)).join(separator);
    };
    const time = (input) => {
      let best = Infinity;
      for (let round = 0; round < 2; round++) {
        const started = performance.now();
        scanText(input, { detectors: ['github-pat'] });
        best = Math.min(best, performance.now() - started);
      }
      return best;
    };
    const small = time(build(250));
    const large = time(build(1000));
    assert.ok(large < small * 8 + 30, `4x input took ${large.toFixed(1)} ms versus ${small.toFixed(1)} ms`);
  });
  test('adversarial detector inputs remain within the performance budget', () => {
    const cases = [
      'api_key='.repeat(12000),
      '"'.repeat(120000),
      'postgres://user:' + 'a'.repeat(120000),
      '-----BEGIN RSA PRIVATE KEY-----\n' + 'A'.repeat(120000),
      ('ghp_' + 'A'.repeat(32) + ' ').repeat(1500),
      'A1b2C3d4'.repeat(15000),
    ];
    for (const input of cases) {
      const started = performance.now();
      scanText(input);
      assert.ok(performance.now() - started < 5000, `case length ${input.length} timed out`);
    }
  });
});
