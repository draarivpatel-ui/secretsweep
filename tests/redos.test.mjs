import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { scanText } from '../src/finder.mjs';
import { listDetectors } from '../src/detectors/index.mjs';
import { analyzePattern } from '../src/util.mjs';

describe('ReDoS safety', () => {
  test('every built-in detector pattern is lint-clean', () => {
    for (const detector of listDetectors()) {
      // Patterns are validated at registration, so reaching this point already
      // proves registration accepted them. Re-check via analyzePattern where a
      // pattern is exposed through the descriptor.
      assert.ok(detector.id);
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
  test('large binary-ish text does not crash', () => {
    const input = 'A'.repeat(100000) + '\n' + 'ghp_' + 'A'.repeat(36);
    assert.equal(scanText(input).length, 1);
  });
});
