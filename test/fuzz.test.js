import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import { scanText } from '../src/index.mjs';

const ALPHA_NUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const TOKEN_ALPHABET = ALPHA_NUM;

function mixedTokenBody(length) {
  return fc.array(fc.integer({ min: 0, max: TOKEN_ALPHABET.length - 1 }), { minLength: length, maxLength: length })
    .map((indexes) => indexes.map((value, index) => TOKEN_ALPHABET[(value + index * 17) % TOKEN_ALPHABET.length]).join(''));
}

const benignWords = fc.array(
  fc.constantFrom('ordinary', 'application', 'log', 'message', 'user', 'completed', 'checkout', 'without', 'credentials'),
  { minLength: 2, maxLength: 10 }
).map((words) => words.join(' '));

test('positive: benign prose produces no secret findings', () => {
  fc.assert(fc.property(benignWords, (input) => {
    assert.deepEqual(scanText(input), []);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: synthetic GitHub tokens are detected and never reported raw', () => {
  fc.assert(fc.property(mixedTokenBody(36), (body) => {
    const token = 'ghp_' + body;
    const findings = scanText('const token = "' + token + '";', { detectors: ['github-pat'] });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].detector, 'github-pat');
    assert.match(findings[0].fingerprint, /^[0-9a-f]{64}$/);
    assert.equal(JSON.stringify(findings[0]).includes(token), false);
    assert.notEqual(findings[0].redacted, token);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: inline suppression neutralizes only the marked detector finding', () => {
  fc.assert(fc.property(mixedTokenBody(36), (body) => {
    const token = 'ghp_' + body;
    const suppressed = scanText('const token = "' + token + '"; // secretsweep:ignore github-pat', { detectors: ['github-pat'] });
    assert.deepEqual(suppressed, []);
    const otherDetector = scanText('const token = "' + token + '"; // secretsweep:ignore github-pat');
    assert.equal(otherDetector.some((finding) => finding.detector === 'github-pat'), false);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: malformed and hostile text never crashes the scanner or leaks raw values', () => {
  const mutation = fc.constantFrom('\u0000', '\n\n', '\r\n', '\u2028', '%', '\\\\', '\u001b[31m', 'secretsweep:ignore');
  fc.assert(fc.property(fc.string({ maxLength: 100 }), mutation, fc.string({ maxLength: 100 }), (before, hostile, after) => {
    const input = before + hostile + after;
    const findings = scanText(input);
    assert.equal(Array.isArray(findings), true);
    for (const finding of findings) {
      assert.match(finding.fingerprint, /^[0-9a-f]{64}$/);
      assert.equal(typeof finding.redacted, 'string');
      assert.equal(Object.hasOwn(finding, 'value'), false);
    }
  }), { seed: 20261127, numRuns: 120 });
});
