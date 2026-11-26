import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  fingerprint, maskValue, shannonEntropy, isPlaceholder, analyzePattern,
} from '../src/util.mjs';

describe('fingerprint', () => {
  test('returns 64 hex characters', () => {
    assert.match(fingerprint('value'), /^[0-9a-f]{64}$/);
  });
  test('is deterministic', () => {
    assert.equal(fingerprint('abc'), fingerprint('abc'));
  });
  test('distinguishes different inputs', () => {
    assert.notEqual(fingerprint('abc'), fingerprint('abd'));
  });
  test('handles empty string', () => {
    assert.match(fingerprint(''), /^[0-9a-f]{64}$/);
  });
  test('handles unicode', () => {
    assert.match(fingerprint('token-é'), /^[0-9a-f]{64}$/);
  });
  test('accepts numbers via coercion', () => {
    assert.equal(fingerprint(123), fingerprint('123'));
  });
  test('does not reveal input prefix', () => {
    const fp = fingerprint('super-secret-value');
    assert.ok(!fp.includes('super'));
  });
});

describe('maskValue', () => {
  test('short values are fully masked', () => {
    assert.equal(maskValue('abc'), '***');
  });
  test('empty value produces empty mask', () => {
    assert.equal(maskValue(''), '');
  });
  test('12 char value is fully masked', () => {
    assert.equal(maskValue('123456789012'), '************');
  });
  test('long value keeps first and last four characters', () => {
    const result = maskValue('ABCDEFGHIJKLMNOPQRST');
    assert.equal(result.slice(0, 4), 'ABCD');
    assert.equal(result.slice(-4), 'QRST');
  });
  test('middle mask never exceeds 12 stars', () => {
    assert.ok(maskValue('X'.repeat(100)).length <= 20);
  });
  test('masked output cannot equal the original for long values', () => {
    const value = 'abcdefghijklmnop';
    assert.notEqual(maskValue(value), value);
  });
  test('does not expose more than 8 original characters', () => {
    const masked = maskValue('0123456789abcdef');
    const revealed = [...masked].filter((c) => c !== '*').length;
    assert.ok(revealed <= 8);
  });
});

describe('shannonEntropy', () => {
  test('empty string has zero entropy', () => {
    assert.equal(shannonEntropy(''), 0);
  });
  test('single character has zero entropy', () => {
    assert.equal(shannonEntropy('aaaa'), 0);
  });
  test('two-symbol alternating string has one bit', () => {
    assert.equal(shannonEntropy('abababab'), 1);
  });
  test('higher diversity increases entropy', () => {
    assert.ok(shannonEntropy('abcdefghijklmnop') > shannonEntropy('aaaaaaaaaaaaaaaa'));
  });
  test('entropy is bounded by log2 of alphabet size', () => {
    assert.ok(shannonEntropy('0123456789abcdef') <= 4.01);
  });
  test('handles unicode strings', () => {
    assert.ok(shannonEntropy('éèê') > 0);
  });
  test('is case sensitive', () => {
    assert.ok(shannonEntropy('AaAa') > 0);
  });
});

describe('isPlaceholder', () => {
  test('empty string is a placeholder', () => assert.equal(isPlaceholder(''), true));
  test('EXAMPLE is a placeholder', () => assert.equal(isPlaceholder('EXAMPLE'), true));
  test('YOUR_API_KEY is a placeholder', () => assert.equal(isPlaceholder('YOUR_API_KEY'), true));
  test('changeme is a placeholder', () => assert.equal(isPlaceholder('changeme'), true));
  test('repeated characters are placeholders', () => assert.equal(isPlaceholder('AAAAAAAA'), true));
  test('dictionary word sequences are placeholders', () => assert.equal(isPlaceholder('your secret here'), true));
  test('angle bracket templates are placeholders', () => assert.equal(isPlaceholder('<your-token>'), true));
  test('ellipsis templates are placeholders', () => assert.equal(isPlaceholder('api_key...'), true));
  test('realistic token is not a placeholder', () => {
    assert.equal(isPlaceholder('Kx8pQ2vLm9ZtR4wN7bYcF1sHjD6uAe'), false);
  });
  test('long random value is not a placeholder', () => {
    const value = Array.from({ length: 64 }, (_, i) => String.fromCharCode(65 + (i * 7) % 26)).join('');
    assert.equal(isPlaceholder(value), false);
  });
  test('very long values are treated as real', () => {
    assert.equal(isPlaceholder('A'.repeat(513)), false);
  });
  test('case insensitive detection', () => assert.equal(isPlaceholder('Your_API_Key'), true));
  test('dash separated placeholders detected', () => assert.equal(isPlaceholder('your-api-key'), true));
  test('placeholder suffix detected', () => assert.equal(isPlaceholder('MY_API_KEY_EXAMPLE'), true));
});

describe('analyzePattern lint', () => {
  test('accepts a simple bounded pattern', () => {
    assert.equal(analyzePattern(/[A-Za-z0-9]{16}/).safe, true);
  });
  test('accepts an alternation pattern', () => {
    assert.equal(analyzePattern(/(?:foo|bar)[0-9]+/).safe, true);
  });
  test('rejects backreferences', () => {
    assert.equal(analyzePattern(/(a)\1+/).safe, false);
  });
  test('rejects stacked quantifiers', () => {
    assert.equal(analyzePattern('a++').safe, false);
  });
  test('rejects repeated groups with repeats', () => {
    assert.equal(analyzePattern(/([a-z]+)+/).safe, false);
  });
  test('accepts a lazy bounded quantifier', () => {
    assert.equal(analyzePattern(/[\s\S]{1,2000}?END/).safe, true);
  });
  test('accepts anchors', () => {
    assert.equal(analyzePattern(/^abc$/).safe, true);
  });
  test('reasons are unique', () => {
    const result = analyzePattern('a++');
    assert.equal(new Set(result.reasons).size, result.reasons.length);
  });
});
