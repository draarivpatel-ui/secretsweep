// secretsweep utilities: deterministic fingerprinting, safe masking, entropy,
// placeholder detection and a small lint that keeps detector patterns linear.

import { createHash } from 'node:crypto';

export const VERSION = '1.0.0';

export function fingerprint(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex');
}

export function maskValue(value) {
  const text = String(value);
  if (text.length <= 16) return '*'.repeat(text.length);
  if (text.length < 32) {
    return text.slice(0, 2) + '*'.repeat(Math.min(12, text.length - 4)) + text.slice(-2);
  }
  return text.slice(0, 4) + '*'.repeat(Math.min(12, text.length - 8)) + text.slice(-4);
}

export function shannonEntropy(value) {
  const text = String(value);
  if (text.length === 0) return 0;
  const counts = new Map();
  for (const char of text) counts.set(char, (counts.get(char) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const PLACEHOLDER_WORDS = [
  'example', 'sample', 'placeholder', 'changeme', 'change_me', 'change-me',
  'yourapikey', 'yourapitoken', 'yourkey', 'yourtoken', 'yoursecret',
  'apikey', 'apitoken', 'accesskey', 'secretkey', 'dummy', 'fake', 'test',
  'testing', 'redacted', 'replace', 'replaceme', 'insert', 'here', 'none',
  'null', 'undefined', 'todo', 'tbd', 'xxxx', 'yyyy', 'zzzz', 'abcdef',
  'abc123', 'password', 'passwd', 'string', 'value', 'literal', 'notreal',
  'notarealkey', 'sanitized', 'masked', 'hidden', 'foo', 'bar', 'baz', 'qux',
];

function normalized(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, '');
}

export function isPlaceholder(value) {
  const text = String(value);
  if (text.length === 0) return true;
  // Long values are treated as real credentials without further scanning.
  // This also keeps assessment strictly linear and cheap on long inputs.
  if (text.length > 256) return false;

  const compact = normalized(text);
  if (compact.length === 0) return true;

  // Repeated single characters and simple sequences carry no information.
  if (/^(.)\1+$/.test(text)) return true;
  if (/^(?:0123456789|1234567890|abcdefghijklmnopqrstuvwxyz)+$/.test(compact)) return true;
  if (/^0+$/.test(compact)) return true;

  // Angle brackets, ellipses and template interpolation are documentation.
  if (/[<>{}]|\.\.\.|${{|\$\(/.test(text)) return true;

  for (const word of PLACEHOLDER_WORDS) {
    if (compact === word || compact.startsWith(word + 'key') || compact.endsWith('key' + word)) return true;
    if (compact.startsWith(word) && compact.length - word.length <= 4) return true;
  }

  // A value made only of short dictionary-like words is almost always prose.
  const words = text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  if (words.length >= 3 && words.every((word) => PLACEHOLDER_WORDS.includes(word))) return true;

  return false;
}

export function positionAt(text, offset) {
  let line = 1;
  let column = 1;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === '\n') {
      line++;
      column = 1;
    } else if (text[i] !== '\r') {
      column++;
    }
  }
  return { line, column };
}

// Reject detector patterns whose structure could backtrack superlinearly.
// Every shipped pattern uses bounded character classes and no nested repeats.
export function analyzePattern(pattern) {
  let source = pattern instanceof RegExp ? pattern.source : String(pattern);
  const reasons = [];

  if (/\\[1-9]/.test(source)) reasons.push('backreference');
  if (/\(\?<[=!][^)]*[+*{][^)]*\)/.test(source)) reasons.push('variable-length lookbehind');
  if (/(\*|\+|\{[^}]*\})\s*(\*|\+|\{[^}]*\})/.test(source)) reasons.push('stacked quantifiers');

  // A group that contains a repeat and is itself repeated is the classic
  // quadratic pattern: ([A-Za-z0-9]+)+. Scan group bodies with a shallow check.
  const nested = /\((?:\?:|\?=|\?!)?[^()]*?(?:\[[^\]]*\]|\\.)?[*+][^()]*?\)[*+{]/g;
  if (nested.test(source)) reasons.push('repeated group containing a repeat');

  // Strip character classes and escapes before checking for any remaining
  // unbounded repeat that follows an unbounded repeat.
  source = source.replace(/\[[^\]]*\]/g, 'A').replace(/\\./g, 'A');
  if (/(?:A|[)\w])\+[*+]/.test(source)) reasons.push('stacked quantifiers');

  return { safe: reasons.length === 0, reasons: [...new Set(reasons)] };
}

export function ensureLinear(pattern, id) {
  const report = analyzePattern(pattern);
  if (!report.safe) {
    throw new Error(`detector ${id} is not linear-time safe: ${report.reasons.join(', ')}`);
  }
  return pattern;
}
