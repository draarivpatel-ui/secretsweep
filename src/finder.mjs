// Finding engine: applies detectors, removes duplicates and placeholder
// matches, honours inline suppression and produces safe, redacted reports.

import { detectors } from './detectors/index.mjs';
import { fingerprint, maskValue, isPlaceholder } from './util.mjs';

const INLINE_IGNORE = /#\s*secretsweep:ignore\b|\/\/\s*secretsweep:ignore\b|\/\*\s*secretsweep:ignore\s*\*\//;

// Build the newline index once per scan so line/column lookup and inline
// suppression are O(log n) per hit instead of O(offset) per hit.
function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

function lineStartAt(starts, index) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

// A hidden continuation inside a leading comment, e.g.
//   // secretsweep:ignore
//   const key = 'ghp_...'
// is deliberately NOT honoured: only a suppression on the same line applies.
function isIgnoredLine(text, index, starts, lineIndex) {
  const lineStart = starts[lineIndex];
  let lineEnd = text.indexOf('\n', index);
  if (lineEnd === -1) lineEnd = text.length;
  return INLINE_IGNORE.test(text.slice(lineStart, lineEnd));
}

export function scanText(text, options = {}) {
  if (typeof text !== 'string') throw new TypeError('scanText expects a string');
  const enabled = new Set(options.detectors || detectors.map((d) => d.id));
  const minSeverity = options.minSeverity || null;
  const severityRank = { low: 0, medium: 1, high: 2, critical: 3 };
  const allowPlaceholder = options.allowPlaceholder === true;
  const findings = [];
  const starts = lineStarts(text);

  for (const detector of detectors) {
    if (!enabled.has(detector.id)) continue;
    if (minSeverity && severityRank[detector.severity] < severityRank[minSeverity]) continue;

    let hits = [];
    try {
      hits = detector.check(text) || [];
    } catch (error) {
      throw new Error(`detector ${detector.id} failed: ${error.message}`);
    }
    for (const hit of hits) {
      if (!hit || typeof hit.value !== 'string' || hit.value.length === 0) continue;
      const value = hit.value;
      const index = Number.isInteger(hit.index) ? hit.index : text.indexOf(value);
      if (index < 0) continue;
      if (!allowPlaceholder && isPlaceholder(value)) continue;
      const lineIndex = lineStartAt(starts, index);
      if (isIgnoredLine(text, index, starts, lineIndex)) continue;
      const line = lineIndex + 1;
      let column = 1;
      for (let i = starts[lineIndex]; i < index; i++) {
        if (text[i] !== '\r') column++;
      }
      findings.push({
        detector: detector.id,
        provider: detector.provider,
        name: detector.name,
        severity: detector.severity,
        line,
        column,
        redacted: maskValue(value),
        fingerprint: fingerprint(value),
      });
    }
  }

  // Deterministic ordering and de-duplication of the same secret found by
  // multiple overlapping detectors on the same line.
  findings.sort((a, b) => a.line - b.line || a.column - b.column ||
    a.detector.localeCompare(b.detector) || a.fingerprint.localeCompare(b.fingerprint));
  const seen = new Set();
  return findings.filter((finding) => {
    const key = `${finding.line}:${finding.column}:${finding.fingerprint}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
