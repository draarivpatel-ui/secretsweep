// Baseline suppression: a baseline is a JSON array of stable fingerprints,
// optionally paired with a file name. Existing findings matching an entry are
// suppressed; new findings are still reported.

import { readFileSync, writeFileSync } from 'node:fs';
import { fingerprint } from './util.mjs';

export function baselineKey(finding) {
  return fingerprint(`${finding.file || ''}:${finding.detector}:${finding.fingerprint}`);
}

export function readBaseline(path) {
  let data;
  try {
    data = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`cannot read baseline ${path}: ${error.message}`);
  }
  const values = Array.isArray(data) ? data : data && Array.isArray(data.entries) ? data.entries : null;
  if (!values) throw new Error(`invalid baseline format in ${path}`);
  const keys = [];
  for (const entry of values) {
    if (typeof entry === 'string') {
      if (entry) keys.push(entry);
      continue;
    }
    if (entry && typeof entry === 'object' &&
        Object.prototype.hasOwnProperty.call(entry, 'key') && typeof entry.key === 'string' && entry.key) {
      keys.push(entry.key);
      continue;
    }
    throw new Error(`invalid baseline entry in ${path}`);
  }
  return new Set(keys);
}

export function applyBaseline(findings, keys) {
  if (!keys) return findings;
  return findings.filter((finding) => !keys.has(baselineKey(finding)));
}

export function writeBaseline(path, findings) {
  const keys = [...new Set(findings.map(baselineKey))].sort();
  writeFileSync(path, JSON.stringify({ version: 1, entries: keys }, null, 2) + '\n', 'utf8');
  return keys.length;
}
