// Detector registry primitives. Kept separate from index.mjs so built-in
// detector modules can register themselves without a circular TDZ hazard.

import { ensureLinear } from '../util.mjs';

export const registry = [];

export function registerDetector(descriptor) {
  const id = String(descriptor.id || '');
  if (!/^[a-z0-9][a-z0-9-]*$/.test(id)) {
    throw new Error(`invalid detector id: ${id}`);
  }
  if (registry.some((entry) => entry.id === id)) {
    throw new Error(`duplicate detector id: ${id}`);
  }
  if (typeof descriptor.check !== 'function') {
    throw new Error(`detector ${id} has no check function`);
  }
  if (descriptor.pattern) ensureLinear(descriptor.pattern, id);
  const entry = Object.freeze({
    id,
    provider: descriptor.provider || id,
    name: descriptor.name || descriptor.provider || id,
    severity: descriptor.severity || 'high',
    pattern: descriptor.pattern || null,
    check: descriptor.check,
  });
  registry.push(entry);
  return entry;
}

export function listDetectors() {
  return registry.map((entry) => ({
    id: entry.id,
    provider: entry.provider,
    name: entry.name,
    severity: entry.severity,
  }));
}

export function getDetector(id) {
  return registry.find((entry) => entry.id === id) || null;
}

export function createPatternDetector(descriptor) {
  const pattern = ensureLinear(descriptor.pattern, descriptor.id);
  const flags = descriptor.flags || 'g';
  return registerDetector({
    ...descriptor,
    pattern,
    check(text) {
      const matches = [];
      const re = new RegExp(pattern.source, flags.includes('g') ? flags : flags + 'g');
      let match;
      while ((match = re.exec(text)) !== null) {
        const value = descriptor.value ? descriptor.value(match) : match[0];
        if (value) matches.push({ value, index: match.index });
        if (match[0].length === 0) re.lastIndex++;
        if (matches.length >= 1000) break;
      }
      return matches;
    },
  });
}
