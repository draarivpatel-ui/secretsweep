import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readBaseline, writeBaseline, applyBaseline, baselineKey } from '../src/baseline.mjs';
import { scanText } from '../src/finder.mjs';

const dirs = [];
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'secretsweep-baseline-'));
  dirs.push(dir);
  return dir;
}
after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });

const finding = (file, detector, fingerprint) => ({
  file, detector, fingerprint, provider: 'x', name: 'x',
  severity: 'high', line: 1, column: 1, redacted: 'x',
});

describe('baseline', () => {
  test('baselineKey is deterministic', () => {
    assert.equal(baselineKey(finding('a.js', 'x', 'abc')), baselineKey(finding('a.js', 'x', 'abc')));
  });
  test('baselineKey includes the file', () => {
    assert.notEqual(baselineKey(finding('a.js', 'x', 'abc')), baselineKey(finding('b.js', 'x', 'abc')));
  });
  test('baselineKey includes the detector', () => {
    assert.notEqual(baselineKey(finding('a.js', 'x', 'abc')), baselineKey(finding('a.js', 'y', 'abc')));
  });
  test('writeBaseline returns entry count', () => {
    const path = join(tempDir(), 'baseline.json');
    assert.equal(writeBaseline(path, [finding('a.js', 'x', 'abc'), finding('b.js', 'y', 'def')]), 2);
  });
  test('writeBaseline deduplicates entries', () => {
    const path = join(tempDir(), 'baseline.json');
    assert.equal(writeBaseline(path, [finding('a.js', 'x', 'abc'), finding('a.js', 'x', 'abc')]), 1);
  });
  test('written baseline is valid JSON', () => {
    const path = join(tempDir(), 'baseline.json');
    writeBaseline(path, [finding('a.js', 'x', 'abc')]);
    const data = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(data.version, 1);
    assert.ok(Array.isArray(data.entries));
  });
  test('readBaseline returns a Set', () => {
    const path = join(tempDir(), 'baseline.json');
    writeBaseline(path, [finding('a.js', 'x', 'abc')]);
    assert.ok(readBaseline(path) instanceof Set);
  });
  test('readBaseline rejects invalid JSON', () => {
    const path = join(tempDir(), 'bad.json');
    writeFileSync(path, '{');
    assert.throws(() => readBaseline(path), /cannot read baseline/);
  });
  test('readBaseline rejects invalid format', () => {
    const path = join(tempDir(), 'bad.json');
    writeFileSync(path, '{}');
    assert.throws(() => readBaseline(path), /invalid baseline format/);
  });
  test('readBaseline accepts a plain array', () => {
    const path = join(tempDir(), 'array.json');
    writeFileSync(path, '["one","two"]');
    assert.equal(readBaseline(path).size, 2);
  });
  test('applyBaseline suppresses matching findings', () => {
    const f = finding('a.js', 'x', 'abc');
    const keys = new Set([baselineKey(f)]);
    assert.equal(applyBaseline([f], keys).length, 0);
  });
  test('applyBaseline keeps new findings', () => {
    const f = finding('a.js', 'x', 'abc');
    const keys = new Set([baselineKey(finding('a.js', 'x', 'other'))]);
    assert.equal(applyBaseline([f], keys).length, 1);
  });
  test('applyBaseline with null keys keeps everything', () => {
    const f = finding('a.js', 'x', 'abc');
    assert.equal(applyBaseline([f], null).length, 1);
  });
  test('round trip suppresses findings from scanText', () => {
    const token = 'ghp_' + 'A'.repeat(36);
    const findings = scanText(token).map((f) => ({ ...f, file: 'a.js' }));
    const path = join(tempDir(), 'baseline.json');
    writeBaseline(path, findings);
    const remaining = applyBaseline(findings, readBaseline(path));
    assert.equal(remaining.length, 0);
  });
  test('new secret is not suppressed by old baseline', () => {
    const findings = scanText('ghp_' + 'A'.repeat(36)).map((f) => ({ ...f, file: 'a.js' }));
    const path = join(tempDir(), 'baseline.json');
    writeBaseline(path, findings);
    const next = scanText('AKIA' + '0'.repeat(16)).map((f) => ({ ...f, file: 'a.js' }));
    assert.ok(applyBaseline(next, readBaseline(path)).length >= 1);
  });
});
