import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as esm from '../src/index.mjs';

const require = createRequire(import.meta.url);
const cjs = require('../cjs/index.cjs');

const GITHUB = () => 'ghp_' + 'A'.repeat(36);
const AWS = () => 'AKIA' + '0'.repeat(16);

describe('ESM / CJS parity', () => {
  test('both expose the same public names', () => {
    const esmNames = Object.keys(esm).sort();
    const cjsNames = Object.keys(cjs).sort();
    assert.deepEqual(cjsNames, esmNames);
  });
  test('VERSION matches', () => {
    assert.equal(cjs.VERSION, esm.VERSION);
  });
  test('detector count matches', () => {
    assert.equal(cjs.listDetectors().length, esm.listDetectors().length);
  });
  test('detector ids match', () => {
    assert.deepEqual(cjs.listDetectors().map((d) => d.id), esm.listDetectors().map((d) => d.id));
  });
  test('fingerprint output matches', () => {
    assert.equal(cjs.fingerprint('abc'), esm.fingerprint('abc'));
  });
  test('maskValue output matches', () => {
    assert.equal(cjs.maskValue('abcdefghijklmnop'), esm.maskValue('abcdefghijklmnop'));
  });
  test('entropy output matches', () => {
    assert.equal(cjs.shannonEntropy('aabb'), esm.shannonEntropy('aabb'));
  });
  test('placeholder detection matches', () => {
    assert.equal(cjs.isPlaceholder('YOUR_API_KEY'), esm.isPlaceholder('YOUR_API_KEY'));
  });
  test('scanText results match for GitHub token', () => {
    assert.deepEqual(cjs.scanText(GITHUB()), esm.scanText(GITHUB()));
  });
  test('scanText results match for AWS key', () => {
    assert.deepEqual(cjs.scanText(AWS()), esm.scanText(AWS()));
  });
  test('scanText results match for clean text', () => {
    assert.deepEqual(cjs.scanText('clean'), esm.scanText('clean'));
  });
  test('scanDiff results match', () => {
    const diff = `diff --git a/a.js b/a.js\n--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n+${GITHUB()}\n`;
    assert.deepEqual(cjs.scanDiff(diff), esm.scanDiff(diff));
  });
  test('text formatting matches', () => {
    assert.equal(cjs.formatText(esm.scanText(GITHUB())), esm.formatText(esm.scanText(GITHUB())));
  });
  test('json formatting matches', () => {
    assert.equal(cjs.formatJson(esm.scanText(GITHUB())), esm.formatJson(esm.scanText(GITHUB())));
  });
  test('sarif formatting matches', () => {
    assert.equal(cjs.formatSarif(esm.scanText(GITHUB())), esm.formatSarif(esm.scanText(GITHUB())));
  });
  test('sortFindings matches', () => {
    const findings = esm.scanText(`${GITHUB()}\n${AWS()}`);
    assert.deepEqual(cjs.sortFindings(findings), esm.sortFindings(findings));
  });
  test('baselineKey matches', () => {
    const finding = { ...esm.scanText(GITHUB())[0], file: 'a.js' };
    assert.equal(cjs.baselineKey(finding), esm.baselineKey(finding));
  });
  test('getDetector matches', () => {
    const pick = (d) => d && ({ id: d.id, provider: d.provider, name: d.name, severity: d.severity });
    assert.deepEqual(pick(cjs.getDetector('github-pat')), pick(esm.getDetector('github-pat')));
  });
  test('DEFAULT_MAX_FILE_BYTES matches', () => {
    assert.equal(cjs.DEFAULT_MAX_FILE_BYTES, esm.DEFAULT_MAX_FILE_BYTES);
  });
});
