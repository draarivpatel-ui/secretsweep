import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { formatText, formatJson, formatSarif, format, sortFindings } from '../src/output.mjs';
import { scanText } from '../src/finder.mjs';
import { VERSION } from '../src/util.mjs';

const finding = (overrides = {}) => ({
  detector: 'github-pat', provider: 'GitHub', name: 'GitHub classic personal access token',
  severity: 'high', line: 2, column: 5, redacted: 'ghp_****AAAA', fingerprint: 'a'.repeat(64),
  file: 'src/a.js', ...overrides,
});

describe('text output', () => {
  test('clean output mentions no secrets', () => {
    assert.match(formatText([]), /no secrets found/);
  });
  test('custom clean message is used', () => {
    assert.match(formatText([], { cleanMessage: 'all good\n' }), /all good/);
  });
  test('report includes finding count', () => {
    assert.match(formatText([finding()]), /1 potential secret/);
  });
  test('report uses plural for multiple findings', () => {
    assert.match(formatText([finding(), finding()]), /2 potential secrets/);
  });
  test('report includes file, line and column', () => {
    assert.match(formatText([finding()]), /src\/a\.js:2:5/);
  });
  test('report includes provider and detector', () => {
    const text = formatText([finding()]);
    assert.match(text, /GitHub/);
    assert.match(text, /github-pat/);
  });
  test('report includes truncated fingerprint', () => {
    assert.match(formatText([finding()]), /sha256:aaaaaaaaaaaa/);
  });
  test('report does not include raw values from real finding', () => {
    const value = 'ghp_' + 'A'.repeat(36);
    const f = scanText(value)[0];
    assert.ok(!formatText([f]).includes(value));
  });
  test('short URL passwords expose at most two edge characters', () => {
    const password = Array.from({ length: 20 }, (_, i) =>
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[(i * 13 + 5) % 62]).join('');
    const finding = scanText(`postgres://user:${password}@db.example.internal/app`, { detectors: ['db-uri-password'] })[0];
    assert.ok(!formatText([finding]).includes(password));
    assert.equal(finding.redacted.startsWith(password.slice(0, 4)), false);
    assert.equal(finding.redacted.endsWith(password.slice(-4)), false);
  });
  test('control characters in file names are escaped', () => {
    const text = formatText([finding({ file: 'a\nforged.js' })]);
    assert.ok(!text.includes('a\nforged.js'));
    assert.match(text, /a\\nforged\.js/);
  });
});

describe('json output', () => {
  test('is valid JSON', () => {
    assert.deepEqual(JSON.parse(formatJson([finding()])).findings.length, 1);
  });
  test('includes version', () => {
    assert.equal(JSON.parse(formatJson([])).version, VERSION);
  });
  test('includes count', () => {
    assert.equal(JSON.parse(formatJson([finding(), finding()])).count, 2);
  });
  test('includes tool name', () => {
    assert.equal(JSON.parse(formatJson([])).tool, 'secretsweep');
  });
  test('empty findings produce empty array', () => {
    assert.deepEqual(JSON.parse(formatJson([])).findings, []);
  });
  test('skipped files are included when supplied', () => {
    const output = formatJson([], { skipped: [{ path: 'a', reason: 'binary' }] });
    assert.equal(JSON.parse(output).skipped.length, 1);
  });
  test('output ends with newline', () => {
    assert.ok(formatJson([]).endsWith('\n'));
  });
});

describe('sarif output', () => {
  const parse = (findings) => JSON.parse(formatSarif(findings));

  test('declares SARIF 2.1.0', () => {
    assert.equal(parse([]).version, '2.1.0');
  });
  test('includes the SARIF schema URL', () => {
    assert.match(parse([]).$schema, /sarif-2\.1\.0\.json$/);
  });
  test('has exactly one run', () => {
    assert.equal(parse([]).runs.length, 1);
  });
  test('names the tool', () => {
    assert.equal(parse([]).runs[0].tool.driver.name, 'secretsweep');
  });
  test('empty findings produce no results', () => {
    assert.deepEqual(parse([]).runs[0].results, []);
  });
  test('findings become results', () => {
    assert.equal(parse([finding()]).runs[0].results.length, 1);
  });
  test('rules are generated', () => {
    assert.equal(parse([finding()]).runs[0].tool.driver.rules.length, 1);
  });
  test('duplicate rules are deduplicated', () => {
    assert.equal(parse([finding(), finding()]).runs[0].tool.driver.rules.length, 1);
  });
  test('rule ids match detector ids', () => {
    assert.equal(parse([finding()]).runs[0].results[0].ruleId, 'github-pat');
  });
  test('severity maps to error level', () => {
    assert.equal(parse([finding()]).runs[0].results[0].level, 'error');
  });
  test('medium severity maps to warning', () => {
    assert.equal(parse([finding({ severity: 'medium' })]).runs[0].results[0].level, 'warning');
  });
  test('includes file URI', () => {
    const result = parse([finding()]).runs[0].results[0];
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'src/a.js');
  });
  test('absolute host paths are reduced to a safe relative artifact name', () => {
    const result = parse([finding({ file: '/home/example/project/src/a.js' })]).runs[0].results[0];
    const uri = result.locations[0].physicalLocation.artifactLocation.uri;
    assert.equal(uri, 'a.js');
    assert.ok(!uri.startsWith('/'));
    assert.ok(!uri.includes('Users'));
  });
  test('Windows drive paths are not emitted as absolute URIs', () => {
    const result = parse([finding({ file: 'C:/example/a.js' })]).runs[0].results[0];
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'a.js');
  });
  test('dot segments cannot escape the artifact base', () => {
    const result = parse([finding({ file: '../outside/a.js' })]).runs[0].results[0];
    const uri = result.locations[0].physicalLocation.artifactLocation.uri;
    assert.equal(uri, 'outside/a.js');
  });
  test('spaces in artifact URIs are percent encoded', () => {
    const result = parse([finding({ file: 'src/path with spaces.js' })]).runs[0].results[0];
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'src/path%20with%20spaces.js');
  });
  test('includes line and column', () => {
    const region = parse([finding()]).runs[0].results[0].locations[0].physicalLocation.region;
    assert.equal(region.startLine, 2);
    assert.equal(region.startColumn, 5);
  });
  test('includes partial fingerprint', () => {
    const result = parse([finding()]).runs[0].results[0];
    assert.equal(result.partialFingerprints.secretsweepFingerprint, 'a'.repeat(64));
  });
  test('message contains redacted value only', () => {
    const value = 'ghp_' + 'A'.repeat(36);
    const f = scanText(value)[0];
    const sarif = formatSarif([f]);
    assert.ok(!sarif.includes(value));
  });
  test('output is valid JSON', () => {
    assert.doesNotThrow(() => JSON.parse(formatSarif([finding()])));
  });
});

describe('format dispatcher', () => {
  test('dispatches to text', () => {
    assert.match(format([], 'text'), /no secrets/);
  });
  test('dispatches to json', () => {
    assert.equal(JSON.parse(format([], 'json')).count, 0);
  });
  test('dispatches to sarif', () => {
    assert.equal(JSON.parse(format([], 'sarif')).version, '2.1.0');
  });
  test('rejects unknown format', () => {
    assert.throws(() => format([], 'xml'), /unknown output format/);
  });
});

describe('sortFindings', () => {
  test('sorts by file', () => {
    const sorted = sortFindings([finding({ file: 'z.js' }), finding({ file: 'a.js' })]);
    assert.equal(sorted[0].file, 'a.js');
  });
  test('sorts by line', () => {
    const sorted = sortFindings([finding({ line: 9 }), finding({ line: 1 })]);
    assert.equal(sorted[0].line, 1);
  });
  test('does not mutate input', () => {
    const input = [finding({ line: 9 }), finding({ line: 1 })];
    sortFindings(input);
    assert.equal(input[0].line, 9);
  });
});
