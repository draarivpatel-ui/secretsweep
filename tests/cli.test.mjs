import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'bin', 'secretsweep.mjs');
const GITHUB = () => 'ghp_' + 'A'.repeat(36);
const AWS = () => 'AKIA' + '0'.repeat(16);
const dirs = [];
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'secretsweep-cli-'));
  dirs.push(dir);
  return dir;
}
after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });

function run(args, stdin) {
  return spawnSync(process.execPath, [CLI, ...args], {
    input: stdin === undefined ? '' : stdin,
    encoding: 'utf8',
  });
}

describe('CLI', () => {
  test('--version prints version', () => {
    const result = run(['--version']);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /^secretsweep 1\.0\.0\s*$/);
  });
  test('-v prints version', () => {
    assert.equal(run(['-v']).status, 0);
  });
  test('--help prints usage', () => {
    const result = run(['--help']);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /Usage:/);
  });
  test('-h prints usage', () => {
    assert.equal(run(['-h']).status, 0);
  });
  test('help documents exit codes', () => {
    assert.match(run(['--help']).stdout, /Exit codes:/);
  });
  test('--list-detectors prints many detectors', () => {
    const result = run(['--list-detectors']);
    assert.equal(result.status, 0);
    assert.ok(result.stdout.trim().split('\n').length >= 25);
  });
  test('unknown option exits 2', () => {
    assert.equal(run(['--bogus']).status, 2);
  });
  test('missing option value exits 2', () => {
    assert.equal(run(['--format']).status, 2);
  });
  test('invalid format exits 2', () => {
    assert.equal(run(['--format', 'xml']).status, 2);
  });
  test('invalid severity exits 2', () => {
    assert.equal(run(['--severity', 'urgent']).status, 2);
  });
  test('invalid max file bytes exits 2', () => {
    assert.equal(run(['--max-file-bytes', 'abc']).status, 2);
  });
  test('conflicting input modes exit 2', () => {
    assert.equal(run(['--stdin', '--diff']).status, 2);
  });
  test('clean stdin exits 0', () => {
    const result = run(['--stdin'], 'const answer = 42;');
    assert.equal(result.status, 0);
    assert.match(result.stdout, /no secrets found/);
  });
  test('secret in stdin exits 1', () => {
    assert.equal(run(['--stdin'], GITHUB()).status, 1);
  });
  test('JSON output is valid', () => {
    const result = run(['--stdin', '--format', 'json'], GITHUB());
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stdout).count, 1);
  });
  test('SARIF output is valid', () => {
    const result = run(['--stdin', '--format', 'sarif'], GITHUB());
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stdout).version, '2.1.0');
  });
  test('detector filter restricts findings', () => {
    const text = `${GITHUB()}\n${AWS()}`;
    const result = run(['--stdin', '--detectors', 'github-pat'], text);
    assert.equal(result.status, 1);
    assert.ok(!JSON.parse(run(['--stdin', '--detectors', 'github-pat', '--format', 'json'], text).stdout)
      .findings.some((f) => f.detector === 'aws-access-key-id'));
  });
  test('severity filter works', () => {
    assert.equal(run(['--stdin', '--severity', 'critical'], GITHUB()).status, 0);
  });
  test('diff mode finds added secrets', () => {
    const diff = [
      'diff --git a/x.js b/x.js',
      '--- a/x.js',
      '+++ b/x.js',
      '@@ -0,0 +1 @@',
      `+${GITHUB()}`,
    ].join('\n');
    assert.equal(run(['--diff'], diff).status, 1);
  });
  test('directory scan exits 1 when secrets found', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'a.js'), GITHUB());
    assert.equal(run([dir]).status, 1);
  });
  test('directory scan exits 0 when clean', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'a.js'), 'const answer = 42;');
    assert.equal(run([dir]).status, 0);
  });
  test('nonexistent path exits 2', () => {
    assert.equal(run([join(tempDir(), 'missing')]).status, 2);
  });
  test('baseline suppresses a known finding', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'a.js'), GITHUB());
    const baseline = join(dir, 'baseline.json');
    assert.equal(run(['--write-baseline', baseline, dir]).status, 0);
    assert.equal(run(['--baseline', baseline, dir]).status, 0);
  });
  test('baseline does not suppress new findings', () => {
    const dir = tempDir();
    const baseline = join(dir, 'baseline.json');
    writeFileSync(join(dir, 'a.js'), GITHUB());
    run(['--write-baseline', baseline, dir]);
    writeFileSync(join(dir, 'a.js'), AWS());
    assert.equal(run(['--baseline', baseline, dir]).status, 1);
  });
  test('invalid baseline exits 2', () => {
    const dir = tempDir();
    const baseline = join(dir, 'bad.json');
    writeFileSync(baseline, '{}');
    assert.equal(run(['--baseline', baseline, '--stdin'], GITHUB()).status, 2);
  });
  test('exclude option works', () => {
    const dir = tempDir();
    const sub = join(dir, 'vendor');
    mkdirSync(sub, { recursive: true });
    writeFileSync(join(sub, 'a.js'), GITHUB());
    assert.equal(run(['--exclude', 'vendor', dir]).status, 0);
  });
  test('CLI never prints raw secret values', () => {
    const value = GITHUB();
    assert.ok(!run(['--stdin', '--format', 'json'], value).stdout.includes(value));
  });
  test('inline ignore works via CLI', () => {
    assert.equal(run(['--stdin'], `${GITHUB()} # secretsweep:ignore`).status, 0);
  });
});
