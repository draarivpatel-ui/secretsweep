import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanPath, scanDiff, looksBinary, isBinaryPath, DEFAULT_MAX_FILE_BYTES } from '../src/scanner.mjs';
import { compileIgnoreRules, isIgnored } from '../src/ignore.mjs';

const GITHUB = () => 'ghp_' + 'A'.repeat(36);
const AWS = () => 'AKIA' + '0'.repeat(16);
const dirs = [];
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'secretsweep-test-'));
  dirs.push(dir);
  return dir;
}
after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });

describe('scanPath', () => {
  test('rejects a nonexistent path', () => {
    assert.throws(() => scanPath('/nonexistent/secretsweep/path'), /cannot read/);
  });
  test('scans a single file', () => {
    const dir = tempDir();
    const file = join(dir, 'app.js');
    writeFileSync(file, `const token = "${GITHUB()}";\n`);
    const result = scanPath(file);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].file, 'app.js');
  });
  test('scans a directory recursively', () => {
    const dir = tempDir();
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src', 'a.js'), GITHUB());
    writeFileSync(join(dir, 'b.js'), AWS());
    assert.equal(scanPath(dir).findings.length, 2);
  });
  test('skips .git directory', () => {
    const dir = tempDir();
    mkdirSync(join(dir, '.git'));
    writeFileSync(join(dir, '.git', 'config'), GITHUB());
    assert.equal(scanPath(dir).findings.length, 0);
  });
  test('skips node_modules directory', () => {
    const dir = tempDir();
    mkdirSync(join(dir, 'node_modules'));
    writeFileSync(join(dir, 'node_modules', 'a.js'), GITHUB());
    assert.equal(scanPath(dir).findings.length, 0);
  });
  test('honors .gitignore', () => {
    const dir = tempDir();
    writeFileSync(join(dir, '.gitignore'), 'secret.txt\n');
    writeFileSync(join(dir, 'secret.txt'), GITHUB());
    writeFileSync(join(dir, 'ok.txt'), AWS());
    assert.equal(scanPath(dir).findings.length, 1);
  });
  test('honors .secretsweepignore', () => {
    const dir = tempDir();
    writeFileSync(join(dir, '.secretsweepignore'), 'secret.txt\n');
    writeFileSync(join(dir, 'secret.txt'), GITHUB());
    assert.equal(scanPath(dir).findings.length, 0);
  });
  test('honors exclude option', () => {
    const dir = tempDir();
    mkdirSync(join(dir, 'vendor'));
    writeFileSync(join(dir, 'vendor', 'a.js'), GITHUB());
    assert.equal(scanPath(dir, { exclude: ['vendor'] }).findings.length, 0);
  });
  test('skip list records binary files', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'image.png'), Buffer.from([1, 2, 3, 4]));
    const result = scanPath(dir);
    assert.ok(result.skipped.some((s) => s.reason === 'binary'));
  });
  test('skip list records oversized files', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'big.txt'), 'x'.repeat(100));
    const result = scanPath(dir, { maxFileBytes: 10 });
    assert.ok(result.skipped.some((s) => s.reason === 'too-large'));
  });
  test('hard link replay is guarded', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'a.js'), GITHUB());
    assert.equal(scanPath(dir).findings.length, 1);
  });
  test('symlink loop is detected', () => {
    const dir = tempDir();
    mkdirSync(join(dir, 'sub'));
    writeFileSync(join(dir, 'sub', 'a.js'), GITHUB());
    symlinkSync(dir, join(dir, 'sub', 'loop'));
    const result = scanPath(dir);
    assert.ok(result.skipped.some((s) => s.reason === 'symlink-loop'));
  });
  test('broken symlink is skipped', () => {
    const dir = tempDir();
    symlinkSync(join(dir, 'missing'), join(dir, 'broken'));
    const result = scanPath(dir);
    assert.ok(result.skipped.some((s) => s.reason === 'broken-symlink'));
  });
  test('default max file size is 2 MiB', () => {
    assert.equal(DEFAULT_MAX_FILE_BYTES, 2 * 1024 * 1024);
  });
  test('findings include relative paths', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'test.js'), GITHUB());
    assert.equal(scanPath(dir).findings[0].file, 'test.js');
  });
  test('inline ignore works in scanned files', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'a.js'), `${GITHUB()} // secretsweep:ignore`);
    assert.equal(scanPath(dir).findings.length, 0);
  });
  test('detectors option is forwarded', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'a.js'), GITHUB());
    assert.equal(scanPath(dir, { detectors: ['github-pat'] }).findings.length, 1);
  });
});

describe('ignore rules', () => {
  test('empty lines are ignored', () => {
    assert.equal(compileIgnoreRules(['', '   ']).length, 0);
  });
  test('comments are ignored', () => {
    assert.equal(compileIgnoreRules(['# comment']).length, 0);
  });
  test('simple name matches any directory level', () => {
    const rules = compileIgnoreRules(['secret.txt']);
    assert.equal(isIgnored('secret.txt', false, rules), true);
    assert.equal(isIgnored('src/secret.txt', false, rules), true);
  });
  test('anchored pattern matches root only', () => {
    const rules = compileIgnoreRules(['/secret.txt']);
    assert.equal(isIgnored('secret.txt', false, rules), true);
    assert.equal(isIgnored('src/secret.txt', false, rules), false);
  });
  test('path pattern matches suffix', () => {
    const rules = compileIgnoreRules(['src/cache']);
    assert.equal(isIgnored('src/cache/a.js', false, rules), true);
  });
  test('negation unignores a path', () => {
    const rules = compileIgnoreRules(['*.txt', '!keep.txt']);
    assert.equal(isIgnored('keep.txt', false, rules), false);
  });
  test('directory-only rule does not match files', () => {
    const rules = compileIgnoreRules(['cache/']);
    assert.equal(isIgnored('cache/a.js', false, rules), false);
    assert.equal(isIgnored('cache', true, rules), true);
  });
});

describe('binary detection', () => {
  test('NUL byte means binary', () => {
    assert.equal(looksBinary(Buffer.from([65, 0, 66])), true);
  });
  test('plain text is not binary', () => {
    assert.equal(looksBinary(Buffer.from('hello world')), false);
  });
  test('known binary extension is detected', () => {
    assert.equal(isBinaryPath('image.png'), true);
  });
  test('text extension is not binary', () => {
    assert.equal(isBinaryPath('index.js'), false);
  });
  test('uppercase extension is detected', () => {
    assert.equal(isBinaryPath('IMAGE.PNG'), true);
  });
});

describe('scanDiff', () => {
  const diff = (line) => [
    'diff --git a/app.js b/app.js',
    '--- a/app.js',
    '+++ b/app.js',
    '@@ -1,1 +1,1 @@',
    '-old line',
    `+${line}`,
  ].join('\n');

  test('rejects non-string input', () => {
    assert.throws(() => scanDiff(42), /expects a string/);
  });
  test('finds a secret in an added line', () => {
    assert.equal(scanDiff(diff(`const token = "${GITHUB()}";`)).length, 1);
  });
  test('ignores secrets in removed lines', () => {
    const text = diff('replacement').replace('-old line', `-${AWS()}`);
    assert.equal(scanDiff(text).length, 0);
  });
  test('extracts the file name', () => {
    assert.equal(scanDiff(diff(GITHUB()))[0].file, 'app.js');
  });
  test('line numbers come from the hunk header', () => {
    assert.equal(scanDiff(diff(GITHUB()))[0].line, 1);
  });
  test('handles a hunk starting at line 40', () => {
    const text = diff(GITHUB()).replace('@@ -1,1 +1,1 @@', '@@ -40,1 +40,1 @@');
    assert.equal(scanDiff(text)[0].line, 40);
  });
  test('handles empty diff', () => {
    assert.deepEqual(scanDiff(''), []);
  });
  test('respects inline ignore in diff', () => {
    assert.equal(scanDiff(diff(`${GITHUB()} # secretsweep:ignore`)).length, 0);
  });
  test('scans multiple files', () => {
    const text = diff(GITHUB()) + '\n' + diff(AWS()).replaceAll('app.js', 'other.js');
    const findings = scanDiff(text);
    assert.equal(findings.length, 2);
    assert.notEqual(findings[0].file, findings[1].file);
  });
});
