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
  test('symlink pointing outside the scan root is not followed', () => {
    const dir = tempDir();
    const outside = join(dir, 'outside');
    const root = join(dir, 'root');
    mkdirSync(outside);
    mkdirSync(root);
    writeFileSync(join(outside, 'outside.txt'), GITHUB());
    symlinkSync(join(outside, 'outside.txt'), join(root, 'linked.txt'));
    const result = scanPath(root);
    assert.equal(result.findings.length, 0);
    assert.ok(result.skipped.some((s) => s.path === 'linked.txt' && s.reason === 'path-escape'));
  });
  test('symlink pointing inside the scan root is scanned once', () => {
    const dir = tempDir();
    mkdirSync(join(dir, 'real'));
    writeFileSync(join(dir, 'real', 'a.txt'), GITHUB());
    symlinkSync(join(dir, 'real', 'a.txt'), join(dir, 'linked.txt'));
    const result = scanPath(dir);
    assert.equal(result.findings.length, 1);
  });
  test('two symlinks pointing at each other report a loop', () => {
    const dir = tempDir();
    symlinkSync('b', join(dir, 'a'));
    symlinkSync('a', join(dir, 'b'));
    const result = scanPath(dir);
    assert.ok(result.skipped.some((s) => s.reason === 'symlink-loop'));
  });
  test('NUL byte after the first 8 KiB makes a file binary', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'late.txt'), 'A'.repeat(9000) + '\0' + GITHUB());
    const result = scanPath(dir);
    assert.equal(result.findings.length, 0);
    assert.ok(result.skipped.some((s) => s.path === 'late.txt' && s.reason === 'binary'));
  });
  test('a binary-looking extension does not hide readable text', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'secret.png'), GITHUB());
    const result = scanPath(dir);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].file, 'secret.png');
  });
  test('dense control bytes make a file binary without a NUL', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'payload.bin'), Buffer.alloc(1024, 1));
    const result = scanPath(dir);
    assert.equal(result.findings.length, 0);
    assert.ok(result.skipped.some((s) => s.path === 'payload.bin' && s.reason === 'binary'));
  });
  test('.gitignore glob and negation are honored during a scan', () => {
    const dir = tempDir();
    writeFileSync(join(dir, '.gitignore'), '*.txt\n!keep.txt\n');
    writeFileSync(join(dir, 'secret.txt'), GITHUB());
    writeFileSync(join(dir, 'keep.txt'), AWS());
    const result = scanPath(dir);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].file, 'keep.txt');
  });
  test('directory-only ignore is honored during a scan', () => {
    const dir = tempDir();
    mkdirSync(join(dir, 'cache'));
    writeFileSync(join(dir, '.gitignore'), 'cache/\n');
    writeFileSync(join(dir, 'cache', 'secret.txt'), GITHUB());
    assert.equal(scanPath(dir).findings.length, 0);
  });
  test('trailing doublestar does not block negated direct children', () => {
    const dir = tempDir();
    mkdirSync(join(dir, 'foo'));
    writeFileSync(join(dir, '.gitignore'), 'foo/**\n!foo/keep.txt\n');
    writeFileSync(join(dir, 'foo', 'secret.txt'), GITHUB());
    writeFileSync(join(dir, 'foo', 'keep.txt'), GITHUB());
    const result = scanPath(dir);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].file, 'foo/keep.txt');
  });
  test('an ignored parent directory is pruned before a child negation', () => {
    const dir = tempDir();
    mkdirSync(join(dir, 'foo'));
    writeFileSync(join(dir, '.gitignore'), 'foo\n!foo/keep.txt\n');
    writeFileSync(join(dir, 'foo', 'keep.txt'), GITHUB());
    assert.equal(scanPath(dir).findings.length, 0);
  });
  test('oversized ignore files are rejected instead of buffered without a cap', () => {
    const dir = tempDir();
    writeFileSync(join(dir, '.gitignore'), '*\n' + '#'.repeat(1024 * 1024));
    assert.throws(() => scanPath(dir), /ignore file .gitignore exceeds/);
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
  test('directory-only rule does not match a same-named file', () => {
    const rules = compileIgnoreRules(['cache/']);
    assert.equal(isIgnored('cache', false, rules), false);
    assert.equal(isIgnored('cache', true, rules), true);
  });
  test('directory-only rule ignores descendants', () => {
    const rules = compileIgnoreRules(['cache/']);
    assert.equal(isIgnored('cache/a.js', false, rules), true);
  });
  test('glob pattern matches nested file names', () => {
    const rules = compileIgnoreRules(['*.txt']);
    assert.equal(isIgnored('src/secret.txt', false, rules), true);
    assert.equal(isIgnored('src/secret.js', false, rules), false);
  });
  test('glob negation re-includes a matching file', () => {
    const rules = compileIgnoreRules(['*.txt', '!keep.txt']);
    assert.equal(isIgnored('src/secret.txt', false, rules), true);
    assert.equal(isIgnored('src/keep.txt', false, rules), false);
  });
  test('anchored glob does not match a deeper root segment', () => {
    const rules = compileIgnoreRules(['/src/*.txt']);
    assert.equal(isIgnored('src/secret.txt', false, rules), true);
    assert.equal(isIgnored('nested/src/secret.txt', false, rules), false);
  });
  test('doublestar glob matches across directories', () => {
    const rules = compileIgnoreRules(['**/secret.txt']);
    assert.equal(isIgnored('a/b/secret.txt', false, rules), true);
  });
  test('trailing doublestar does not ignore its parent directory', () => {
    const rules = compileIgnoreRules(['foo/**']);
    assert.equal(isIgnored('foo', true, rules), false);
    assert.equal(isIgnored('foo/child', true, rules), true);
    assert.equal(isIgnored('foo/file.txt', false, rules), true);
  });
  test('negation re-includes a direct child below trailing doublestar', () => {
    const rules = compileIgnoreRules(['foo/**', '!foo/keep.txt']);
    assert.equal(isIgnored('foo/keep.txt', false, rules), false);
    assert.equal(isIgnored('foo/secret.txt', false, rules), true);
  });
  test('character class glob matches', () => {
    const rules = compileIgnoreRules(['[a-c]ecret.txt']);
    assert.equal(isIgnored('becret.txt', false, rules), true);
    assert.equal(isIgnored('zecret.txt', false, rules), false);
  });
});

describe('binary detection', () => {
  test('NUL byte means binary', () => {
    assert.equal(looksBinary(Buffer.from([65, 0, 66])), true);
  });
  test('plain text is not binary', () => {
    assert.equal(looksBinary(Buffer.from('hello world')), false);
  });
  test('NUL byte after 8 KiB means binary', () => {
    const buffer = Buffer.concat([Buffer.alloc(8193, 65), Buffer.from([0])]);
    assert.equal(looksBinary(buffer), true);
  });
  test('known binary extension is detected', () => {
    assert.equal(isBinaryPath('image.png'), true);
    assert.equal(isBinaryPath('payload.bin'), true);
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
  test('added content beginning with two plus signs is scanned', () => {
    const findings = scanDiff(diff('++ prefix ' + GITHUB()));
    assert.equal(findings.length, 1);
  });
  test('multi-line PEM in consecutive added lines is detected', () => {
    const pem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'A'.repeat(64),
      '-----END RSA PRIVATE KEY-----',
    ];
    const text = [
      'diff --git a/key.pem b/key.pem',
      '--- /dev/null',
      '+++ b/key.pem',
      '@@ -0,0 +1,3 @@',
      ...pem.map((line) => `+${line}`),
    ].join('\n');
    const findings = scanDiff(text, { detectors: ['pem-private-key'] });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].line, 1);
  });
  test('file names with spaces are extracted', () => {
    const text = diff(GITHUB()).replaceAll('app.js', 'path with spaces.js');
    assert.equal(scanDiff(text)[0].file, 'path with spaces.js');
  });
  test('renamed files use the new file name', () => {
    const text = diff(GITHUB()).replace('diff --git a/app.js b/app.js',
      'diff --git a/old.js b/new.js\nsimilarity index 80%\nrename from old.js\nrename to new.js')
      .replace('--- a/app.js', '--- a/old.js')
      .replace('+++ b/app.js', '+++ b/new.js');
    assert.equal(scanDiff(text)[0].file, 'new.js');
  });
  test('multiple hunks keep independent line numbers', () => {
    const text = [
      'diff --git a/app.js b/app.js',
      '--- a/app.js',
      '+++ b/app.js',
      '@@ -10 +10 @@',
      `+${GITHUB()}`,
      '@@ -40 +42 @@',
      `+${AWS()}`,
    ].join('\n');
    const findings = scanDiff(text);
    assert.equal(findings[0].line, 10);
    assert.equal(findings[1].line, 42);
  });
  test('CRLF diffs are parsed', () => {
    const text = diff(GITHUB()).split('\n').join('\r\n');
    assert.equal(scanDiff(text).length, 1);
  });
  test('file names containing diff marker text are extracted', () => {
    const plusName = '+++ odd.js';
    const hunkName = '@@ odd.js';
    const plusText = diff(GITHUB()).replaceAll('app.js', plusName);
    const hunkText = diff(AWS()).replaceAll('app.js', hunkName);
    assert.equal(scanDiff(plusText)[0].file, plusName);
    assert.equal(scanDiff(hunkText)[0].file, hunkName);
  });
  test('quoted git file names are unescaped', () => {
    const text = diff(GITHUB()).replace('+++ b/app.js', '+++ "b/app\\040copy.js"');
    assert.equal(scanDiff(text)[0].file, 'app copy.js');
  });
  test('dev-null new file header does not retain a prior file name', () => {
    const text = [
      'diff --git a/deleted.js b/deleted.js',
      '--- a/deleted.js',
      '+++ /dev/null',
      '@@ -1 +0,0 @@',
      `+${GITHUB()}`,
    ].join('\n');
    assert.equal(scanDiff(text).length, 0);
  });
  test('a context line separates added blocks', () => {
    const pem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'A'.repeat(64),
      '-----END RSA PRIVATE KEY-----',
    ];
    const text = [
      'diff --git a/key.pem b/key.pem',
      '--- a/key.pem',
      '+++ b/key.pem',
      '@@ -1,3 +1,4 @@',
      `+${pem[0]}`,
      ' context',
      `+${pem[1]}`,
      `+${pem[2]}`,
    ].join('\n');
    assert.equal(scanDiff(text, { detectors: ['pem-private-key'] }).length, 0);
  });
});
