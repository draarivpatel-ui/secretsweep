import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');

describe('package metadata', () => {
  test('package name is secretsweep', () => {
    assert.equal(pkg.name, 'secretsweep');
  });
  test('version is semver', () => {
    assert.match(pkg.version, /^\d+\.\d+\.\d+$/);
  });
  test('license is MIT', () => {
    assert.equal(pkg.license, 'MIT');
  });
  test('requires Node 18 or newer', () => {
    assert.match(pkg.engines.node, />=18/);
  });
  test('has no runtime dependencies', () => {
    assert.deepEqual(pkg.dependencies, {});
  });
  test('has no dev dependencies', () => {
    assert.deepEqual(pkg.devDependencies, {});
  });
  test('declares a bin entry', () => {
    assert.equal(pkg.bin.secretsweep, './bin/secretsweep.mjs');
  });
  test('declares ESM module entry', () => {
    assert.equal(pkg.module, './src/index.mjs');
  });
  test('declares CJS main entry', () => {
    assert.equal(pkg.main, './cjs/index.cjs');
  });
  test('declares types entry', () => {
    assert.equal(pkg.types, './types/index.d.ts');
  });
  test('exports map has import and require branches', () => {
    assert.ok(pkg.exports['.'].import);
    assert.ok(pkg.exports['.'].require);
  });
  test('test script uses an explicit test file glob', () => {
    assert.equal(pkg.scripts.test, 'node --test tests/*.test.mjs');
  });
  test('check:cjs script exists', () => {
    assert.match(pkg.scripts['check:cjs'], /--check/);
  });
  test('sideEffects is false', () => {
    assert.equal(pkg.sideEffects, false);
  });
  test('README mentions exact test count', () => {
    assert.match(readme, /\*\*[0-9]+\*\* tests|\b[0-9]+ tests/);
  });
});

describe('community scaffolding', () => {
  const files = ['README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'LICENSE',
    'docs/good-first-issues.md', '.github/workflows/ci.yml', 'types/index.d.ts',
    '.gitattributes', '.github/ISSUE_TEMPLATE/bug_report.md',
    '.github/ISSUE_TEMPLATE/feature_request.md', '.github/PULL_REQUEST_TEMPLATE.md'];
  for (const file of files) {
    test(`${file} exists`, () => {
      assert.ok(existsSync(join(ROOT, file)), `missing ${file}`);
    });
  }
  test('CONTRIBUTING has a detector guide', () => {
    const text = readFileSync(join(ROOT, 'CONTRIBUTING.md'), 'utf8');
    assert.match(text, /Add a Provider Detector/i);
  });
  test('good-first-issues has at least 20 issues', () => {
    const text = readFileSync(join(ROOT, 'docs/good-first-issues.md'), 'utf8');
    const matches = text.match(/^###\s+\d+\./gm) || [];
    assert.ok(matches.length >= 20, `found ${matches.length} issues`);
  });
  test('CI matrix covers Ubuntu and Windows on Node 18 through 24', () => {
    const text = readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8');
    for (const version of ['18', '20', '22', '24']) assert.match(text, new RegExp(`\\b${version}\\b`));
    for (const required of ['ubuntu-latest', 'windows-latest', 'shell: bash', 'npm_config_script_shell: bash']) {
      assert.ok(text.includes(required), `CI is missing ${required}`);
    }
  });
  test('gitattributes pins source files to LF line endings', () => {
    const text = readFileSync(join(ROOT, '.gitattributes'), 'utf8');
    for (const required of ['*.cjs text eol=lf', '*.mjs text eol=lf', '*.ts text eol=lf']) {
      assert.ok(text.includes(required), `.gitattributes is missing ${required}`);
    }
  });
  test('LICENSE is MIT text', () => {
    const text = readFileSync(join(ROOT, 'LICENSE'), 'utf8');
    assert.match(text, /MIT License/);
  });
  test('tracked files contain no personal paths', () => {
    assert.ok(!readme.includes('/Users/'));
  });
  test('tracked files contain no em dashes', () => {
    assert.ok(!readme.includes('\u2014'));
    assert.ok(!readme.includes('\u2013'));
  });
});
