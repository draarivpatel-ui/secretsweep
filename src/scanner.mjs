// Directory and file scanner. Skips binary files, honours ignore files,
// guards symlink loops and enforces a maximum file size.

import { readFileSync, readdirSync, lstatSync, realpathSync, statSync } from 'node:fs';
import { join, resolve, extname, relative, isAbsolute, sep, basename } from 'node:path';
import { scanText } from './finder.mjs';
import { loadIgnoreFiles, isIgnored, isAlwaysIgnored } from './ignore.mjs';

export const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.avif',
  '.pdf', '.zip', '.gz', '.tar', '.bz2', '.xz', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.o', '.a', '.class', '.jar',
  '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp3', '.mp4',
  '.mov', '.avi', '.wav', '.flac', '.webm', '.sqlite', '.db',
  '.p12', '.pfx', '.keystore', '.pyc', '.node', '.wasm', '.bin',
]);

export function looksBinary(buffer) {
  if (buffer.length === 0) return false;
  let controls = 0;
  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte === 0) return true;
    if ((byte < 9 || (byte > 13 && byte < 32) || byte === 127)) controls++;
  }
  return controls / buffer.length > 0.3;
}

export function isBinaryPath(path) {
  return BINARY_EXTENSIONS.has(extname(path).toLowerCase());
}

function readTextFile(path, maxBytes) {
  const stats = statSync(path);
  if (!stats.isFile()) return null;
  if (stats.size > maxBytes) return null;
  const buffer = readFileSync(path);
  if (looksBinary(buffer)) return null;
  return buffer.toString('utf8');
}

function insideRoot(rootReal, identity) {
  const rel = relative(rootReal, identity);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

export function scanPath(target, options = {}) {
  const root = resolve(target);
  const maxBytes = options.maxFileBytes || DEFAULT_MAX_FILE_BYTES;
  const rules = options.ignoreRules || loadIgnoreFiles(root);
  const results = [];
  const skipped = [];
  const visited = new Set();
  const extraRules = options.exclude || [];

  let rootStat;
  try {
    rootStat = statSync(root);
  } catch (error) {
    throw new Error(`cannot read ${root}: ${error.message}`);
  }
  const rootIsDirectory = rootStat.isDirectory();
  let rootReal = root;
  try {
    rootReal = realpathSync(root);
  } catch {
    rootReal = root;
  }

  function visit(path, relPath) {
    if (relPath && isAlwaysIgnored(relPath.split('/').pop())) return;
    if (extraRules.some((pattern) => relPath === pattern || relPath.startsWith(pattern + '/'))) return;

    let stat;
    try {
      stat = lstatSync(path);
    } catch {
      skipped.push({ path: relPath, reason: 'unreadable-file' });
      return;
    }
    if (relPath && isIgnored(relPath, stat.isDirectory(), rules)) return;

    let identity;
    try {
      identity = realpathSync(path);
    } catch (error) {
      skipped.push({ path: relPath, reason: error && error.code === 'ELOOP' ? 'symlink-loop' : 'broken-symlink' });
      return;
    }

    if (stat.isSymbolicLink()) {
      if (rootIsDirectory && !insideRoot(rootReal, identity)) {
        skipped.push({ path: relPath, reason: 'path-escape' });
        return;
      }
      try {
        stat = statSync(path);
      } catch {
        skipped.push({ path: relPath, reason: 'broken-symlink' });
        return;
      }
    }
    if (visited.has(identity)) {
      skipped.push({ path: relPath, reason: 'symlink-loop' });
      return;
    }
    visited.add(identity);

    if (stat.isDirectory()) {
      let entries;
      try {
        entries = readdirSync(path);
      } catch {
        skipped.push({ path: relPath, reason: 'unreadable-directory' });
        return;
      }
      entries.sort().forEach((entry) => visit(join(path, entry), relPath ? `${relPath}/${entry}` : entry));
      return;
    }
    if (!stat.isFile()) return;

    let text;
    try {
      text = readTextFile(path, maxBytes);
    } catch {
      skipped.push({ path: relPath, reason: 'unreadable-file' });
      return;
    }
    if (text === null) {
      skipped.push({ path: relPath, reason: stat.size > maxBytes ? 'too-large' : 'binary' });
      return;
    }
    const findings = scanText(text, options);
    for (const finding of findings) results.push({ ...finding, file: relPath });
  }

  if (rootIsDirectory) {
    visit(root, '');
  } else {
    visit(root, basename(root));
  }
  return { findings: results, skipped, root };
}

function unquoteGitPath(value) {
  if (value.length < 2 || value[0] !== '"' || value[value.length - 1] !== '"') return value;
  let output = '';
  for (let i = 1; i < value.length - 1; i++) {
    const char = value[i];
    if (char !== '\\') {
      output += char;
      continue;
    }
    if (i + 1 >= value.length - 1) {
      output += '\\';
      continue;
    }
    const next = value[++i];
    const escapes = { n: '\n', r: '\r', t: '\t', b: '\b', a: '\x07', f: '\f', v: '\v', '\\': '\\', '"': '"' };
    if (Object.prototype.hasOwnProperty.call(escapes, next)) {
      output += escapes[next];
    } else if (/[0-7]/.test(next)) {
      let octal = next;
      while (octal.length < 3 && i + 1 < value.length - 1 && /[0-7]/.test(value[i + 1])) {
        octal += value[++i];
      }
      output += String.fromCharCode(parseInt(octal, 8));
    } else {
      output += next;
    }
  }
  return output;
}

function parseNewFileHeader(line) {
  if (!line.startsWith('+++ ')) return null;
  const raw = line.slice(4).split('\t')[0];
  const path = unquoteGitPath(raw);
  if (path === '/dev/null') return { file: null };
  if (path.startsWith('b/') || path.startsWith('a/')) return { file: path.slice(2) };
  return { file: path };
}

const HUNK_HEADER = /^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/;

export function scanDiff(diff, options = {}) {
  if (typeof diff !== 'string') throw new TypeError('scanDiff expects a string');
  const findings = [];
  const lines = diff.split(/\r?\n/);
  let currentFile = '<stdin>';
  let inHunk = false;
  let newLine = 0;
  let blockLines = [];
  let blockMap = [];

  function flushBlock() {
    if (blockLines.length === 0) return;
    const text = blockLines.join('\n');
    for (const finding of scanText(text, options)) {
      const localLine = Math.max(1, Math.min(finding.line, blockMap.length));
      findings.push({ ...finding, file: currentFile, line: blockMap[localLine - 1] || newLine });
    }
    blockLines = [];
    blockMap = [];
  }

  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    if (line.startsWith('diff --git ')) {
      flushBlock();
      currentFile = '<stdin>';
      inHunk = false;
      newLine = 0;
      continue;
    }

    if (!inHunk) {
      const header = parseNewFileHeader(line);
      if (header) {
        currentFile = header.file;
        continue;
      }
      const hunk = HUNK_HEADER.exec(line);
      if (hunk) {
        inHunk = true;
        newLine = Number(hunk[1]);
      }
      continue;
    }

    const nextHunk = HUNK_HEADER.exec(line);
    if (nextHunk) {
      flushBlock();
      newLine = Number(nextHunk[1]);
      continue;
    }
    if (line.startsWith('+')) {
      if (currentFile !== null) {
        blockLines.push(line.slice(1));
        blockMap.push(newLine);
      }
      newLine++;
      continue;
    }
    if (line.startsWith('-')) continue;
    if (line.startsWith(' ') || line === '') {
      flushBlock();
      newLine++;
      continue;
    }
    if (line.startsWith('\\')) continue;

    flushBlock();
    inHunk = false;
    index--;
  }
  flushBlock();
  return findings;
}
