// Directory and file scanner. Skips binary files, honours ignore files,
// guards symlink loops and enforces a maximum file size.

import { readFileSync, readdirSync, lstatSync, realpathSync, statSync } from 'node:fs';
import { join, resolve, extname } from 'node:path';
import { scanText } from './finder.mjs';
import { loadIgnoreFiles, isIgnored, isAlwaysIgnored, toRelative } from './ignore.mjs';

export const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.avif',
  '.pdf', '.zip', '.gz', '.tar', '.bz2', '.xz', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.o', '.a', '.class', '.jar',
  '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp3', '.mp4',
  '.mov', '.avi', '.wav', '.flac', '.webm', '.sqlite', '.db',
  '.p12', '.pfx', '.keystore', '.pyc', '.node', '.wasm',
]);

export function looksBinary(buffer) {
  const length = Math.min(buffer.length, 8192);
  for (let i = 0; i < length; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

export function isBinaryPath(path) {
  return BINARY_EXTENSIONS.has(extname(path).toLowerCase());
}

function readTextFile(path, maxBytes) {
  const stats = statSync(path);
  if (!stats.isFile()) return null;
  if (stats.size > maxBytes) return null;
  const buffer = readFileSync(path);
  if (isBinaryPath(path) || looksBinary(buffer)) return null;
  return buffer.toString('utf8');
}

export function scanPath(target, options = {}) {
  const root = resolve(target);
  const maxBytes = options.maxFileBytes || DEFAULT_MAX_FILE_BYTES;
  const rules = options.ignoreRules || loadIgnoreFiles(root);
  const results = [];
  const skipped = [];
  const visited = new Set();
  const extraRules = options.exclude || [];

  function visit(path, relPath, isDirectory) {
    if (relPath && isAlwaysIgnored(relPath.split('/').pop())) return;
    if (extraRules.some((pattern) => relPath === pattern || relPath.startsWith(pattern + '/'))) return;
    if (relPath && isIgnored(relPath, isDirectory, rules)) return;

    let stat;
    let identity;
    try {
      stat = lstatSync(path);
      identity = realpathSync(path);
    } catch {
      skipped.push({ path: relPath, reason: 'broken-symlink' });
      return;
    }
    if (stat.isSymbolicLink()) {
      if (visited.has(identity)) {
        skipped.push({ path: relPath, reason: 'symlink-loop' });
        return;
      }
      try {
        stat = statSync(path);
      } catch {
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
      entries.sort().forEach((entry) => visit(join(path, entry), relPath ? `${relPath}/${entry}` : entry, false));
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

  let rootStat;
  try {
    rootStat = statSync(root);
  } catch (error) {
    throw new Error(`cannot read ${root}: ${error.message}`);
  }
  if (rootStat.isDirectory()) {
    visit(root, '', true);
  } else {
    visit(root, root.split('/').pop(), false);
  }
  return { findings: results, skipped, root };
}

export function scanDiff(diff, options = {}) {
  if (typeof diff !== 'string') throw new TypeError('scanDiff expects a string');
  const findings = [];
  let currentFile = '<stdin>';
  let newLine = 0;

  for (const line of diff.split(/\r?\n/)) {
    const header = /^\+\+\+\s+[ab]\/(.+)$/.exec(line);
    if (header) {
      currentFile = header[1].split('\t')[0];
      continue;
    }
    if (line.startsWith('diff --git ')) {
      currentFile = '<stdin>';
      newLine = 0;
      continue;
    }
    if (/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)/.test(line)) {
      newLine = Number(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)/.exec(line)[1]);
      continue;
    }
    if (line.startsWith('+') && !line.startsWith('+++')) {
      const text = line.slice(1);
      for (const finding of scanText(text, options)) {
        findings.push({ ...finding, file: currentFile, line: newLine });
      }
      newLine++;
    } else if (!line.startsWith('-') && !line.startsWith('\\')) {
      newLine++;
    }
  }
  return findings;
}
