// Ignore rules: .gitignore-like patterns plus .secretsweepignore. This is a
// small, deliberately limited matcher: no external dependencies and no
// potentially expensive glob backtracking.

import { readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const ALWAYS_IGNORED = new Set([
  '.git', 'node_modules', '.svn', '.hg', 'vendor', 'dist', 'build',
  '.next', '.cache', '.venv', '__pycache__', '.idea', '.vscode',
]);

function parsePattern(line) {
  let text = line.trim();
  if (!text || text.startsWith('#')) return null;
  let negate = false;
  if (text.startsWith('!')) {
    negate = true;
    text = text.slice(1);
  }
  let dirOnly = false;
  if (text.endsWith('/')) {
    dirOnly = true;
    text = text.slice(0, -1);
  }
  const anchored = text.startsWith('/');
  if (anchored) text = text.slice(1);
  return { text, negate, dirOnly, anchored };
}

export function compileIgnoreRules(lines) {
  const rules = [];
  for (const line of lines) {
    const rule = parsePattern(line);
    if (rule) rules.push(rule);
  }
  return rules;
}

export function loadIgnoreFiles(root, filenames = ['.gitignore', '.secretsweepignore']) {
  const lines = [];
  for (const filename of filenames) {
    try {
      const content = readFileSync(join(root, filename), 'utf8');
      lines.push(...content.split(/\r?\n/));
    } catch {
      // Missing or unreadable ignore files simply contribute no rules.
    }
  }
  return compileIgnoreRules(lines);
}

function matchesRule(relPath, isDirectory, rule) {
  const parts = relPath.split(/[\\/]/);
  if (rule.anchored) {
    if (rule.dirOnly) return isDirectory && parts[0] === rule.text;
    return parts.includes(rule.text) && parts[0] === rule.text;
  }
  // A pattern without a slash matches any path segment.
  if (!rule.text.includes('/')) {
    if (rule.dirOnly) return isDirectory && parts.includes(rule.text);
    return parts.includes(rule.text);
  }
  // Patterns with a slash match a path prefix anchored at the scan root.
  const normalized = rule.text.replace(/\/+$/, '');
  return relPath === normalized || relPath.startsWith(normalized + '/');
}

export function isIgnored(relPath, isDirectory, rules) {
  let ignored = false;
  for (const rule of rules) {
    if (matchesRule(relPath, isDirectory, rule)) ignored = !rule.negate;
  }
  return ignored;
}

export function isAlwaysIgnored(name) {
  return ALWAYS_IGNORED.has(name);
}

export function toRelative(root, path) {
  return relative(root, path).split(sep).join('/');
}
