// Ignore rules: .gitignore-like patterns plus .secretsweepignore. This is a
// small, deliberately limited matcher: no external dependencies and no
// potentially expensive glob backtracking.

import { readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const ALWAYS_IGNORED = new Set([
  '.git', 'node_modules', '.svn', '.hg', 'vendor', 'dist', 'build',
  '.next', '.cache', '.venv', '__pycache__', '.idea', '.vscode',
]);

const MAX_PATTERN_CHARS = 1024;
const MAX_IGNORE_FILE_BYTES = 1024 * 1024;

function isEscaped(text, index) {
  let count = 0;
  for (let i = index - 1; i >= 0 && text[i] === '\\'; i--) count++;
  return count % 2 === 1;
}

function stripUnescapedTrailingSpaces(line) {
  let end = line.length;
  while (end > 0 && line[end - 1] === ' ' && !isEscaped(line, end - 1)) end--;
  return line.slice(0, end);
}

function parsePattern(line) {
  let text = stripUnescapedTrailingSpaces(line);
  if (!text || text.startsWith('#')) return null;

  let literalFirst = false;
  if (text.startsWith('\\#') || text.startsWith('\\!')) {
    text = text.slice(1);
    literalFirst = true;
  }

  let negate = false;
  if (!literalFirst && text.startsWith('!')) {
    negate = true;
    text = text.slice(1);
  }

  let dirOnly = false;
  if (text.endsWith('/')) {
    dirOnly = true;
    text = text.slice(0, -1);
  }

  let anchored = false;
  if (text.startsWith('/')) {
    anchored = true;
    text = text.slice(1);
  }
  if (!text || text.length > MAX_PATTERN_CHARS) return null;

  const leadingGlobstar = text.startsWith('**/');
  const hasSlash = text.includes('/');
  const rootAnchored = anchored || (hasSlash && !leadingGlobstar);
  return { text, parts: text.split('/'), negate, dirOnly, anchored: rootAnchored };
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
    const file = join(root, filename);
    let stats;
    try {
      stats = statSync(file);
    } catch {
      continue;
    }
    if (stats.size > MAX_IGNORE_FILE_BYTES) {
      throw new Error(`ignore file ${filename} exceeds ${MAX_IGNORE_FILE_BYTES} bytes`);
    }
    try {
      const content = readFileSync(file, 'utf8');
      lines.push(...content.split(/\r?\n/));
    } catch {
      // Unreadable ignore files simply contribute no rules.
    }
  }
  return compileIgnoreRules(lines);
}

function classChar(pattern, index) {
  if (pattern[index] === '\\' && index + 1 < pattern.length) {
    return { char: pattern[index + 1], next: index + 2 };
  }
  return { char: pattern[index], next: index + 1 };
}

function matchClass(pattern, start, char) {
  let index = start + 1;
  let negate = false;
  if (pattern[index] === '!' || pattern[index] === '^') {
    negate = true;
    index++;
  }

  let first = true;
  let matched = false;
  let closed = false;
  while (index < pattern.length) {
    if (pattern[index] === ']' && !first) {
      closed = true;
      index++;
      break;
    }

    const low = classChar(pattern, index);
    index = low.next;
    if (index < pattern.length && pattern[index] === '-' && index + 1 < pattern.length && pattern[index + 1] !== ']') {
      const high = classChar(pattern, index + 1);
      index = high.next;
      if (char >= low.char && char <= high.char) matched = true;
    } else if (char === low.char) {
      matched = true;
    }
    first = false;
  }

  if (!closed) return { matched: char === '[', next: start + 1 };
  return { matched: negate ? !matched : matched, next: index };
}

function matchSegment(pattern, text) {
  if (pattern.length > MAX_PATTERN_CHARS || text.length > 4096) return false;
  const memo = new Map();

  function dp(pi, ti) {
    const key = `${pi}:${ti}`;
    if (memo.has(key)) return memo.get(key);
    let result = false;

    if (pi === pattern.length) {
      result = ti === text.length;
    } else if (pattern[pi] === '*') {
      let next = pi;
      while (next < pattern.length && pattern[next] === '*') next++;
      for (let end = ti; end <= text.length; end++) {
        if (dp(next, end)) {
          result = true;
          break;
        }
      }
    } else if (pattern[pi] === '?') {
      result = ti < text.length && dp(pi + 1, ti + 1);
    } else if (pattern[pi] === '[') {
      if (ti < text.length) {
        const cls = matchClass(pattern, pi, text[ti]);
        result = cls.matched && dp(cls.next, ti + 1);
      }
    } else {
      let literal = pattern[pi];
      let next = pi + 1;
      if (literal === '\\' && pi + 1 < pattern.length) {
        literal = pattern[pi + 1];
        next = pi + 2;
      }
      result = ti < text.length && text[ti] === literal && dp(next, ti + 1);
    }

    memo.set(key, result);
    return result;
  }

  return dp(0, 0);
}

function matchParts(patternParts, pathParts) {
  const memo = new Map();

  function dp(pi, ti) {
    const key = `${pi}:${ti}`;
    if (memo.has(key)) return memo.get(key);
    let result = false;
    if (pi === patternParts.length) {
      result = ti === pathParts.length;
    } else if (patternParts[pi] === '**') {
      if (pi === patternParts.length - 1) {
        result = ti < pathParts.length;
      } else {
        result = dp(pi + 1, ti) || (ti < pathParts.length && dp(pi, ti + 1));
      }
    } else if (ti < pathParts.length) {
      result = matchSegment(patternParts[pi], pathParts[ti]) && dp(pi + 1, ti + 1);
    }
    memo.set(key, result);
    return result;
  }

  return dp(0, 0);
}

function matchesRule(relPath, isDirectory, rule) {
  const parts = relPath.split(/[\\/]/).filter(Boolean);
  if (parts.length === 0) return false;

  if (!rule.anchored && rule.parts.length === 1) {
    for (let index = 0; index < parts.length; index++) {
      const componentIsDirectory = index < parts.length - 1 || isDirectory;
      if (rule.dirOnly && !componentIsDirectory) continue;
      if (matchSegment(rule.parts[0], parts[index])) return true;
    }
    return false;
  }

  for (let end = 1; end <= parts.length; end++) {
    const candidateIsDirectory = end < parts.length || isDirectory;
    if (rule.dirOnly && !candidateIsDirectory) continue;
    if (matchParts(rule.parts, parts.slice(0, end))) return true;
  }
  return false;
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
