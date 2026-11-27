#!/usr/bin/env node
// secretsweep command line interface.
// Exit codes: 0 = clean, 1 = findings, 2 = usage/error.

import { readFileSync } from 'node:fs';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import {
  VERSION, scanText, scanPath, scanDiff, listDetectors,
  readBaseline, applyBaseline, writeBaseline, format, sortFindings,
} from '../src/index.mjs';

const EXIT_CLEAN = 0;
const EXIT_FINDINGS = 1;
const EXIT_USAGE = 2;

const HELP = `secretsweep ${VERSION}

Usage:
  secretsweep [options] [path ...]
  secretsweep [options] --diff
  secretsweep [options] --stdin

Options:
  --diff                 Scan a unified git diff from standard input
  --stdin                Scan standard input as plain text
  --format <name>        text, json or sarif (default: text)
  --baseline <file>      Suppress findings already present in the baseline
  --write-baseline <file> Write current findings as a baseline and exit 0
  --detectors <list>     Comma separated detector ids (default: all)
  --severity <level>     low, medium, high or critical
  --max-file-bytes <n>   Maximum file size to scan (default: 2097152)
  --exclude <pattern>    Exclude a path prefix (repeatable)
  --list-detectors       Print detector ids and exit
  -h, --help             Show this help
  -v, --version          Print the version

Exit codes:
  0  no findings (or baseline written)
  1  at least one finding
  2  invalid usage or input error

Reports contain masked previews and SHA-256 fingerprints only; raw secret
values are never printed. An inline "# secretsweep:ignore" comment ignores a
single line.
`;

function fail(message) {
  process.stderr.write(`secretsweep: ${message}\n`);
  process.stderr.write('Run "secretsweep --help" for usage.\n');
  process.exit(EXIT_USAGE);
}

function consumeValue(argv, i, flag) {
  const value = argv[i + 1];
  if (value === undefined || value.startsWith('--')) fail(`${flag} requires a value`);
  return value;
}

export function parseArgs(argv) {
  const options = {
    paths: [], diff: false, stdin: false, format: 'text',
    baseline: null, writeBaseline: null, detectors: null,
    severity: null, maxFileBytes: 2 * 1024 * 1024,
    exclude: [], listDetectors: false, help: false, version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--diff') options.diff = true;
    else if (arg === '--stdin') options.stdin = true;
    else if (arg === '--format') options.format = consumeValue(argv, i++, '--format');
    else if (arg === '--baseline') options.baseline = consumeValue(argv, i++, '--baseline');
    else if (arg === '--write-baseline') options.writeBaseline = consumeValue(argv, i++, '--write-baseline');
    else if (arg === '--detectors') {
      const value = consumeValue(argv, i++, '--detectors');
      options.detectors = value.split(',').map((v) => v.trim()).filter(Boolean);
    } else if (arg === '--severity') options.severity = consumeValue(argv, i++, '--severity');
    else if (arg === '--max-file-bytes') {
      const value = consumeValue(argv, i++, '--max-file-bytes');
      const bytes = Number(value);
      if (!Number.isSafeInteger(bytes) || bytes <= 0) fail('--max-file-bytes must be a positive integer');
      options.maxFileBytes = bytes;
    } else if (arg === '--exclude') options.exclude.push(consumeValue(argv, i++, '--exclude'));
    else if (arg === '--list-detectors') options.listDetectors = true;
    else if (arg === '-h' || arg === '--help') options.help = true;
    else if (arg === '-v' || arg === '--version') options.version = true;
    else if (arg.startsWith('-')) fail(`unknown option: ${arg}`);
    else options.paths.push(arg);
  }
  if (!['text', 'json', 'sarif'].includes(options.format)) fail(`unknown format: ${options.format}`);
  if (!['low', 'medium', 'high', 'critical', null].includes(options.severity)) fail(`unknown severity: ${options.severity}`);
  if (options.detectors) {
    if (options.detectors.length === 0) fail('--detectors requires at least one detector id');
    const known = new Set(listDetectors().map((detector) => detector.id));
    const unknown = options.detectors.filter((id) => !known.has(id));
    if (unknown.length) fail(`unknown detector: ${unknown.join(',')}`);
  }
  if ((options.diff ? 1 : 0) + (options.stdin ? 1 : 0) + (options.paths.length ? 1 : 0) > 1) {
    fail('choose exactly one input mode: paths, --diff or --stdin');
  }
  return options;
}

export function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(HELP);
    return EXIT_CLEAN;
  }
  if (options.version) {
    process.stdout.write(`secretsweep ${VERSION}\n`);
    return EXIT_CLEAN;
  }
  if (options.listDetectors) {
    for (const detector of listDetectors()) {
      process.stdout.write(`${detector.id}\t${detector.provider}\t${detector.severity}\n`);
    }
    return EXIT_CLEAN;
  }

  const scanOptions = {
    detectors: options.detectors,
    minSeverity: options.severity,
    maxFileBytes: options.maxFileBytes,
    exclude: options.exclude,
  };
  let findings = [];
  let skipped = [];

  try {
    if (options.diff || options.stdin) {
      const input = readFileSync(0, 'utf8');
      findings = options.diff ? scanDiff(input, scanOptions) : scanText(input, scanOptions);
    } else {
      const paths = options.paths.length ? options.paths : ['.'];
      for (const path of paths) {
        const result = scanPath(path, scanOptions);
        findings.push(...result.findings);
        skipped.push(...result.skipped);
      }
    }
  } catch (error) {
    fail(error.message);
  }

  findings = sortFindings(findings);
  if (options.writeBaseline) {
    try {
      const count = writeBaseline(options.writeBaseline, findings);
      process.stdout.write(`secretsweep: wrote ${count} baseline entries\n`);
      return EXIT_CLEAN;
    } catch (error) {
      fail(error.message);
    }
  }
  if (options.baseline) {
    try {
      findings = applyBaseline(findings, readBaseline(options.baseline));
    } catch (error) {
      fail(error.message);
    }
  }

  process.stdout.write(format(findings, options.format, { skipped }));
  return findings.length > 0 ? EXIT_FINDINGS : EXIT_CLEAN;
}

if (process.argv[1] && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  process.exitCode = main();
}
