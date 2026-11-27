// Deterministic output formats: text, JSON and SARIF 2.1.0. Findings never
// contain raw secret values.

import { VERSION } from './util.mjs';

const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
const SARIF_LEVEL = { low: 'warning', medium: 'warning', high: 'error', critical: 'error' };

function safeDisplay(value) {
  return String(value).replace(/[\x00-\x1f\x7f]/g, (char) => {
    if (char === '\n') return '\\n';
    if (char === '\r') return '\\r';
    if (char === '\t') return '\\t';
    return `\\x${char.charCodeAt(0).toString(16).padStart(2, '0')}`;
  });
}

function sarifArtifactUri(file) {
  let text = String(file || '').replace(/\\/g, '/');
  if (!text || text === '<text>') return 'stdin';

  if (/^(?:[A-Za-z]:\/|\/)/.test(text)) {
    const parts = text.split('/').filter(Boolean);
    text = parts[parts.length - 1] || 'artifact';
  } else {
    const segments = [];
    for (const segment of text.split('/')) {
      if (!segment || segment === '.') continue;
      if (segment === '..') {
        segments.pop();
        continue;
      }
      segments.push(segment);
    }
    text = segments.join('/') || 'artifact';
  }
  return text.split('/').map((segment) => encodeURIComponent(segment)).join('/');
}

export function formatText(findings, options = {}) {
  if (findings.length === 0) {
    return options.cleanMessage || 'secretsweep: no secrets found\n';
  }
  const lines = [`secretsweep: ${findings.length} potential secret${findings.length === 1 ? '' : 's'} found`];
  for (const finding of findings) {
    const where = `${safeDisplay(finding.file || '<text>')}:${finding.line}:${finding.column}`;
    lines.push(`${where} [${safeDisplay(finding.severity)}] ${safeDisplay(finding.provider)} (${safeDisplay(finding.detector)}) ${safeDisplay(finding.redacted)} sha256:${finding.fingerprint.slice(0, 12)}`);
  }
  return lines.join('\n') + '\n';
}

export function formatJson(findings, options = {}) {
  return JSON.stringify({
    tool: 'secretsweep',
    version: VERSION,
    count: findings.length,
    findings,
    ...(options.skipped ? { skipped: options.skipped } : {}),
  }, null, 2) + '\n';
}

export function formatSarif(findings, options = {}) {
  const rules = [];
  const seenRules = new Set();
  const results = findings.map((finding) => {
    if (!seenRules.has(finding.detector)) {
      seenRules.add(finding.detector);
      rules.push({
        id: finding.detector,
        name: finding.detector,
        shortDescription: { text: finding.name || finding.provider },
        defaultConfiguration: { level: SARIF_LEVEL[finding.severity] || 'warning' },
        properties: { tags: ['security', 'secrets', finding.provider] },
      });
    }
    return {
      ruleId: finding.detector,
      level: SARIF_LEVEL[finding.severity] || 'warning',
      message: { text: `${finding.provider}: potential ${finding.name || 'secret'} (${finding.redacted})` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: sarifArtifactUri(finding.file) },
          region: {
            startLine: Math.max(1, finding.line || 1),
            startColumn: Math.max(1, finding.column || 1),
          },
        },
      }],
      partialFingerprints: { secretsweepFingerprint: finding.fingerprint },
    };
  });
  rules.sort((a, b) => a.id.localeCompare(b.id));
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'secretsweep',
          version: VERSION,
          informationUri: 'https://github.com/draarivpatel-ui/secretsweep',
          rules,
        },
      },
      results,
      ...(options.originalUriBaseIds ? { originalUriBaseIds: options.originalUriBaseIds } : {}),
    }],
  }, null, 2) + '\n';
}

export function format(findings, formatName, options = {}) {
  switch (formatName) {
    case 'text': return formatText(findings, options);
    case 'json': return formatJson(findings, options);
    case 'sarif': return formatSarif(findings, options);
    default: throw new Error(`unknown output format: ${formatName}`);
  }
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) =>
    (a.file || '').localeCompare(b.file || '') ||
    a.line - b.line || a.column - b.column ||
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    a.detector.localeCompare(b.detector) ||
    a.fingerprint.localeCompare(b.fingerprint));
}
