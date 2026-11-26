// Built-in detectors. All patterns are bounded, character-class based and
// validated by ensureLinear() at registration time. Detector values never
// leave the process in reports: only a masked preview and a SHA-256 fingerprint
// are emitted by the finder.

import { createPatternDetector, registerDetector } from './registry.mjs';
import { shannonEntropy, isPlaceholder } from '../util.mjs';

const high = 'high';
const critical = 'critical';
const medium = 'medium';

createPatternDetector({
  id: 'aws-access-key-id', provider: 'AWS', name: 'AWS access key ID', severity: high,
  pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
});

createPatternDetector({
  id: 'aws-secret-access-key', provider: 'AWS', name: 'AWS secret access key', severity: critical,
  pattern: /\baws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
  value: (m) => m[1],
});

createPatternDetector({
  id: 'github-pat', provider: 'GitHub', name: 'GitHub classic personal access token', severity: high,
  pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
});

createPatternDetector({
  id: 'github-fine-grained-pat', provider: 'GitHub', name: 'GitHub fine-grained personal access token', severity: high,
  pattern: /\bgithub_pat_[A-Za-z0-9_]{40,255}\b/g,
});

createPatternDetector({
  id: 'github-oauth-token', provider: 'GitHub', name: 'GitHub OAuth token', severity: high,
  pattern: /\bgho_[A-Za-z0-9]{36}\b/g,
});

createPatternDetector({
  id: 'stripe-secret-key', provider: 'Stripe', name: 'Stripe secret key', severity: critical,
  pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{16,40}\b/g,
});

createPatternDetector({
  id: 'stripe-restricted-key', provider: 'Stripe', name: 'Stripe restricted key', severity: high,
  pattern: /\brk_(?:live|test)_[A-Za-z0-9]{16,40}\b/g,
});

createPatternDetector({
  id: 'stripe-publishable-key', provider: 'Stripe', name: 'Stripe publishable key', severity: medium,
  pattern: /\bpk_(?:live|test)_[A-Za-z0-9]{16,40}\b/g,
});

createPatternDetector({
  id: 'slack-webhook', provider: 'Slack', name: 'Slack incoming webhook URL', severity: high,
  pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,}/g,
});

createPatternDetector({
  id: 'slack-token', provider: 'Slack', name: 'Slack bot or user token', severity: high,
  pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,48}\b/g,
});

createPatternDetector({
  id: 'google-api-key', provider: 'Google', name: 'Google API key', severity: high,
  pattern: /\bAIza[A-Za-z0-9_-]{35}\b/g,
});

createPatternDetector({
  id: 'google-oauth-client-secret', provider: 'Google', name: 'Google OAuth client secret', severity: high,
  pattern: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/g,
});

createPatternDetector({
  id: 'google-refresh-token', provider: 'Google', name: 'Google OAuth refresh token', severity: high,
  pattern: /\b1\/\/0[A-Za-z0-9_-]{30,}\b/g,
});

createPatternDetector({
  id: 'openai-api-key', provider: 'OpenAI', name: 'OpenAI API key', severity: critical,
  pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
});

createPatternDetector({
  id: 'anthropic-api-key', provider: 'Anthropic', name: 'Anthropic API key', severity: critical,
  pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
});

createPatternDetector({
  id: 'huggingface-token', provider: 'Hugging Face', name: 'Hugging Face access token', severity: high,
  pattern: /\bhf_[A-Za-z0-9]{30,}\b/g,
});

createPatternDetector({
  id: 'npm-token', provider: 'npm', name: 'npm access token', severity: high,
  pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
});

createPatternDetector({
  id: 'pypi-token', provider: 'PyPI', name: 'PyPI API token', severity: high,
  pattern: /\bpypi-[A-Za-z0-9_-]{40,}\b/g,
});

createPatternDetector({
  id: 'docker-token', provider: 'Docker', name: 'Docker Hub personal access token', severity: high,
  pattern: /\bdckr_pat_[A-Za-z0-9_-]{20,}\b/g,
});

createPatternDetector({
  id: 'twilio-api-key', provider: 'Twilio', name: 'Twilio API key', severity: high,
  pattern: /\bSK[0-9a-f]{32}\b/g,
});

createPatternDetector({
  id: 'sendgrid-api-key', provider: 'SendGrid', name: 'SendGrid API key', severity: high,
  pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
});

createPatternDetector({
  id: 'discord-bot-token', provider: 'Discord', name: 'Discord bot token', severity: high,
  pattern: /\b[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}\b/g,
});

createPatternDetector({
  id: 'telegram-bot-token', provider: 'Telegram', name: 'Telegram bot token', severity: high,
  pattern: /\b\d{8,12}:[A-Za-z0-9_-]{30,}\b/g,
});

createPatternDetector({
  id: 'mailgun-api-key', provider: 'Mailgun', name: 'Mailgun API key', severity: high,
  pattern: /\bkey-[0-9a-fA-F]{32}\b/g,
});

createPatternDetector({
  id: 'mailchimp-api-key', provider: 'Mailchimp', name: 'Mailchimp API key', severity: high,
  pattern: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/g,
});

createPatternDetector({
  id: 'square-access-token', provider: 'Square', name: 'Square access token', severity: high,
  pattern: /\bsq0atp-[A-Za-z0-9_-]{20,}\b/g,
});

createPatternDetector({
  id: 'datadog-api-key', provider: 'Datadog', name: 'Datadog API key', severity: high,
  pattern: /\b(?:dd|datadog)[A-Za-z0-9]{0,8}[:=]\s*["']?([0-9a-f]{32})["']?/gi,
  value: (m) => m[1],
});

createPatternDetector({
  id: 'new-relic-license-key', provider: 'New Relic', name: 'New Relic license key', severity: high,
  pattern: /\b(?:new_relic|newrelic|license_key)\s*[:=]\s*["']?([A-Za-z0-9]{32,40})["']?/gi,
  value: (m) => m[1],
});

createPatternDetector({
  id: 'sonarqube-token', provider: 'SonarQube', name: 'SonarQube user token', severity: high,
  pattern: /\bsqu_[A-Za-z0-9]{40}\b/g,
});

createPatternDetector({
  id: 'db-uri-password', provider: 'Database', name: 'Database URI with password', severity: high,
  pattern: /\b([a-z][a-z0-9+.-]*):\/\/([^:\s/@]+):([^@\s/]{3,})@/gi,
  value: (m) => m[3],
});

createPatternDetector({
  id: 'jwt-in-config', provider: 'JWT', name: 'JSON Web Token in configuration', severity: medium,
  pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
});

// PEM private keys need a bounded body scan. indexOf is linear and avoids a
// potentially backtracking lazy repeat over large files.
registerDetector({
  id: 'pem-private-key', provider: 'PEM', name: 'PEM encoded private key', severity: critical,
  pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{1,20000}?-----END/g,
  check(text) {
    const hits = [];
    // Each pair is (begin marker, matching end marker). Linear indexOf scans.
    const pairs = [
      ['-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----'],
      ['-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----'],
      ['-----BEGIN EC PRIVATE KEY-----', '-----END EC PRIVATE KEY-----'],
      ['-----BEGIN DSA PRIVATE KEY-----', '-----END DSA PRIVATE KEY-----'],
      ['-----BEGIN OPENSSH PRIVATE KEY-----', '-----END OPENSSH PRIVATE KEY-----'],
      ['-----BEGIN ENCRYPTED PRIVATE KEY-----', '-----END ENCRYPTED PRIVATE KEY-----'],
    ];
    let cursor = 0;
    while (cursor < text.length) {
      let begin = -1;
      let pair = null;
      for (const candidate of pairs) {
        const at = text.indexOf(candidate[0], cursor);
        if (at !== -1 && (begin === -1 || at < begin)) {
          begin = at;
          pair = candidate;
        }
      }
      if (begin === -1 || pair === null) break;
      const end = text.indexOf(pair[1], begin);
      if (end === -1) break;
      const value = text.slice(begin, end + pair[1].length);
      hits.push({ value, index: begin });
      cursor = end + pair[1].length;
      if (hits.length >= 100) break;
    }
    return hits;
  },
});

const ASSIGNMENT_PATTERN = /([A-Za-z0-9_.-]{0,40}(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|auth)[A-Za-z0-9_.-]{0,40})\s*[:=]\s*["']?([^\s"',;]{8,200})["']?/gi;

registerDetector({
  id: 'generic-secret-assignment', provider: 'Generic', name: 'High-entropy secret assignment', severity: medium,
  pattern: ASSIGNMENT_PATTERN,
  check(text) {
    const hits = [];
    const re = new RegExp(ASSIGNMENT_PATTERN.source, 'gi');
    let match;
    while ((match = re.exec(text)) !== null) {
      const value = match[2];
      if (!value) continue;
      if (shannonEntropy(value) < 3.2) continue;
      hits.push({ value, index: match.index + match[0].indexOf(value) });
      if (hits.length >= 1000) break;
    }
    return hits;
  },
});

const WORD_RE = /[A-Za-z0-9+/_-]{32,200}/g;

registerDetector({
  id: 'high-entropy-generic', provider: 'Generic', name: 'High-entropy unlabelled token', severity: medium,
  pattern: WORD_RE,
  check(text) {
    const hits = [];
    const re = new RegExp(WORD_RE.source, 'g');
    let match;
    while ((match = re.exec(text)) !== null) {
      const value = match[0];
      if (shannonEntropy(value) < 4.3) continue;
      const before = text.slice(Math.max(0, match.index - 24), match.index);
      const after = text.slice(match.index + value.length, match.index + value.length + 2);
      const assigned = /(?:["'=:]|^)\s*$/.test(before) || /^["']/.test(after);
      if (!assigned) continue;
      hits.push({ value, index: match.index });
      if (hits.length >= 1000) break;
    }
    return hits;
  },
});
