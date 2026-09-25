// Secret detection shared by the check and by the sanitizer.

export const PROVIDER_PATTERNS = [
  { kind: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { kind: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g },
  { kind: 'Stripe secret key', re: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { kind: 'Stripe webhook secret', re: /\bwhsec_[A-Za-z0-9]{16,}/g },
  { kind: 'AWS access key id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})/g },
  { kind: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { kind: 'Slack webhook URL', re: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{16,}/g },
  { kind: 'Discord webhook URL', re: /discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{30,}/g },
  { kind: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g },
  { kind: 'Telegram bot token', re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  { kind: 'Private key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g },
  { kind: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { kind: 'Password in URL', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/'"`]+:[^\s@/'"`{]{3,}@[^\s'"`]+/gi },
];

const SECRET_NAME = /(api[_-]?key|apikey|secret|token|passw(or)?d|pwd|private[_-]?key|client[_-]?secret|access[_-]?key|auth(orization)?|bearer|signing[_-]?key|webhook[_-]?key)/i;

const CODE_ASSIGNMENT = /([A-Za-z_$][\w$]*(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|private[_-]?key|access[_-]?key|signing[_-]?key)[\w$]*|api[_-]?key|apikey|secret|token|password|passwd|pwd|bearer)["']?\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/gi;

const PLACEHOLDER = /^(x{3,}|\*{3,}|\.{3,}|<.*>|\[.*\]|\{.*\}|your[_-].*|.*[_-]here|change[_-]?me|example.*|placeholder|dummy|sample|todo|replace.*|insert.*|none|null|undefined|test|secret|password|token|redacted.*|\*\*\*redacted\*\*\*)$/i;

export function entropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function mask(secret) {
  const s = String(secret);
  return `${s.slice(0, 4)}… (${s.length} chars)`;
}

const isExpression = (v) => typeof v === 'string' && (v.startsWith('=') || v.includes('{{'));
const referencesEnv = (v) => /\$env|process\.env|\$credentials|\$secrets|\$vars/.test(v);

export function looksSecret(value) {
  const v = String(value).trim();
  if (v.length < 8 || PLACEHOLDER.test(v) || referencesEnv(v)) return false;
  if (/^https?:\/\//i.test(v) && !/:[^/@]+@/.test(v)) return false;
  return entropy(v) >= 3.0;
}

/**
 * Finds secrets in one string. `context` is 'code' for Code-node source,
 * anything else for parameter values.
 */
export function findSecrets(text, context = 'param') {
  const found = [];
  if (typeof text !== 'string' || !text) return found;
  const seen = new Set();
  for (const { kind, re } of PROVIDER_PATTERNS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      if (seen.has(m[0]) || m[0].includes('REDACTED')) continue;
      seen.add(m[0]);
      found.push({ kind, value: m[0] });
    }
  }
  if (context === 'code') {
    CODE_ASSIGNMENT.lastIndex = 0;
    for (const m of text.matchAll(CODE_ASSIGNMENT)) {
      const value = m[2];
      if (seen.has(value) || !looksSecret(value)) continue;
      if (found.some((f) => f.value.includes(value) || value.includes(f.value))) continue;
      seen.add(value);
      found.push({ kind: `hardcoded ${m[1]}`, value });
    }
  }
  return found;
}

/**
 * Header / query / body parameter entries shaped like { name, value } whose
 * name says "secret" and whose value is a literal, not an expression.
 */
export function findSecretPairs(parameters) {
  const found = [];
  const visit = (obj, path) => {
    if (Array.isArray(obj)) return obj.forEach((v, i) => visit(v, `${path}[${i}]`));
    if (!obj || typeof obj !== 'object') return;
    if (typeof obj.name === 'string' && typeof obj.value === 'string' && SECRET_NAME.test(obj.name)) {
      const raw = obj.value.replace(/^bearer\s+/i, '');
      if (!isExpression(obj.value) && looksSecret(raw)) {
        found.push({ kind: `literal "${obj.name}" value`, value: raw, path });
      }
    }
    for (const [k, v] of Object.entries(obj)) visit(v, path ? `${path}.${k}` : k);
  };
  visit(parameters, '');
  return found;
}
