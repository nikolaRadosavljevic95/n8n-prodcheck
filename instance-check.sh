#!/bin/sh
# n8n-prodcheck instance export
#
# Run this on YOUR server, where the `n8n` command works (inside the n8n container
# or on the host of an npm install). It is read-only for your instance: it exports
# workflow definitions, never credentials, and cleans them before anything leaves
# the machine. See INSTANCE-CHECK.md for what is and is not collected.
#
#   sh instance-check.sh [output-dir]
#
# Docker:
#   docker cp instance-check.sh n8n:/tmp/instance-check.sh
#   docker exec -u node n8n sh /tmp/instance-check.sh /tmp/prodcheck-export
#   docker cp n8n:/tmp/prodcheck-export.tar.gz .

set -eu

OUT="${1:-./prodcheck-export}"
mkdir -p "$OUT/workflows"

if [ "${PRODCHECK_SKIP_EXPORT:-}" != "1" ]; then
  command -v n8n >/dev/null 2>&1 || { echo "The n8n command was not found. Run this where n8n is installed (for Docker, inside the container)." >&2; exit 1; }
  n8n --version > "$OUT/n8n-version.txt" 2>/dev/null || echo "unknown" > "$OUT/n8n-version.txt"
  # Workflow definitions only. Credentials are deliberately NOT exported.
  n8n export:workflow --all --separate --output="$OUT/workflows/" >/dev/null
fi

# Clean every exported workflow in place: remove pinned data and static data,
# and replace anything that looks like a secret with ***REDACTED***.
node - "$OUT/workflows" <<'NODE'
const fs = require('fs');
const path = require('path');
const dir = process.argv[2];
const R = '***REDACTED***';
const PROVIDERS = [
  /\bsk-ant-[A-Za-z0-9_-]{20,}/g, /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g,
  /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/g, /\bwhsec_[A-Za-z0-9]{16,}/g, /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})/g, /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{16,}/g,
  /discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{30,}/g, /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g, /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];
const SECRET_NAME = /(api[_-]?key|apikey|secret|token|passw(or)?d|pwd|private[_-]?key|client[_-]?secret|access[_-]?key|auth(orization)?|bearer|signing[_-]?key|webhook[_-]?key)/i;
const CODE_SECRET = /(\b[A-Za-z_$][\w$]*(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|private[_-]?key|access[_-]?key|signing[_-]?key)[\w$]*|\bapi[_-]?key|\bapikey|\bsecret|\btoken|\bpassword|\bpasswd|\bpwd|\bbearer)(["']?\s*[:=]\s*)(["'`])([^"'`\s]{6,})\3/gi;
const URL_PASSWORD = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/'"`]+:)([^\s@/'"`{]{3,})(@)/gi;
function clean(s, isCode) {
  let out = s;
  for (const re of PROVIDERS) out = out.replace(re, R);
  out = out.replace(URL_PASSWORD, `$1${R}$3`);
  if (isCode) out = out.replace(CODE_SECRET, (m, name, sep, q, value) => /\$env|process\.env/.test(value) ? m : `${name}${sep}${q}${R}${q}`);
  return out;
}
function walk(v, key) {
  if (typeof v === 'string') return clean(v, /^(jsCode|pythonCode|functionCode|code)$/.test(key || ''));
  if (Array.isArray(v)) return v.map((x) => walk(x));
  if (!v || typeof v !== 'object') return v;
  const o = {};
  for (const [k, x] of Object.entries(v)) o[k] = walk(x, k);
  if (typeof o.name === 'string' && typeof o.value === 'string' && SECRET_NAME.test(o.name)
      && !o.value.startsWith('=') && !o.value.includes('{{') && o.value.length >= 6) o.value = R;
  return o;
}
function sanitize(w) {
  const c = { ...w };
  delete c.pinData;
  delete c.staticData;
  c.nodes = (w.nodes || []).map((n) => ({ ...n, parameters: walk(n.parameters || {}) }));
  return c;
}
let count = 0;
for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.json'))) {
  const file = path.join(dir, f);
  const json = JSON.parse(fs.readFileSync(file, 'utf8'));
  fs.writeFileSync(file, JSON.stringify(Array.isArray(json) ? json.map(sanitize) : sanitize(json), null, 2));
  count += 1;
}
console.log(`Cleaned ${count} workflow file(s): pinned data and static data removed, secret-looking values redacted.`);
NODE

tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")"
echo "Done: $OUT.tar.gz"
echo "Open a few files in $OUT/workflows and check nothing sensitive is left before you send the archive."
