// Strips data that should not leave the client's server before an audit:
// pinned data, static data, and secret-looking values in node parameters.

import fs from 'node:fs';
import path from 'node:path';
import { findSecretPairs, findSecrets } from './secrets.mjs';

export const REDACTED = '***REDACTED***';

function redactString(value, context) {
  let out = value;
  for (const { value: secret } of findSecrets(value, context)) out = out.split(secret).join(REDACTED);
  return out;
}

function redactParameters(obj, context = 'param', key = '') {
  if (typeof obj === 'string') {
    const isCode = /^(jsCode|pythonCode|functionCode|code)$/.test(key);
    return redactString(obj, isCode ? 'code' : context);
  }
  if (Array.isArray(obj)) return obj.map((v) => redactParameters(v, context));
  if (!obj || typeof obj !== 'object') return obj;
  const pairs = findSecretPairs({ v: obj }).filter((p) => p.path === 'v');
  const copy = {};
  for (const [k, v] of Object.entries(obj)) copy[k] = redactParameters(v, context, k);
  if (pairs.length && typeof copy.value === 'string') copy.value = REDACTED;
  return copy;
}

export function sanitizeWorkflow(workflow) {
  const clean = { ...workflow };
  delete clean.pinData;
  delete clean.staticData;
  clean.nodes = (workflow.nodes || []).map((n) => ({ ...n, parameters: redactParameters(n.parameters || {}) }));
  return clean;
}

/** Sanitizes every workflow JSON file in `dir` in place. Returns the number of files written. */
export function sanitizeDir(dir) {
  let written = 0;
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.json')) continue;
    const file = path.join(dir, name);
    const json = JSON.parse(fs.readFileSync(file, 'utf8'));
    const out = Array.isArray(json) ? json.map(sanitizeWorkflow) : sanitizeWorkflow(json);
    fs.writeFileSync(file, JSON.stringify(out, null, 2));
    written += 1;
  }
  return written;
}
