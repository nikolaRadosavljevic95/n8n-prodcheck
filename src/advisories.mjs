// Minimal semver matching for the ranges npm advisories use (">=1.2.3 <1.4.0", "<2.0.0", "=1.0.0", "a || b").

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DATA_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'data', 'advisories.json');

export function parseVersion(v) {
  const m = String(v).trim().replace(/^v/, '').match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/);
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] || '' };
}

export function compare(a, b) {
  const x = typeof a === 'string' ? parseVersion(a) : a;
  const y = typeof b === 'string' ? parseVersion(b) : b;
  for (const k of ['major', 'minor', 'patch']) {
    if (x[k] !== y[k]) return x[k] < y[k] ? -1 : 1;
  }
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1; // 1.0.0 > 1.0.0-rc.1
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}

function satisfiesComparator(version, comparator) {
  const m = comparator.match(/^(>=|<=|>|<|=)?\s*(.+)$/);
  if (!m) return false;
  const op = m[1] || '=';
  const target = parseVersion(m[2]);
  if (!target) return false;
  const c = compare(version, target);
  switch (op) {
    case '>=': return c >= 0;
    case '<=': return c <= 0;
    case '>': return c > 0;
    case '<': return c < 0;
    default: return c === 0;
  }
}

export function satisfies(version, range) {
  const v = parseVersion(version);
  if (!v) return false;
  return String(range).split('||').some((set) => {
    const comparators = set.trim().split(/\s+/).filter(Boolean);
    return comparators.length > 0 && comparators.every((c) => satisfiesComparator(v, c));
  });
}

export function loadAdvisories(file = DATA_FILE) {
  if (!fs.existsSync(file)) return { generatedAt: null, stable: null, advisories: [] };
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

const SEVERITY = { critical: 'critical', high: 'high', moderate: 'medium', medium: 'medium', low: 'low' };
const RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/** Advisories affecting `version`, one per GHSA id, most severe first. */
export function advisoriesFor(version, data = loadAdvisories()) {
  const byId = new Map();
  for (const a of data.advisories || []) {
    if (!satisfies(version, a.vulnerable_versions)) continue;
    const id = a.url || a.title;
    const severity = SEVERITY[a.severity] || 'medium';
    const prev = byId.get(id);
    if (!prev || RANK[severity] > RANK[prev.severity]) {
      byId.set(id, { id: String(id).split('/').pop(), url: a.url, title: a.title, severity, range: a.vulnerable_versions, cvss: a.cvss?.score ?? null });
    }
  }
  return [...byId.values()].sort((a, b) => RANK[b.severity] - RANK[a.severity] || (b.cvss ?? 0) - (a.cvss ?? 0));
}
