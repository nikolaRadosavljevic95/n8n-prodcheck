#!/usr/bin/env node
// Refreshes data/advisories.json from the public npm advisory database.
// Asks for advisories affecting any published n8n version, which returns all of them.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'data', 'advisories.json');
const REGISTRY = 'https://registry.npmjs.org';

async function getJson(url, init) {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`${init?.method || 'GET'} ${url}: HTTP ${res.status}`);
  return res.json();
}

const meta = await getJson(`${REGISTRY}/n8n`, { headers: { accept: 'application/vnd.npm.install-v1+json' } });
const versions = Object.keys(meta.versions || {});
if (!versions.length) throw new Error('No n8n versions returned by the registry');

const bulk = await getJson(`${REGISTRY}/-/npm/v1/security/advisories/bulk`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ n8n: versions }),
});

const advisories = (bulk.n8n || [])
  .map((a) => ({
    url: a.url,
    title: a.title,
    severity: a.severity,
    vulnerable_versions: a.vulnerable_versions,
    cvss: a.cvss?.score ? { score: a.cvss.score } : null,
    cwe: a.cwe || [],
  }))
  .sort((a, b) => a.url.localeCompare(b.url) || a.vulnerable_versions.localeCompare(b.vulnerable_versions));

const data = {
  generatedAt: new Date().toISOString(),
  source: 'npm advisory database (registry.npmjs.org/-/npm/v1/security/advisories/bulk), which mirrors the GitHub Advisory Database',
  stable: meta['dist-tags']?.stable || meta['dist-tags']?.latest || null,
  advisories,
};

fs.writeFileSync(OUT, JSON.stringify(data, null, 1) + '\n');
const ids = new Set(advisories.map((a) => a.url)).size;
console.log(`Wrote ${advisories.length} advisory ranges (${ids} advisories) for n8n; stable is ${data.stable}.`);
