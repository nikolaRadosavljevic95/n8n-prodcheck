// Test suite. No dependencies: node test/run.mjs

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { advisoriesFor, compare, loadAdvisories, satisfies } from '../src/advisories.mjs';
import { runCheck } from '../src/check.mjs';
import { renderMarkdown } from '../src/report.mjs';
import { RULES } from '../src/rules.mjs';
import { sanitizeWorkflow } from '../src/sanitize.mjs';
import { findSecretPairs, findSecrets } from '../src/secrets.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const F = (...p) => path.join(ROOT, 'fixtures', ...p);
const CLI = path.join(ROOT, 'bin', 'prodcheck.mjs');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'prodcheck-'));
const ruleIds = (findings) => [...new Set(findings.map((f) => f.rule))].sort();

// Secrets in well-known formats, assembled at runtime so that no real-looking
// key is ever committed to this repository.
const j = (...parts) => parts.join('');
const PROVIDER_SAMPLES = {
  'OpenAI API key': j('sk-', 'proj-', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6'),
  'Anthropic API key': j('sk-', 'ant-', 'api03-', 'Zq8Xw7Vu6Ts5Rq4Po3Nm2Lk1'),
  'Stripe secret key': j('sk', '_live_', '51H8zQeKx7Lm2Np4Rs6Tu8Vw0'),
  'Stripe webhook secret': j('wh', 'sec_', 'Qw3Er5Ty7Ui9Op1As3Df5Gh'),
  'AWS access key id': j('AK', 'IA', 'Z7Q4XK2M9P3L5N8R'),
  'GitHub token': j('gh', 'p_', 'aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5'),
  'Slack token': j('xo', 'xb-', '1234567890-0987654321-AbCdEfGhIjKl'),
  'Google API key': j('AI', 'za', 'SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6q'),
  'Private key': j('-----BEGIN ', 'RSA PRIVATE', ' KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----'),
  'Password in URL': j('postgres://app:', 'S3cr3tPassw0rd', '@db.internal:5432/app'),
};

function providerWorkflow() {
  return {
    name: 'Secrets: provider formats',
    settings: { errorWorkflow: 'x' },
    connections: {},
    nodes: [
      { name: 'Code', type: 'n8n-nodes-base.code', parameters: { jsCode: Object.values(PROVIDER_SAMPLES).map((v, i) => `const k${i} = ${JSON.stringify(v)};`).join('\n') } },
      { name: 'Note', type: 'n8n-nodes-base.stickyNote', parameters: { content: `temp key: ${PROVIDER_SAMPLES['OpenAI API key']}` } },
    ],
  };
}

// ---------------------------------------------------------------------------

const expectedBad = JSON.parse(fs.readFileSync(F('expected-bad.json'), 'utf8'));

for (const [file, rules] of Object.entries(expectedBad)) {
  test(`bad fixture ${file} triggers exactly ${rules.join(', ')}`, () => {
    const result = runCheck({ targets: [F('bad', file)] });
    assert.deepEqual(ruleIds(result.findings), [...rules].sort());
  });
}

test('every per-workflow rule has at least one bad fixture', () => {
  const covered = new Set(Object.values(expectedBad).flat());
  const missing = RULES.filter((r) => r.scope !== 'run' && !covered.has(r.id)).map((r) => r.id);
  assert.deepEqual(missing, []);
});

test('good fixture has no findings', () => {
  const result = runCheck({ targets: [F('good')] });
  assert.deepEqual(result.findings, []);
});

test('portfolio workflows: only the known RFQ authentication findings remain after review', () => {
  const ignore = JSON.parse(fs.readFileSync(F('portfolio', '.prodcheck-ignore.json'), 'utf8')).ignore;
  const result = runCheck({ targets: [F('portfolio')], ignore });
  const got = result.findings.map((f) => `${f.severity} ${f.rule} ${f.workflow} / ${f.node}`).sort();
  assert.deepEqual(got, [
    'high WEBHOOK-NO-AUTH RFQ: API (webhooks) / GET /rfq/quote/xlsx',
    'high WEBHOOK-NO-AUTH RFQ: API (webhooks) / POST /rfq/quote',
    'high WEBHOOK-NO-AUTH RFQ: API (webhooks) / POST /rfq/review/resolve',
    'high WEBHOOK-NO-AUTH RFQ: Upload form / RFQ upload form',
  ]);
  assert.equal(result.suppressed.length, ignore.length);
  assert.equal(result.scanned.workflows, 16);
});

test('sub-workflows in the same scan are followed (RFQ engine is idempotent per PDF hash)', () => {
  const result = runCheck({ targets: [F('portfolio')] });
  assert.ok(!result.findings.some((f) => f.rule === 'WEBHOOK-NO-IDEMPOTENCY' && f.node === 'POST /rfq/quote'));
  const alone = runCheck({ targets: [F('portfolio', '05-rfq-api.json')] });
  const f = alone.findings.find((x) => x.rule === 'WEBHOOK-NO-IDEMPOTENCY' && x.node === 'POST /rfq/quote');
  assert.ok(f, 'without the engine in the scan the finding is raised');
  assert.equal(f.severity, 'low');
});

test('secrets in well-known formats are detected in code and in text', () => {
  for (const [kind, value] of Object.entries(PROVIDER_SAMPLES)) {
    assert.ok(findSecrets(`x = "${value}"`, 'code').length > 0, `${kind} in code`);
    assert.ok(findSecrets(value, 'param').length > 0, `${kind} as a parameter`);
  }
  const result = runCheck({ targets: [writeTemp(providerWorkflow())] });
  const nodes = result.findings.filter((f) => f.rule === 'HARDCODED-SECRET').map((f) => f.node).sort();
  assert.deepEqual(nodes, ['Code', 'Note']);
});

test('expressions, placeholders and low-entropy values are not reported as secrets', () => {
  const quiet = [
    '={{ $env.OPENAI_API_KEY }}',
    '=Bearer {{ $credentials.token }}',
    'your-api-key-here',
    'xxxxxxxxxxxxxxxx',
    'https://api.example.com/v1/items',
    'aaaaaaaaaaaaaaaa',
  ];
  for (const value of quiet) {
    assert.deepEqual(findSecretPairs({ headers: [{ name: 'Authorization', value }] }), [], value);
    assert.deepEqual(findSecrets(`const token = "${value}";`, 'code'), [], value);
  }
  assert.deepEqual(findSecrets('const apiKey = process.env.API_KEY;', 'code'), []);
});

test('semver ranges used by advisories', () => {
  assert.ok(satisfies('1.120.0', '>=1.65.0 <1.121.0'));
  assert.ok(!satisfies('1.121.0', '>=1.65.0 <1.121.0'));
  assert.ok(satisfies('2.3.0', '<1.0.0 || >=2.0.0 <2.4.0'));
  assert.ok(satisfies('1.0.0', '=1.0.0'));
  assert.ok(!satisfies('1.0.0-rc.1', '>=1.0.0'));
  assert.equal(compare('2.10.0', '2.9.9'), 1);
});

test('advisory data: an old version is flagged critical, the current stable is not flagged', () => {
  const data = loadAdvisories();
  assert.ok(data.advisories.length > 50, 'advisory data is present');
  const old = advisoriesFor('1.120.0', data);
  assert.equal(old[0].severity, 'critical');
  assert.ok(old.some((a) => a.id === 'GHSA-v4pr-fm98-w9pg'), 'CVE-2026-21858 (unauthenticated RCE) is listed');
  if (data.stable) assert.deepEqual(advisoriesFor(data.stable, data), [], `stable ${data.stable} has no advisories`);
  const result = runCheck({ targets: [F('good')], n8nVersion: '1.120.0', advisoryData: data });
  assert.equal(result.findings[0].rule, 'N8N-VERSION-ADVISORY');
  assert.equal(result.findings[0].severity, 'critical');
});

test('sanitizer removes pinned data and every secret the check can see', () => {
  for (const wf of [readJson(F('bad', 'hardcoded-secret.json')), readJson(F('bad', 'export-hygiene.json')), providerWorkflow()]) {
    const clean = sanitizeWorkflow(wf);
    assert.equal(clean.pinData, undefined);
    const result = runCheck({ targets: [writeTemp(clean)] });
    assert.deepEqual(result.findings.filter((f) => ['HARDCODED-SECRET', 'PINDATA-IN-EXPORT'].includes(f.rule)), [], wf.name);
  }
});

test('instance-check.sh cleans exported files and packs them', () => {
  const dir = tmp();
  const out = path.join(dir, 'export');
  fs.mkdirSync(path.join(out, 'workflows'), { recursive: true });
  fs.copyFileSync(F('bad', 'hardcoded-secret.json'), path.join(out, 'workflows', 'a.json'));
  fs.copyFileSync(F('bad', 'export-hygiene.json'), path.join(out, 'workflows', 'b.json'));
  fs.writeFileSync(path.join(out, 'workflows', 'c.json'), JSON.stringify(providerWorkflow()));
  execFileSync('sh', [path.join(ROOT, 'instance-check.sh'), out], { env: { ...process.env, PRODCHECK_SKIP_EXPORT: '1' }, stdio: 'pipe' });
  assert.ok(fs.existsSync(`${out}.tar.gz`));
  const result = runCheck({ targets: [path.join(out, 'workflows')] });
  assert.deepEqual(result.findings.filter((f) => ['HARDCODED-SECRET', 'PINDATA-IN-EXPORT'].includes(f.rule)), []);
  const text = fs.readdirSync(path.join(out, 'workflows')).map((f) => fs.readFileSync(path.join(out, 'workflows', f), 'utf8')).join('\n');
  for (const value of Object.values(PROVIDER_SAMPLES)) assert.ok(!text.includes(value.split('\n')[0].slice(12)), 'secret text is gone');
  assert.ok(!text.includes('jane.doe@example.com'), 'pinned personal data is gone');
});

test('CLI: exit codes, formats and the ignore file', () => {
  const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
  assert.equal(run(F('bad'), '--fail-on', 'high').status, 1);
  assert.equal(run(F('good'), '--fail-on', 'low').status, 0);
  assert.equal(run(F('bad')).status, 0, 'without --fail-on the exit code is 0');
  const json = JSON.parse(run(F('bad'), '--format', 'json').stdout);
  assert.ok(json.findings.length > 0);
  const md = run(F('bad'), '--format', 'md', '--n8n-version', '1.120.0').stdout;
  assert.match(md, /## Scope and limitations/);
  assert.match(md, /## Fix plan/);
  assert.match(md, /N8N-VERSION-ADVISORY|advisories/);
  const ignored = run(F('portfolio'), '--ignore', F('portfolio', '.prodcheck-ignore.json'), '--format', 'json');
  assert.equal(JSON.parse(ignored.stdout).suppressed.length, 5);
  assert.equal(run('--nope').status, 2);
  assert.equal(run('/does/not/exist').status, 2);
});

test('non-workflow JSON files are skipped, not fatal', () => {
  const result = runCheck({ targets: [F('expected-bad.json')] });
  assert.equal(result.scanned.workflows, 0);
  assert.equal(result.skipped.length, 1);
});

test('markdown report renders every rule without crashing', () => {
  const result = runCheck({ targets: [F('bad'), F('good')], n8nVersion: '1.120.0' });
  const md = renderMarkdown(result, { date: '2026-01-01' });
  for (const id of ruleIds(result.findings)) assert.ok(md.includes(id), id);
});

// ---------------------------------------------------------------------------

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeTemp(workflow) {
  const file = path.join(tmp(), 'workflow.json');
  fs.writeFileSync(file, JSON.stringify(workflow));
  return file;
}

let failed = 0;
for (const t of tests) {
  try {
    await t.fn();
    console.log(`  ok    ${t.name}`);
  } catch (e) {
    failed += 1;
    console.log(`  FAIL  ${t.name}\n        ${String(e.message).split('\n').join('\n        ')}`);
  }
}
console.log(`\n${tests.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
