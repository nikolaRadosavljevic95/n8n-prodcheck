#!/usr/bin/env node
// n8n-prodcheck: static production and security check for exported n8n workflows.

import fs from 'node:fs';
import { loadAdvisories } from '../src/advisories.mjs';
import { counts, loadIgnore, runCheck, SEVERITIES } from '../src/check.mjs';
import { renderJson, renderMarkdown, renderText } from '../src/report.mjs';
import { sanitizeDir } from '../src/sanitize.mjs';

const HELP = `Usage:
  n8n-prodcheck <file-or-dir>... [options]
  n8n-prodcheck sanitize <dir>

Checks exported n8n workflow JSON (single workflows, "export:workflow --all" arrays,
or API responses) for production and security problems.

Options:
  --n8n-version X.Y.Z   also check the n8n version against published advisories
  --format text|md|json output format (default: text)
  --out <file>          write the report to a file instead of stdout
  --ignore <file>       JSON list of reviewed findings to suppress:
                        [{ "rule": "...", "workflow": "...", "node": "...", "reason": "..." }]
  --fail-on <severity>  exit 1 if any finding is at or above: critical, high, medium, low
  --title <text>        report title (md)
  --subject <text>      "Subject" line in the md report, e.g. the client name
  -h, --help            show this help

sanitize <dir>: strips pinData, staticData and secret-looking values from every
workflow JSON file in <dir>, in place. Run it before sending exports to anyone.
`;

function parseArgs(argv) {
  const args = { targets: [], format: 'text' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === '-h' || a === '--help') args.help = true;
    else if (a === '--n8n-version') args.n8nVersion = value();
    else if (a === '--format') args.format = value();
    else if (a === '--out') args.out = value();
    else if (a === '--ignore') args.ignore = value();
    else if (a === '--fail-on') args.failOn = value();
    else if (a === '--title') args.title = value();
    else if (a === '--subject') args.subject = value();
    else if (a.startsWith('--')) throw new Error(`Unknown option ${a}`);
    else args.targets.push(a);
  }
  return args;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === 'sanitize') {
    if (!argv[1]) throw new Error('sanitize needs a directory');
    const n = sanitizeDir(argv[1]);
    process.stdout.write(`Sanitized ${n} file(s) in ${argv[1]}: removed pinData and staticData, redacted secret-looking values.\n`);
    return 0;
  }

  const args = parseArgs(argv);
  if (args.help || !args.targets.length) {
    process.stdout.write(HELP);
    return args.help ? 0 : 2;
  }
  if (!['text', 'md', 'json'].includes(args.format)) throw new Error(`Unknown format ${args.format}`);
  if (args.failOn && !SEVERITIES.includes(args.failOn)) throw new Error(`--fail-on must be one of ${SEVERITIES.join(', ')}`);
  for (const t of args.targets) if (!fs.existsSync(t)) throw new Error(`Not found: ${t}`);

  const advisoryData = loadAdvisories();
  if (args.n8nVersion && advisoryData.generatedAt) {
    const ageDays = (Date.now() - Date.parse(advisoryData.generatedAt)) / 86400000;
    if (ageDays > 14) process.stderr.write(`warning: advisory data is ${Math.floor(ageDays)} days old; run "npm run advisories" to refresh\n`);
  }

  const result = runCheck({ targets: args.targets, n8nVersion: args.n8nVersion || null, ignore: loadIgnore(args.ignore), advisoryData });
  const output = args.format === 'json' ? renderJson(result)
    : args.format === 'md' ? renderMarkdown(result, { title: args.title, subject: args.subject })
      : renderText(result);

  if (args.out) {
    fs.writeFileSync(args.out, output);
    process.stdout.write(`Report written to ${args.out}\n`);
  } else {
    process.stdout.write(output);
  }

  if (args.failOn) {
    const c = counts(result.findings);
    const threshold = SEVERITIES.indexOf(args.failOn);
    if (SEVERITIES.slice(0, threshold + 1).some((s) => c[s] > 0)) return 1;
  }
  return 0;
}

try {
  process.exitCode = main();
} catch (e) {
  process.stderr.write(`n8n-prodcheck: ${e.message}\n`);
  process.exitCode = 2;
}
