// Renders a check result as console text, Markdown or JSON.

import path from 'node:path';
import { counts, SEVERITIES } from './check.mjs';
import { RULE_BY_ID } from './rules.mjs';

const LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

const where = (f, base) => {
  if (!f.workflow) return 'n8n instance';
  const file = f.file ? path.relative(base, f.file) || path.basename(f.file) : '';
  return `${f.workflow}${file ? ` (${file})` : ''}${f.node ? ` → "${f.node}"` : ''}`;
};

export function renderText(result, { base = process.cwd() } = {}) {
  const c = counts(result.findings);
  const lines = [];
  lines.push(`n8n-prodcheck: ${result.scanned.workflows} workflow(s), ${result.scanned.nodes} node(s)`);
  if (!result.n8nVersion) lines.push('n8n version not checked (pass --n8n-version X.Y.Z)');
  lines.push(SEVERITIES.map((s) => `${c[s]} ${s}`).join(', ') + (result.suppressed.length ? `, ${result.suppressed.length} suppressed` : ''));
  lines.push('');
  for (const f of result.findings) {
    lines.push(`${LABEL[f.severity].padEnd(8)} ${f.rule}  ${where(f, base)}`);
    lines.push(`         ${f.message}`);
  }
  for (const s of result.skipped) lines.push(`skipped  ${path.relative(base, s.file)}: ${s.reason}`);
  return lines.join('\n') + '\n';
}

export function renderJson(result) {
  return JSON.stringify(result, null, 2) + '\n';
}

export function renderMarkdown(result, { base = process.cwd(), title = 'n8n production and security check', date = new Date().toISOString().slice(0, 10), subject = null } = {}) {
  const c = counts(result.findings);
  const out = [];
  out.push(`# ${title}`, '');
  const meta = [
    subject ? `**Subject:** ${subject}` : null,
    `**Date:** ${date}`,
    `**Scanned:** ${result.scanned.workflows} workflow(s), ${result.scanned.nodes} node(s)`,
    `**n8n version:** ${result.n8nVersion || 'not provided, so known n8n advisories were not checked'}`,
    `**Tool:** [n8n-prodcheck](https://github.com/nikolaRadosavljevic95/n8n-prodcheck), advisory data from ${result.advisoryData.generatedAt ? result.advisoryData.generatedAt.slice(0, 10) : 'n/a'}`,
  ].filter(Boolean);
  out.push(meta.join('  \n'), '');

  out.push('## Summary', '');
  out.push('| Severity | Findings |', '|---|---|');
  for (const s of SEVERITIES) out.push(`| ${LABEL[s]} | ${c[s]} |`);
  if (result.suppressed.length) out.push(`| Suppressed (reviewed) | ${result.suppressed.length} |`);
  out.push('');

  if (!result.findings.length) {
    out.push('No findings. That covers only what a static check can see; see "Scope and limitations".', '');
  } else {
    const top = result.findings.slice(0, 5);
    out.push('**Fix first:**', '');
    top.forEach((f, i) => out.push(`${i + 1}. **${LABEL[f.severity]}** ${RULE_BY_ID.get(f.rule).title}: ${where(f, base)}`));
    out.push('');
  }

  if (result.findings.length) {
    out.push('## Findings', '');
    let i = 0;
    for (const f of result.findings) {
      const rule = RULE_BY_ID.get(f.rule);
      i += 1;
      out.push(`### ${i}. [${LABEL[f.severity]}] ${rule.title}`, '');
      out.push(`- **Where:** ${where(f, base)}`);
      out.push(`- **Rule:** \`${f.rule}\``);
      out.push(`- **What we found:** ${f.message}`);
      if (f.evidence) out.push('- **Details:**', '', '```', f.evidence, '```', '');
      out.push(`- **Why it matters:** ${rule.why}`);
      out.push(`- **How to fix:** ${rule.fix}`);
      if (rule.refs?.length) out.push(`- **Reference:** ${rule.refs.map((r) => `<${r}>`).join(', ')}`);
      out.push('');
    }

    out.push('## Fix plan', '');
    const group = (effort) => {
      const ids = [...new Set(result.findings.filter((f) => RULE_BY_ID.get(f.rule).effort === effort).map((f) => f.rule))];
      return ids.map((id) => {
        const n = result.findings.filter((f) => f.rule === id).length;
        return `- ${RULE_BY_ID.get(id).title} (${n} place${n === 1 ? '' : 's'}): ${RULE_BY_ID.get(id).fix}`;
      });
    };
    const quick = group('quick');
    const sprint = group('sprint');
    out.push('**Quick fixes you can usually do yourself in the editor:**', '', ...(quick.length ? quick : ['- none']), '');
    out.push('**Changes that need design and testing (a fix sprint):**', '', ...(sprint.length ? sprint : ['- none']), '');
  }

  if (result.suppressed.length) {
    out.push('## Reviewed and suppressed', '');
    out.push('These matched a rule but were reviewed and accepted, with the reason recorded in the ignore file.', '');
    for (const f of result.suppressed) out.push(`- \`${f.rule}\` ${where(f, base)}: ${f.reason}`);
    out.push('');
  }

  out.push('## Scope and limitations', '');
  out.push('- This is a static review of exported workflow JSON. It does not run workflows, call your APIs or log in to your instance, and it is not a penetration test.');
  out.push('- Rules are heuristics tuned to avoid false alarms, so a clean result does not prove a workflow is safe. Logic inside sub-workflows, external services and databases is only visible if those workflows are included.');
  out.push('- Secrets are shown masked (first 4 characters). Treat any secret listed here as exposed and rotate it.');
  out.push('- Advisory data comes from the public npm/GitHub advisory database and is only as current as the date above.');
  out.push('');
  return out.join('\n');
}
