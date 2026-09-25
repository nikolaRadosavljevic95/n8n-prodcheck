// Loads exported workflows, runs every rule and applies the ignore list.

import fs from 'node:fs';
import path from 'node:path';
import { loadAdvisories } from './advisories.mjs';
import { buildGraph } from './graph.mjs';
import { RULES } from './rules.mjs';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const severityRank = (s) => SEVERITIES.length - SEVERITIES.indexOf(s);

const isWorkflow = (x) => x && typeof x === 'object' && Array.isArray(x.nodes) && x.connections && typeof x.connections === 'object';

function workflowsIn(json) {
  if (isWorkflow(json)) return [json];
  if (Array.isArray(json)) return json.filter(isWorkflow);
  if (json && Array.isArray(json.data)) return json.data.filter(isWorkflow);
  return [];
}

function listJsonFiles(target) {
  const stat = fs.statSync(target);
  if (stat.isFile()) return [target];
  const files = [];
  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
    const full = path.join(target, entry.name);
    if (entry.isDirectory()) files.push(...listJsonFiles(full));
    else if (entry.name.endsWith('.json')) files.push(full);
  }
  return files.sort();
}

export function loadWorkflows(targets) {
  const workflows = [];
  const skipped = [];
  for (const target of targets) {
    for (const file of listJsonFiles(target)) {
      let json;
      try {
        json = JSON.parse(fs.readFileSync(file, 'utf8'));
      } catch (e) {
        skipped.push({ file, reason: `not valid JSON (${e.message})` });
        continue;
      }
      const found = workflowsIn(json);
      if (!found.length) {
        skipped.push({ file, reason: 'no n8n workflow in this file' });
        continue;
      }
      found.forEach((workflow) => workflows.push({ file, workflow }));
    }
  }
  return { workflows, skipped };
}

export function loadIgnore(file) {
  if (!file) return [];
  const json = JSON.parse(fs.readFileSync(file, 'utf8'));
  const list = Array.isArray(json) ? json : json.ignore || [];
  for (const entry of list) {
    if (!entry.rule || !entry.reason) throw new Error(`Every ignore entry needs "rule" and "reason": ${JSON.stringify(entry)}`);
  }
  return list;
}

const matchesIgnore = (finding, entry) =>
  entry.rule === finding.rule
  && (!entry.workflow || entry.workflow === finding.workflow || (finding.file && finding.file.endsWith(entry.workflow)))
  && (!entry.node || entry.node === finding.node);

export function runCheck({ targets, n8nVersion = null, ignore = [], advisoryData = loadAdvisories() }) {
  const { workflows, skipped } = loadWorkflows(targets);
  const options = { n8nVersion };
  const findings = [];

  for (const rule of RULES.filter((r) => r.scope === 'run')) {
    for (const f of rule.check({ options, advisoryData })) {
      findings.push({ rule: rule.id, severity: f.severity || rule.severity, workflow: null, file: null, node: null, message: f.message, evidence: f.evidence || null });
    }
  }

  const byId = new Map(workflows.filter((w) => w.workflow.id).map((w) => [String(w.workflow.id), w.workflow]));
  const resolve = (id) => byId.get(String(id)) || null;

  for (const { file, workflow } of workflows) {
    const graph = buildGraph(workflow);
    for (const rule of RULES.filter((r) => r.scope !== 'run')) {
      for (const f of rule.check({ workflow, graph, options, resolve })) {
        findings.push({
          rule: rule.id,
          severity: f.severity || rule.severity,
          workflow: workflow.name || path.basename(file),
          file,
          node: f.node || null,
          message: f.message,
          evidence: f.evidence || null,
        });
      }
    }
  }

  const active = [];
  const suppressed = [];
  for (const f of findings) {
    const entry = ignore.find((e) => matchesIgnore(f, e));
    if (entry) suppressed.push({ ...f, reason: entry.reason });
    else active.push(f);
  }
  const bySeverity = (a, b) => severityRank(b.severity) - severityRank(a.severity)
    || String(a.workflow).localeCompare(String(b.workflow)) || a.rule.localeCompare(b.rule);
  active.sort(bySeverity);
  suppressed.sort(bySeverity);

  const nodeCount = workflows.reduce((n, w) => n + w.workflow.nodes.filter((x) => !String(x.type).endsWith('stickyNote')).length, 0);
  return {
    scanned: { workflows: workflows.length, nodes: nodeCount, files: [...new Set(workflows.map((w) => w.file))].length },
    n8nVersion,
    advisoryData: { generatedAt: advisoryData.generatedAt, stable: advisoryData.stable, count: (advisoryData.advisories || []).length },
    findings: active,
    suppressed,
    skipped,
  };
}

export function counts(findings) {
  return Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
}
