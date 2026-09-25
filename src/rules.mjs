// The checks. Each rule reads one workflow (or, for `scope: 'run'`, the whole run)
// and returns findings. Rules prefer missing a low-value issue to raising a false alarm.

import { advisoriesFor } from './advisories.mjs';
import { effectOf, hasSideEffect, isAuthCheck, isSqlNode, sqlOf, subWorkflowId, successorChecksErrors, touchesData } from './effects.mjs';
import { baseType, codeOf, isAgent, isDisabled, isHttpTrigger, isToolNode, isTrigger, paramsText, shortType, strings } from './graph.mjs';
import { findSecretPairs, findSecrets, mask } from './secrets.mjs';

const OWASP_LLM = 'https://genai.owasp.org/llm-top-10/';

const httpMethod = (node) => String(node.parameters?.httpMethod || 'GET').toUpperCase();

const triggerAuth = (node) => {
  const p = node.parameters || {};
  const type = shortType(node);
  if (type === 'chatTrigger' && p.public !== true) return 'n8n editor only';
  const auth = p.authentication;
  return auth && auth !== 'none' ? auth : null;
};

// Everything a trigger reaches: downstream nodes, tools of any agent on the way, and
// the nodes of sub-workflows that are part of the same scan (followed up to 3 levels).
function reachFrom(graph, trigger, resolve = () => null) {
  const nodes = [];
  const expanded = new Set();
  const visitedWorkflows = new Set();
  const walk = (list, depth) => {
    for (const n of list) {
      nodes.push(n);
      if (isAgent(n)) nodes.push(...graph.toolsOf(n.name));
      const id = shortType(n) === 'executeWorkflow' ? subWorkflowId(n) : null;
      const sub = id && depth < 3 && !visitedWorkflows.has(id) ? resolve(id) : null;
      if (sub) {
        visitedWorkflows.add(id);
        expanded.add(n);
        walk((sub.nodes || []).filter((x) => !isDisabled(x)), depth + 1);
      }
    }
  };
  walk(graph.downstream(trigger.name), 0);
  const effects = nodes.filter((n) => hasSideEffect(n) && !expanded.has(n));
  return { nodes, effects };
}

// Side-effect nodes reachable from a trigger, including write tools of any agent on the path.
const effectsAfter = (graph, trigger, resolve) => reachFrom(graph, trigger, resolve).effects;

const nodeLabel = (n) => `"${n.name}" (${shortType(n)})`;

export const RULES = [
  {
    id: 'N8N-VERSION-ADVISORY',
    scope: 'run',
    title: 'The n8n version has published security advisories',
    severity: 'critical',
    effort: 'quick',
    why: 'Known vulnerabilities in n8n itself are the fastest way into an instance: several recent ones allow remote code execution or reading credentials without logging in.',
    fix: 'Upgrade n8n to the current stable release, then re-run this check with the new version.',
    refs: ['https://github.com/n8n-io/n8n/security/advisories'],
    check({ options, advisoryData }) {
      if (!options.n8nVersion) return [];
      const list = advisoriesFor(options.n8nVersion, advisoryData);
      if (!list.length) return [];
      const counts = list.reduce((acc, a) => ({ ...acc, [a.severity]: (acc[a.severity] || 0) + 1 }), {});
      const summary = Object.entries(counts).map(([s, c]) => `${c} ${s}`).join(', ');
      const top = list.slice(0, 8).map((a) => `${a.id} (${a.severity}${a.cvss ? `, CVSS ${a.cvss}` : ''}): ${a.title}`);
      const stable = advisoryData.stable ? ` Current stable is ${advisoryData.stable}.` : '';
      return [{
        severity: list[0].severity,
        message: `n8n ${options.n8nVersion} is affected by ${list.length} published advisories (${summary}).${stable}`,
        evidence: top.join('\n') + (list.length > top.length ? `\n…and ${list.length - top.length} more` : ''),
      }];
    },
  },

  {
    id: 'WEBHOOK-NO-AUTH',
    title: 'Public trigger accepts requests from anyone',
    severity: 'high',
    effort: 'quick',
    why: 'Anyone who finds or guesses the URL can run the workflow. When the workflow writes data, sends messages or moves money, that is an open door, and webhook paths leak through logs, browser history and screenshots.',
    fix: 'Turn on the trigger\'s authentication (header auth, basic auth or JWT), or verify a shared secret or provider signature (HMAC) in the first node with a constant-time comparison, and answer 401 before anything else runs.',
    refs: ['https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/', 'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'],
    check({ graph }) {
      const findings = [];
      for (const trigger of graph.nodes.filter(isHttpTrigger)) {
        if (triggerAuth(trigger)) continue;
        const down = graph.downstream(trigger.name);
        if (down.some(isAuthCheck)) continue;
        const reached = [...down, ...down.filter(isAgent).flatMap((a) => graph.toolsOf(a.name))];
        const touching = reached.filter(touchesData);
        const kind = shortType(trigger) === 'formTrigger' ? 'Form' : shortType(trigger) === 'chatTrigger' ? 'Public chat' : 'Webhook';
        const pathText = trigger.parameters?.path ? ` (${httpMethod(trigger)} /${trigger.parameters.path})` : '';
        findings.push({
          node: trigger.name,
          severity: touching.length ? 'high' : 'medium',
          message: touching.length
            ? `${kind}${pathText} has no authentication and no secret or signature check, and it reaches ${touching.length} node(s) that read or change data: ${touching.slice(0, 4).map(nodeLabel).join(', ')}.`
            : `${kind}${pathText} has no authentication and no secret or signature check. It does not reach any database or external call, but anyone can still run it and use your executions.`,
        });
      }
      return findings;
    },
  },

  {
    id: 'HARDCODED-SECRET',
    title: 'Secret written directly into the workflow',
    severity: 'high',
    effort: 'quick',
    why: 'Workflow JSON is exported, shared, pasted into forums and committed to Git. A key inside it is readable by everyone who ever sees the file, and it cannot be rotated without editing every copy.',
    fix: 'Move the value into an n8n credential (or an environment variable read with $env), rotate the exposed key at the provider, and re-export the workflow.',
    refs: ['https://docs.n8n.io/credentials/', 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'],
    check({ graph }) {
      const findings = [];
      for (const node of graph.allNodes) {
        const hits = [];
        const code = codeOf(node);
        if (code) hits.push(...findSecrets(code, 'code'));
        for (const { path, value } of strings(node.parameters || {})) {
          if (path.endsWith('jsCode') || path.endsWith('pythonCode') || path.endsWith('functionCode')) continue;
          hits.push(...findSecrets(value, 'param').map((h) => ({ ...h, path })));
        }
        hits.push(...findSecretPairs(node.parameters || {}));
        const unique = [...new Map(hits.map((h) => [h.value, h])).values()];
        if (!unique.length) continue;
        findings.push({
          node: node.name,
          message: `${nodeLabel(node)} contains ${unique.length} secret-looking value(s): ${unique.map((h) => `${h.kind} ${mask(h.value)}`).join('; ')}.`,
        });
      }
      return findings;
    },
  },

  {
    id: 'AGENT-WRITE-TOOL',
    title: 'AI agent can change data or move money with no limit outside the prompt',
    severity: 'high',
    effort: 'sprint',
    why: 'A tool the model can call is a capability anyone who can talk to the model can try to use. Prompt injection, a confused model or a crafted customer message can make it refund, delete or send. A system prompt is a request, not a control.',
    fix: 'Put the limit where the model cannot talk its way past it: scope every query to the authenticated user, enforce amounts and states in the database or in a sub-workflow, and route anything above a threshold to a human approval step. Log every tool call.',
    refs: [OWASP_LLM, 'https://genai.owasp.org/llmrisk/llm062025-excessive-agency/'],
    check({ graph }) {
      const findings = [];
      for (const agent of graph.nodes.filter(isAgent)) {
        for (const tool of graph.toolsOf(agent.name)) {
          const { effect, why } = effectOf(tool);
          if (effect === 'none') continue;
          const known = effect !== 'unknown';
          findings.push({
            node: tool.name,
            severity: known ? 'high' : 'medium',
            message: known
              ? `Agent "${agent.name}" can call ${nodeLabel(tool)}, which ${why}${effect === 'money' ? ' (money)' : ''}. Nothing in this workflow limits what the model can do with it.`
              : `Agent "${agent.name}" can call ${nodeLabel(tool)}; ${why}. Check that its limits are enforced there and not only described to the model.`,
          });
        }
      }
      return findings;
    },
  },

  {
    id: 'SQL-INTERPOLATION',
    title: 'Values pasted into SQL text instead of passed as parameters',
    severity: 'high',
    effort: 'quick',
    why: 'An expression inside the query text becomes part of the SQL. A quote in a customer name breaks the query; a crafted value (or a model-chosen value from $fromAI) can read or change other rows.',
    fix: 'Use $1, $2 placeholders in the query and pass the values in the node\'s "Query Parameters" option, or use the node\'s insert/update operations.',
    refs: ['https://docs.n8n.io/integrations/builtin/app-nodes/n8n-nodes-base.postgres/', 'https://owasp.org/www-community/attacks/SQL_Injection'],
    check({ graph }) {
      const findings = [];
      const httpTriggered = graph.nodes.some(isHttpTrigger);
      for (const node of graph.nodes.filter(isSqlNode)) {
        const sql = sqlOf(node);
        const exprs = sql.match(/\{\{[\s\S]*?\}\}/g) || [];
        const dynamic = exprs.filter((e) => /\$json|\$\(|\$input|\$node|\$item|\$fromAI|\$binary|\$request|\$query|\$body/.test(e));
        if (!dynamic.length) continue;
        const fromModel = dynamic.some((e) => e.includes('$fromAI'));
        findings.push({
          node: node.name,
          severity: fromModel || httpTriggered ? 'high' : 'medium',
          message: `${nodeLabel(node)} builds SQL from ${fromModel ? 'values the AI model chooses' : 'workflow data'}: ${dynamic.slice(0, 3).map((e) => e.replace(/\s+/g, ' ')).join(', ')}.`,
        });
      }
      return findings;
    },
  },

  {
    id: 'EXECUTE-COMMAND',
    title: 'Workflow runs shell commands on the n8n host',
    severity: 'high',
    effort: 'sprint',
    why: 'A shell on the n8n host can read every credential n8n holds. When any part of the command comes from workflow data, whoever controls that data controls the host.',
    fix: 'Replace the command with a dedicated node or an HTTP call to a small service. If a command is unavoidable, never build it from input, and keep the node disabled on instances that face the internet.',
    refs: ['https://docs.n8n.io/hosting/securing/blocking-nodes/'],
    check({ graph }) {
      return graph.nodes
        .filter((n) => ['executeCommand', 'ssh'].includes(shortType(n)))
        .map((node) => {
          const dynamic = /\{\{/.test(String(node.parameters?.command || ''));
          return {
            node: node.name,
            severity: dynamic ? 'high' : 'medium',
            message: dynamic
              ? `${nodeLabel(node)} builds a shell command from workflow data.`
              : `${nodeLabel(node)} runs a fixed shell command on the host.`,
          };
        });
    },
  },

  {
    id: 'NON-ATOMIC-DEDUPE',
    title: 'Duplicate protection that fails under concurrency',
    severity: 'medium',
    effort: 'sprint',
    why: 'Providers retry and deliver the same event more than once, often in parallel. A check-then-write dedupe (Remove Duplicates history, workflow static data) lets two simultaneous deliveries both pass, so the order ships twice.',
    fix: 'Make the database decide: insert the event id into a table with a UNIQUE constraint (INSERT … ON CONFLICT DO NOTHING) and only continue when the insert actually happened.',
    refs: ['https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.removeduplicates/'],
    check({ graph }) {
      const findings = [];
      for (const node of graph.nodes) {
        const type = shortType(node);
        if (type === 'removeDuplicates' && node.parameters?.operation === 'removeItemsProcessedPreviously') {
          findings.push({ node: node.name, message: `${nodeLabel(node)} remembers processed items across executions, which is a check-then-write and not atomic when deliveries arrive in parallel.` });
        } else if ((type === 'code' || type === 'function') && /\$getWorkflowStaticData\s*\(/.test(codeOf(node))
          && /(seen|processed|dedup|already|last[_A-Z]?(id|seen|processed)|\.includes\(|\.has\()/i.test(codeOf(node))) {
          findings.push({ node: node.name, message: `${nodeLabel(node)} uses workflow static data to remember processed items. Static data is saved at the end of an execution, so parallel executions do not see each other.` });
        }
      }
      return findings;
    },
  },

  {
    id: 'WEBHOOK-NO-IDEMPOTENCY',
    title: 'Webhook with side effects and no sign of duplicate protection',
    severity: 'medium',
    effort: 'sprint',
    why: 'Every webhook sender retries: payment providers, voice platforms, form tools, your own frontend after a timeout. Without an idempotency key the retry repeats the side effect (a second order, a second email, a second booking).',
    fix: 'Take a stable id from the request (event id, message id, tool call id, or a hash of the payload), store it with a UNIQUE constraint before acting, and return the stored result when it is seen again.',
    refs: ['https://docs.stripe.com/webhooks#handle-duplicate-events'],
    check({ graph, resolve }) {
      const findings = [];
      const MARKERS = /on\s+conflict|idempot|dedup|unique|event_?id|request_?id|tool_?call_?id|message_?id|delivery_?id|external_?id|sha-?256|already[ _]processed|removeDuplicates/i;
      for (const trigger of graph.nodes.filter((n) => shortType(n) === 'webhook')) {
        if (['GET', 'HEAD', 'OPTIONS'].includes(httpMethod(trigger))) continue;
        const { nodes, effects } = reachFrom(graph, trigger, resolve);
        if (!effects.length) continue;
        const text = [trigger, ...nodes].map((n) => `${n.type} ${paramsText(n)}`).join('\n');
        if (MARKERS.test(text)) continue;
        const opaqueOnly = effects.every((n) => effectOf(n).opaque);
        const path = `${httpMethod(trigger)} /${trigger.parameters?.path || ''}`;
        findings.push({
          node: trigger.name,
          severity: opaqueOnly ? 'low' : 'medium',
          message: opaqueOnly
            ? `${path} leads to ${effects.slice(0, 4).map(nodeLabel).join(', ')}. What happens there is not visible in this scan, so confirm that a repeated request cannot repeat the effect.`
            : `${path} leads to ${effects.slice(0, 4).map(nodeLabel).join(', ')}, and nothing on the way looks like an idempotency key or a unique constraint.`,
        });
      }
      return findings;
    },
  },

  {
    id: 'WEBHOOK-RESPONDS-LATE',
    title: 'Webhook answers only after the whole workflow finishes',
    severity: 'medium',
    effort: 'quick',
    why: 'With "respond when last node finishes", the caller waits for every external call. Senders time out after a few seconds and retry, which is where duplicates come from, and some (Stripe, Shopify) disable endpoints that are slow too often.',
    fix: 'Acknowledge immediately (respond "immediately" or put a Respond to Webhook node right after validation and storing the event), then do the slow work after the response or in a sub-workflow that does not wait.',
    refs: ['https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/'],
    check({ graph }) {
      const findings = [];
      for (const trigger of graph.nodes.filter((n) => shortType(n) === 'webhook')) {
        if (trigger.parameters?.responseMode !== 'lastNode') continue;
        const slow = graph.downstream(trigger.name).filter((n) =>
          baseType(n) === 'httpRequest' || shortType(n) === 'executeWorkflow' || isAgent(n) || effectOf(n).effect === 'money' || effectOf(n).effect === 'message');
        if (!slow.length) continue;
        findings.push({
          node: trigger.name,
          message: `${nodeLabel(trigger)} responds after the last node, and the caller waits for ${slow.slice(0, 4).map(nodeLabel).join(', ')}.`,
        });
      }
      return findings;
    },
  },

  {
    id: 'HTTP-NO-RETRY',
    title: 'External call fails the run on the first error',
    severity: 'medium',
    effort: 'quick',
    why: 'APIs return 429 and 5xx as a matter of course. Without a retry or an error branch, one blip stops the execution halfway: some steps done, the rest not, and nobody told.',
    fix: 'Enable "Retry On Fail" with 3–5 tries and a wait, or route errors to an explicit error output that records the failure for a later retry (a dead-letter table).',
    refs: ['https://docs.n8n.io/flow-logic/error-handling/'],
    check({ graph }) {
      return graph.nodes
        .filter((n) => baseType(n) === 'httpRequest' && !isToolNode(n))
        .filter((n) => n.retryOnFail !== true && n.continueOnFail !== true && (!n.onError || n.onError === 'stopWorkflow'))
        .map((node) => ({ node: node.name, message: `${nodeLabel(node)} has neither "Retry On Fail" nor an error output.` }));
    },
  },

  {
    id: 'ERRORS-SWALLOWED',
    title: 'Failures continue down the success path',
    severity: 'medium',
    effort: 'quick',
    why: 'With "continue (regular output)", a failed call hands its error to the next node as if it were a result. Unless someone checks, the workflow reports success for work that did not happen.',
    fix: 'Use "continue (using error output)" and handle the error branch, or check the status / error field in the very next node and route failures to a retry or dead-letter path.',
    refs: ['https://docs.n8n.io/flow-logic/error-handling/'],
    check({ graph }) {
      return graph.nodes
        .filter((n) => hasSideEffect(n) && (n.onError === 'continueRegularOutput' || n.continueOnFail === true))
        .filter((n) => !successorChecksErrors(graph, n))
        .map((node) => ({ node: node.name, message: `${nodeLabel(node)} continues on error, and the next node does not check for the error.` }));
    },
  },

  {
    id: 'HTTP-NO-TIMEOUT',
    title: 'External call without an explicit timeout',
    severity: 'low',
    effort: 'quick',
    why: 'A hanging API keeps the execution (and, behind a webhook, the caller) waiting far longer than any sender will. Explicit timeouts turn hangs into errors your retry and error paths can handle.',
    fix: 'Set Options → Timeout on the HTTP Request node to a value that fits the caller (for example 5–30 seconds).',
    refs: ['https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.httprequest/'],
    check({ graph }) {
      return graph.nodes
        .filter((n) => baseType(n) === 'httpRequest' && !isToolNode(n))
        .filter((n) => !n.parameters?.options?.timeout)
        .map((node) => ({ node: node.name, message: `${nodeLabel(node)} relies on the default timeout.` }));
    },
  },

  {
    id: 'NO-ERROR-WORKFLOW',
    title: 'Failures are not reported anywhere',
    severity: 'medium',
    effort: 'quick',
    why: 'When a production execution fails, n8n records it and moves on. Without an error workflow, nobody hears about it until a customer does.',
    fix: 'Create one error workflow (Error Trigger → alert to Slack/email/on-call and a row in an errors table) and select it under Workflow Settings → Error Workflow for every production workflow.',
    refs: ['https://docs.n8n.io/flow-logic/error-handling/'],
    check({ workflow, graph }) {
      if (workflow.settings?.errorWorkflow) return [];
      const productionTriggers = graph.nodes.filter((n) => isTrigger(n)
        && !['errorTrigger', 'executeWorkflowTrigger', 'manualTrigger'].includes(shortType(n)));
      if (!productionTriggers.length) return [];
      return [{ message: `Started by ${productionTriggers.slice(0, 3).map(nodeLabel).join(', ')}, but no error workflow is set.` }];
    },
  },

  {
    id: 'PINDATA-IN-EXPORT',
    title: 'Export contains pinned test data',
    severity: 'low',
    effort: 'quick',
    why: 'Pinned data is usually a copy of a real execution: customer names, emails, payloads, sometimes tokens. It travels with every export.',
    fix: 'Unpin the data before exporting, or strip "pinData" from the file (instance-check.sh does this).',
    refs: ['https://docs.n8n.io/data/data-pinning/'],
    check({ workflow }) {
      const pinned = Object.keys(workflow.pinData || {});
      return pinned.length ? [{ message: `Pinned data on ${pinned.length} node(s): ${pinned.slice(0, 5).map((n) => `"${n}"`).join(', ')}.` }] : [];
    },
  },

  {
    id: 'SAVE-ERROR-EXECUTIONS-OFF',
    title: 'Failed executions are not saved',
    severity: 'low',
    effort: 'quick',
    why: 'With failed executions discarded, there is nothing to debug or replay after an incident.',
    fix: 'Set Workflow Settings → Save failed production executions to "Save", and prune old executions by age instead.',
    refs: ['https://docs.n8n.io/workflows/settings/'],
    check({ workflow }) {
      return workflow.settings?.saveDataErrorExecution === 'none'
        ? [{ message: 'Workflow settings discard failed executions (saveDataErrorExecution = "none").' }]
        : [];
    },
  },
];

export const RULE_BY_ID = new Map(RULES.map((r) => [r.id, r]));

export { isDisabled };
