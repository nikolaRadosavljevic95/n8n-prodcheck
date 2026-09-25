// Helpers for reading one exported n8n workflow as a graph.

export const shortType = (node) => String(node?.type || '').split('.').pop();

// "postgresTool" -> "postgres", "httpRequestTool" -> "httpRequest"
export const baseType = (node) => shortType(node).replace(/Tool$/, '');

export const isToolNode = (node) =>
  /Tool$/.test(shortType(node)) || /^tool[A-Z]/.test(shortType(node));

export const isDisabled = (node) => node?.disabled === true;

const TRIGGER_TYPES = new Set(['webhook', 'formTrigger', 'chatTrigger', 'mcpTrigger']);

export const isHttpTrigger = (node) => TRIGGER_TYPES.has(shortType(node));

export const isTrigger = (node) =>
  isHttpTrigger(node) || /Trigger$/.test(shortType(node)) || shortType(node) === 'n8nTrigger';

export const isAgent = (node) => /(^|\.)agent$/i.test(String(node?.type || ''));

export function buildGraph(workflow) {
  const nodes = Array.isArray(workflow?.nodes) ? workflow.nodes : [];
  const byName = new Map(nodes.map((n) => [n.name, n]));
  const out = new Map();
  const inc = new Map();
  const add = (map, key, value) => {
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(value);
  };

  for (const [from, byConnType] of Object.entries(workflow?.connections || {})) {
    for (const [connType, outputs] of Object.entries(byConnType || {})) {
      (outputs || []).forEach((targets, outputIndex) => {
        for (const t of targets || []) {
          if (!t || !t.node) continue;
          add(out, from, { node: t.node, type: connType, outputIndex });
          add(inc, t.node, { node: from, type: connType, outputIndex });
        }
      });
    }
  }

  // Nodes reachable from `name` along "main" connections, excluding `name` itself.
  function downstream(name) {
    const seen = new Set([name]);
    const queue = [name];
    const result = [];
    while (queue.length) {
      const current = queue.shift();
      for (const edge of out.get(current) || []) {
        if (edge.type !== 'main' || seen.has(edge.node)) continue;
        seen.add(edge.node);
        queue.push(edge.node);
        const node = byName.get(edge.node);
        if (node && !isDisabled(node)) result.push(node);
      }
    }
    return result;
  }

  // Direct "main" successors of a node.
  function next(name) {
    return (out.get(name) || [])
      .filter((e) => e.type === 'main')
      .map((e) => byName.get(e.node))
      .filter((n) => n && !isDisabled(n));
  }

  // Tool nodes attached to an agent through ai_tool connections.
  function toolsOf(agentName) {
    return (inc.get(agentName) || [])
      .filter((e) => e.type === 'ai_tool')
      .map((e) => byName.get(e.node))
      .filter((n) => n && !isDisabled(n));
  }

  // The agent (if any) a tool node is attached to.
  function agentOf(toolName) {
    const edge = (out.get(toolName) || []).find((e) => e.type === 'ai_tool');
    return edge ? byName.get(edge.node) : undefined;
  }

  // Trigger nodes whose "main" paths reach `name`.
  function triggersReaching(name) {
    return nodes.filter((n) => isTrigger(n) && !isDisabled(n) && downstream(n.name).some((d) => d.name === name));
  }

  return { nodes: nodes.filter((n) => !isDisabled(n)), allNodes: nodes, byName, out, inc, downstream, next, toolsOf, agentOf, triggersReaching };
}

// Every string inside a value, with a dotted path, for scanning parameters.
export function* strings(value, path = '') {
  if (typeof value === 'string') {
    yield { path, value };
  } else if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) yield* strings(value[i], `${path}[${i}]`);
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) yield* strings(v, path ? `${path}.${k}` : k);
  }
}

export const paramsText = (node) => JSON.stringify(node?.parameters || {});

export const codeOf = (node) => {
  const p = node?.parameters || {};
  return String(p.jsCode || p.pythonCode || p.functionCode || p.code || '');
};
