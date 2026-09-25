// Classifies what a node does to the outside world. Deliberately conservative:
// "unknown" is reported as unknown, never guessed as safe.

import { baseType, codeOf, paramsText, shortType } from './graph.mjs';

const DB_TYPES = new Set([
  'postgres', 'mySql', 'microsoftSql', 'oracleDb', 'snowflake', 'crateDb', 'questDb',
  'timescaleDb', 'mongoDb', 'redis', 'supabase', 'cockroachDb',
]);

const SQL_TYPES = new Set([
  'postgres', 'mySql', 'microsoftSql', 'oracleDb', 'snowflake', 'crateDb', 'questDb',
  'timescaleDb', 'cockroachDb',
]);

const MONEY_TYPES = new Set([
  'stripe', 'payPal', 'paypal', 'shopify', 'wooCommerce', 'quickbooks', 'xero', 'chargebee',
  'paddle', 'mollie', 'square', 'lemonSqueezy', 'invoiceNinja',
]);

const MESSAGE_TYPES = new Set([
  'emailSend', 'gmail', 'microsoftOutlook', 'slack', 'telegram', 'twilio', 'sendGrid', 'mailgun',
  'discord', 'whatsApp', 'mattermost', 'microsoftTeams', 'vonage', 'messageBird', 'mailchimp',
  'mailjet', 'awsSes', 'brevo', 'sendInBlue',
]);

const READ_OPERATION = /^(get|getall|getmany|search|list|read|lookup|select|find|download|query|count|getinfo|getrecord|getrows)$/i;
const WRITE_SQL = /\b(insert|update|delete|merge|upsert|truncate|drop|alter|create|grant|revoke|call)\b/i;
const FUNCTION_CALL_SQL = /\bselect\s+[\w."]+\s*\(/i;

export const isSqlNode = (node) => SQL_TYPES.has(baseType(node));

export const sqlOf = (node) => String(node?.parameters?.query || '');

function operationOf(node) {
  const p = node?.parameters || {};
  return String(p.operation || '');
}

/**
 * Returns { effect: 'none' | 'write' | 'money' | 'message' | 'unknown', why }.
 */
export function effectOf(node) {
  const base = baseType(node);
  const type = shortType(node);
  const op = operationOf(node);

  if (type === 'stickyNote' || type === 'noOp') return { effect: 'none' };

  if (DB_TYPES.has(base)) {
    if (op === 'executeQuery' || (!op && sqlOf(node))) {
      const sql = sqlOf(node);
      if (WRITE_SQL.test(sql)) return { effect: 'write', why: 'runs a writing SQL statement' };
      if (FUNCTION_CALL_SQL.test(sql)) return { effect: 'write', why: 'calls a database function that may write', opaque: true };
      return { effect: 'none' };
    }
    if (op && READ_OPERATION.test(op)) return { effect: 'none' };
    return { effect: 'write', why: `runs the database operation "${op || 'default'}"` };
  }

  if (base === 'httpRequest' || type === 'toolHttpRequest') {
    const method = String(node?.parameters?.method || node?.parameters?.requestMethod || 'GET').toUpperCase();
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return { effect: 'none' };
    return { effect: 'write', why: `sends an HTTP ${method} request` };
  }

  if (MONEY_TYPES.has(base)) {
    if (op && READ_OPERATION.test(op)) return { effect: 'none' };
    return { effect: 'money', why: `runs the ${base} operation "${op || 'default'}"` };
  }

  if (MESSAGE_TYPES.has(base)) {
    if (op && READ_OPERATION.test(op)) return { effect: 'none' };
    return { effect: 'message', why: `sends messages through ${base}` };
  }

  if (type === 'executeWorkflow') return { effect: 'unknown', why: 'runs a sub-workflow', opaque: true };
  if (type === 'toolWorkflow' || type === 'toolCode' || type === 'mcpClientTool') {
    return { effect: 'unknown', why: type === 'toolCode' ? 'runs model-driven code' : 'its effects are defined elsewhere', opaque: true };
  }
  if (type === 'executeCommand' || type === 'ssh') return { effect: 'write', why: 'runs a shell command' };

  // Generic integration nodes: judge by the operation name.
  if (op) {
    if (READ_OPERATION.test(op)) return { effect: 'none' };
    if (/create|update|delete|upsert|send|post|append|insert|add|remove|cancel|refund|charge|capture|publish|upload|move|archive|clear/i.test(op)) {
      return { effect: 'write', why: `runs the ${base} operation "${op}"` };
    }
  }
  return { effect: 'none' };
}

export const hasSideEffect = (node) => effectOf(node).effect !== 'none';

// Reads or changes something outside the workflow: any database, HTTP call or sub-workflow.
export const touchesData = (node) =>
  hasSideEffect(node) || DB_TYPES.has(baseType(node)) || baseType(node) === 'httpRequest' || shortType(node) === 'executeWorkflow';

// Sub-workflow id referenced by an Execute Workflow node, when it is a literal.
export function subWorkflowId(node) {
  const w = node?.parameters?.workflowId;
  const id = w && typeof w === 'object' ? w.value : w;
  return typeof id === 'string' && !id.startsWith('=') ? id : null;
}

const AUTH_WORDS = /(secret|signature|hmac|token|authori[sz]ation|api[-_ ]?key|timingSafeEqual|verify|bearer)/i;

// A node that looks at request headers and compares something secret.
export function isAuthCheck(node) {
  const type = shortType(node);
  if (type === 'code' || type === 'function' || type === 'functionItem') {
    const code = codeOf(node);
    return /headers/i.test(code) && AUTH_WORDS.test(code);
  }
  if (type === 'if' || type === 'switch' || type === 'filter') {
    const text = paramsText(node);
    return /headers/i.test(text) && AUTH_WORDS.test(text);
  }
  if (type === 'crypto') return /hmac/i.test(paramsText(node));
  return false;
}

// Does one of the direct successors inspect the result for errors / status codes?
export function successorChecksErrors(graph, node) {
  return graph.next(node.name).some((n) => {
    const t = shortType(n);
    if (!['if', 'switch', 'filter', 'code', 'function', 'functionItem'].includes(t)) return false;
    const text = t.startsWith('function') || t === 'code' ? codeOf(n) : paramsText(n);
    return /statusCode|error/i.test(text);
  });
}
