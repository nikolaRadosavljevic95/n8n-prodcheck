# Sample report: synthetic example

**Subject:** Synthetic workflows written to trigger every rule (fixtures/bad), checked as if they ran on n8n 1.120.0. Not a real client.  
**Date:** 2026-09-25  
**Scanned:** 13 workflow(s), 37 node(s)  
**n8n version:** 1.120.0  
**Tool:** [n8n-prodcheck](https://github.com/nikolaRadosavljevic95/n8n-prodcheck), advisory data from 2026-09-25

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 1 |
| HIGH | 9 |
| MEDIUM | 8 |
| LOW | 3 |

**Fix first:**

1. **CRITICAL** The n8n version has published security advisories: n8n instance
2. **HIGH** Secret written directly into the workflow: Billing: sync invoices (bad/hardcoded-secret.json) → "Fetch invoices"
3. **HIGH** Secret written directly into the workflow: Billing: sync invoices (bad/hardcoded-secret.json) → "Log in to portal"
4. **HIGH** Workflow runs shell commands on the n8n host: Media: convert (bad/execute-command.json) → "Convert video"
5. **HIGH** Values pasted into SQL text instead of passed as parameters: Orders: lookup API (bad/sql-interpolation.json) → "Find orders"

## Findings

### 1. [CRITICAL] The n8n version has published security advisories

- **Where:** n8n instance
- **Rule:** `N8N-VERSION-ADVISORY`
- **What we found:** n8n 1.120.0 is affected by 140 published advisories (22 critical, 51 high, 67 medium). Current stable is 2.40.7.
- **Details:**

```
GHSA-q5f4-99jv-pgg5 (critical, CVSS 10): n8n has Prototype Pollution in XML Webhook Body Parser that Leads to RCE
GHSA-v4pr-fm98-w9pg (critical, CVSS 10): n8n Vulnerable to Unauthenticated File Access via Improper Webhook Request Handling
GHSA-58qr-rcgv-642v (critical, CVSS 9.9): n8n has Multiple Remote Code Execution Vulnerabilities in Merge Node AlaSQL SQL Mode
GHSA-5xrp-6693-jjx9 (critical, CVSS 9.9): n8n Unsafe Workflow Expression Evaluation Allows Remote Code Execution
GHSA-62r4-hw23-cc8v (critical, CVSS 9.9): n8n Vulnerable to Arbitrary Command Execution in Pyodide based Python Code Node 
GHSA-8398-gmmx-564h (critical, CVSS 9.9): n8n has a Python sandbox escape
GHSA-c8xv-5998-g76h (critical, CVSS 9.9): n8n: HTTP Request Node Pagination Prototype Pollution to RCE
GHSA-hqr4-h3xv-9m3r (critical, CVSS 9.9): n8n has XML Node Prototype Pollution that to RCE
…and 132 more
```

- **Why it matters:** Known vulnerabilities in n8n itself are the fastest way into an instance: several recent ones allow remote code execution or reading credentials without logging in.
- **How to fix:** Upgrade n8n to the current stable release, then re-run this check with the new version.
- **Reference:** <https://github.com/n8n-io/n8n/security/advisories>

### 2. [HIGH] Secret written directly into the workflow

- **Where:** Billing: sync invoices (bad/hardcoded-secret.json) → "Fetch invoices"
- **Rule:** `HARDCODED-SECRET`
- **What we found:** "Fetch invoices" (httpRequest) contains 1 secret-looking value(s): literal "Authorization" value 9f8e… (32 chars).
- **Why it matters:** Workflow JSON is exported, shared, pasted into forums and committed to Git. A key inside it is readable by everyone who ever sees the file, and it cannot be rotated without editing every copy.
- **How to fix:** Move the value into an n8n credential (or an environment variable read with $env), rotate the exposed key at the provider, and re-export the workflow.
- **Reference:** <https://docs.n8n.io/credentials/>, <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/>

### 3. [HIGH] Secret written directly into the workflow

- **Where:** Billing: sync invoices (bad/hardcoded-secret.json) → "Log in to portal"
- **Rule:** `HARDCODED-SECRET`
- **What we found:** "Log in to portal" (code) contains 1 secret-looking value(s): hardcoded password Tr0u… (25 chars).
- **Why it matters:** Workflow JSON is exported, shared, pasted into forums and committed to Git. A key inside it is readable by everyone who ever sees the file, and it cannot be rotated without editing every copy.
- **How to fix:** Move the value into an n8n credential (or an environment variable read with $env), rotate the exposed key at the provider, and re-export the workflow.
- **Reference:** <https://docs.n8n.io/credentials/>, <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/>

### 4. [HIGH] Workflow runs shell commands on the n8n host

- **Where:** Media: convert (bad/execute-command.json) → "Convert video"
- **Rule:** `EXECUTE-COMMAND`
- **What we found:** "Convert video" (executeCommand) builds a shell command from workflow data.
- **Why it matters:** A shell on the n8n host can read every credential n8n holds. When any part of the command comes from workflow data, whoever controls that data controls the host.
- **How to fix:** Replace the command with a dedicated node or an HTTP call to a small service. If a command is unavoidable, never build it from input, and keep the node disabled on instances that face the internet.
- **Reference:** <https://docs.n8n.io/hosting/securing/blocking-nodes/>

### 5. [HIGH] Values pasted into SQL text instead of passed as parameters

- **Where:** Orders: lookup API (bad/sql-interpolation.json) → "Find orders"
- **Rule:** `SQL-INTERPOLATION`
- **What we found:** "Find orders" (postgres) builds SQL from workflow data: {{ $json.query.email }}.
- **Why it matters:** An expression inside the query text becomes part of the SQL. A quote in a customer name breaks the query; a crafted value (or a model-chosen value from $fromAI) can read or change other rows.
- **How to fix:** Use $1, $2 placeholders in the query and pass the values in the node's "Query Parameters" option, or use the node's insert/update operations.
- **Reference:** <https://docs.n8n.io/integrations/builtin/app-nodes/n8n-nodes-base.postgres/>, <https://owasp.org/www-community/attacks/SQL_Injection>

### 6. [HIGH] Public trigger accepts requests from anyone

- **Where:** Orders: webhook without auth (bad/webhook-no-auth.json) → "Order webhook"
- **Rule:** `WEBHOOK-NO-AUTH`
- **What we found:** Webhook (POST /orders) has no authentication and no secret or signature check, and it reaches 1 node(s) that read or change data: "Store event" (postgres).
- **Why it matters:** Anyone who finds or guesses the URL can run the workflow. When the workflow writes data, sends messages or moves money, that is an open door, and webhook paths leak through logs, browser history and screenshots.
- **How to fix:** Turn on the trigger's authentication (header auth, basic auth or JWT), or verify a shared secret or provider signature (HMAC) in the first node with a constant-time comparison, and answer 401 before anything else runs.
- **Reference:** <https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/>, <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/>

### 7. [HIGH] Public trigger accepts requests from anyone

- **Where:** Shop: public chat assistant (bad/public-chat.json) → "Public chat"
- **Rule:** `WEBHOOK-NO-AUTH`
- **What we found:** Public chat has no authentication and no secret or signature check, and it reaches 1 node(s) that read or change data: "Search catalogue" (httpRequestTool).
- **Why it matters:** Anyone who finds or guesses the URL can run the workflow. When the workflow writes data, sends messages or moves money, that is an open door, and webhook paths leak through logs, browser history and screenshots.
- **How to fix:** Turn on the trigger's authentication (header auth, basic auth or JWT), or verify a shared secret or provider signature (HMAC) in the first node with a constant-time comparison, and answer 401 before anything else runs.
- **Reference:** <https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/>, <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/>

### 8. [HIGH] AI agent can change data or move money with no limit outside the prompt

- **Where:** Support: AI agent with write tools (bad/agent-write-tools.json) → "Delete order"
- **Rule:** `AGENT-WRITE-TOOL`
- **What we found:** Agent "Support agent" can call "Delete order" (postgresTool), which runs a writing SQL statement. Nothing in this workflow limits what the model can do with it.
- **Why it matters:** A tool the model can call is a capability anyone who can talk to the model can try to use. Prompt injection, a confused model or a crafted customer message can make it refund, delete or send. A system prompt is a request, not a control.
- **How to fix:** Put the limit where the model cannot talk its way past it: scope every query to the authenticated user, enforce amounts and states in the database or in a sub-workflow, and route anything above a threshold to a human approval step. Log every tool call.
- **Reference:** <https://genai.owasp.org/llm-top-10/>, <https://genai.owasp.org/llmrisk/llm062025-excessive-agency/>

### 9. [HIGH] AI agent can change data or move money with no limit outside the prompt

- **Where:** Support: AI agent with write tools (bad/agent-write-tools.json) → "Issue refund"
- **Rule:** `AGENT-WRITE-TOOL`
- **What we found:** Agent "Support agent" can call "Issue refund" (httpRequestTool), which sends an HTTP POST request. Nothing in this workflow limits what the model can do with it.
- **Why it matters:** A tool the model can call is a capability anyone who can talk to the model can try to use. Prompt injection, a confused model or a crafted customer message can make it refund, delete or send. A system prompt is a request, not a control.
- **How to fix:** Put the limit where the model cannot talk its way past it: scope every query to the authenticated user, enforce amounts and states in the database or in a sub-workflow, and route anything above a threshold to a human approval step. Log every tool call.
- **Reference:** <https://genai.owasp.org/llm-top-10/>, <https://genai.owasp.org/llmrisk/llm062025-excessive-agency/>

### 10. [HIGH] Values pasted into SQL text instead of passed as parameters

- **Where:** Support: AI agent with write tools (bad/agent-write-tools.json) → "Delete order"
- **Rule:** `SQL-INTERPOLATION`
- **What we found:** "Delete order" (postgresTool) builds SQL from values the AI model chooses: {{ $fromAI('order_id', 'order to delete', 'number') }}.
- **Why it matters:** An expression inside the query text becomes part of the SQL. A quote in a customer name breaks the query; a crafted value (or a model-chosen value from $fromAI) can read or change other rows.
- **How to fix:** Use $1, $2 placeholders in the query and pass the values in the node's "Query Parameters" option, or use the node's insert/update operations.
- **Reference:** <https://docs.n8n.io/integrations/builtin/app-nodes/n8n-nodes-base.postgres/>, <https://owasp.org/www-community/attacks/SQL_Injection>

### 11. [MEDIUM] Duplicate protection that fails under concurrency

- **Where:** Events: notify once (bad/non-atomic-dedupe.json) → "Skip seen events"
- **Rule:** `NON-ATOMIC-DEDUPE`
- **What we found:** "Skip seen events" (removeDuplicates) remembers processed items across executions, which is a check-then-write and not atomic when deliveries arrive in parallel.
- **Why it matters:** Providers retry and deliver the same event more than once, often in parallel. A check-then-write dedupe (Remove Duplicates history, workflow static data) lets two simultaneous deliveries both pass, so the order ships twice.
- **How to fix:** Make the database decide: insert the event id into a table with a UNIQUE constraint (INSERT … ON CONFLICT DO NOTHING) and only continue when the insert actually happened.
- **Reference:** <https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.removeduplicates/>

### 12. [MEDIUM] Duplicate protection that fails under concurrency

- **Where:** Events: notify once (bad/non-atomic-dedupe.json) → "Remember event"
- **Rule:** `NON-ATOMIC-DEDUPE`
- **What we found:** "Remember event" (code) uses workflow static data to remember processed items. Static data is saved at the end of an execution, so parallel executions do not see each other.
- **Why it matters:** Providers retry and deliver the same event more than once, often in parallel. A check-then-write dedupe (Remove Duplicates history, workflow static data) lets two simultaneous deliveries both pass, so the order ships twice.
- **How to fix:** Make the database decide: insert the event id into a table with a UNIQUE constraint (INSERT … ON CONFLICT DO NOTHING) and only continue when the insert actually happened.
- **Reference:** <https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.removeduplicates/>

### 13. [MEDIUM] Webhook answers only after the whole workflow finishes

- **Where:** Leads: enrich (bad/responds-late.json) → "Lead webhook"
- **Rule:** `WEBHOOK-RESPONDS-LATE`
- **What we found:** "Lead webhook" (webhook) responds after the last node, and the caller waits for "Enrich lead" (httpRequest).
- **Why it matters:** With "respond when last node finishes", the caller waits for every external call. Senders time out after a few seconds and retry, which is where duplicates come from, and some (Stripe, Shopify) disable endpoints that are slow too often.
- **How to fix:** Acknowledge immediately (respond "immediately" or put a Respond to Webhook node right after validation and storing the event), then do the slow work after the response or in a sub-workflow that does not wait.
- **Reference:** <https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/>

### 14. [MEDIUM] Failures are not reported anywhere

- **Where:** Ops: health (bad/no-error-workflow.json)
- **Rule:** `NO-ERROR-WORKFLOW`
- **What we found:** Started by "Health" (webhook), but no error workflow is set.
- **Why it matters:** When a production execution fails, n8n records it and moves on. Without an error workflow, nobody hears about it until a customer does.
- **How to fix:** Create one error workflow (Error Trigger → alert to Slack/email/on-call and a row in an errors table) and select it under Workflow Settings → Error Workflow for every production workflow.
- **Reference:** <https://docs.n8n.io/flow-logic/error-handling/>

### 15. [MEDIUM] Webhook with side effects and no sign of duplicate protection

- **Where:** Payments: create order (bad/no-idempotency.json) → "Payment webhook"
- **Rule:** `WEBHOOK-NO-IDEMPOTENCY`
- **What we found:** POST /payments leads to "Create POS order" (httpRequest), and nothing on the way looks like an idempotency key or a unique constraint.
- **Why it matters:** Every webhook sender retries: payment providers, voice platforms, form tools, your own frontend after a timeout. Without an idempotency key the retry repeats the side effect (a second order, a second email, a second booking).
- **How to fix:** Take a stable id from the request (event id, message id, tool call id, or a hash of the payload), store it with a UNIQUE constraint before acting, and return the stored result when it is seen again.
- **Reference:** <https://docs.stripe.com/webhooks#handle-duplicate-events>

### 16. [MEDIUM] Failures continue down the success path

- **Where:** Reminders: SMS (bad/errors-swallowed.json) → "Send reminder SMS"
- **Rule:** `ERRORS-SWALLOWED`
- **What we found:** "Send reminder SMS" (twilio) continues on error, and the next node does not check for the error.
- **Why it matters:** With "continue (regular output)", a failed call hands its error to the next node as if it were a result. Unless someone checks, the workflow reports success for work that did not happen.
- **How to fix:** Use "continue (using error output)" and handle the error branch, or check the status / error field in the very next node and route failures to a retry or dead-letter path.
- **Reference:** <https://docs.n8n.io/flow-logic/error-handling/>

### 17. [MEDIUM] External call fails the run on the first error

- **Where:** Stock: push to ERP (bad/http-reliability.json) → "Push stock levels"
- **Rule:** `HTTP-NO-RETRY`
- **What we found:** "Push stock levels" (httpRequest) has neither "Retry On Fail" nor an error output.
- **Why it matters:** APIs return 429 and 5xx as a matter of course. Without a retry or an error branch, one blip stops the execution halfway: some steps done, the rest not, and nobody told.
- **How to fix:** Enable "Retry On Fail" with 3–5 tries and a wait, or route errors to an explicit error output that records the failure for a later retry (a dead-letter table).
- **Reference:** <https://docs.n8n.io/flow-logic/error-handling/>

### 18. [MEDIUM] AI agent can change data or move money with no limit outside the prompt

- **Where:** Support: AI agent with write tools (bad/agent-write-tools.json) → "Look up customer"
- **Rule:** `AGENT-WRITE-TOOL`
- **What we found:** Agent "Support agent" can call "Look up customer" (toolWorkflow); its effects are defined elsewhere. Check that its limits are enforced there and not only described to the model.
- **Why it matters:** A tool the model can call is a capability anyone who can talk to the model can try to use. Prompt injection, a confused model or a crafted customer message can make it refund, delete or send. A system prompt is a request, not a control.
- **How to fix:** Put the limit where the model cannot talk its way past it: scope every query to the authenticated user, enforce amounts and states in the database or in a sub-workflow, and route anything above a threshold to a human approval step. Log every tool call.
- **Reference:** <https://genai.owasp.org/llm-top-10/>, <https://genai.owasp.org/llmrisk/llm062025-excessive-agency/>

### 19. [LOW] Export contains pinned test data

- **Where:** Reports: nightly (bad/export-hygiene.json)
- **Rule:** `PINDATA-IN-EXPORT`
- **What we found:** Pinned data on 1 node(s): "Every 15 minutes".
- **Why it matters:** Pinned data is usually a copy of a real execution: customer names, emails, payloads, sometimes tokens. It travels with every export.
- **How to fix:** Unpin the data before exporting, or strip "pinData" from the file (instance-check.sh does this).
- **Reference:** <https://docs.n8n.io/data/data-pinning/>

### 20. [LOW] Failed executions are not saved

- **Where:** Reports: nightly (bad/export-hygiene.json)
- **Rule:** `SAVE-ERROR-EXECUTIONS-OFF`
- **What we found:** Workflow settings discard failed executions (saveDataErrorExecution = "none").
- **Why it matters:** With failed executions discarded, there is nothing to debug or replay after an incident.
- **How to fix:** Set Workflow Settings → Save failed production executions to "Save", and prune old executions by age instead.
- **Reference:** <https://docs.n8n.io/workflows/settings/>

### 21. [LOW] External call without an explicit timeout

- **Where:** Stock: push to ERP (bad/http-reliability.json) → "Push stock levels"
- **Rule:** `HTTP-NO-TIMEOUT`
- **What we found:** "Push stock levels" (httpRequest) relies on the default timeout.
- **Why it matters:** A hanging API keeps the execution (and, behind a webhook, the caller) waiting far longer than any sender will. Explicit timeouts turn hangs into errors your retry and error paths can handle.
- **How to fix:** Set Options → Timeout on the HTTP Request node to a value that fits the caller (for example 5–30 seconds).
- **Reference:** <https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.httprequest/>

## Fix plan

**Quick fixes you can usually do yourself in the editor:**

- The n8n version has published security advisories (1 place): Upgrade n8n to the current stable release, then re-run this check with the new version.
- Secret written directly into the workflow (2 places): Move the value into an n8n credential (or an environment variable read with $env), rotate the exposed key at the provider, and re-export the workflow.
- Values pasted into SQL text instead of passed as parameters (2 places): Use $1, $2 placeholders in the query and pass the values in the node's "Query Parameters" option, or use the node's insert/update operations.
- Public trigger accepts requests from anyone (2 places): Turn on the trigger's authentication (header auth, basic auth or JWT), or verify a shared secret or provider signature (HMAC) in the first node with a constant-time comparison, and answer 401 before anything else runs.
- Webhook answers only after the whole workflow finishes (1 place): Acknowledge immediately (respond "immediately" or put a Respond to Webhook node right after validation and storing the event), then do the slow work after the response or in a sub-workflow that does not wait.
- Failures are not reported anywhere (1 place): Create one error workflow (Error Trigger → alert to Slack/email/on-call and a row in an errors table) and select it under Workflow Settings → Error Workflow for every production workflow.
- Failures continue down the success path (1 place): Use "continue (using error output)" and handle the error branch, or check the status / error field in the very next node and route failures to a retry or dead-letter path.
- External call fails the run on the first error (1 place): Enable "Retry On Fail" with 3–5 tries and a wait, or route errors to an explicit error output that records the failure for a later retry (a dead-letter table).
- Export contains pinned test data (1 place): Unpin the data before exporting, or strip "pinData" from the file (instance-check.sh does this).
- Failed executions are not saved (1 place): Set Workflow Settings → Save failed production executions to "Save", and prune old executions by age instead.
- External call without an explicit timeout (1 place): Set Options → Timeout on the HTTP Request node to a value that fits the caller (for example 5–30 seconds).

**Changes that need design and testing (a fix sprint):**

- Workflow runs shell commands on the n8n host (1 place): Replace the command with a dedicated node or an HTTP call to a small service. If a command is unavoidable, never build it from input, and keep the node disabled on instances that face the internet.
- AI agent can change data or move money with no limit outside the prompt (3 places): Put the limit where the model cannot talk its way past it: scope every query to the authenticated user, enforce amounts and states in the database or in a sub-workflow, and route anything above a threshold to a human approval step. Log every tool call.
- Duplicate protection that fails under concurrency (2 places): Make the database decide: insert the event id into a table with a UNIQUE constraint (INSERT … ON CONFLICT DO NOTHING) and only continue when the insert actually happened.
- Webhook with side effects and no sign of duplicate protection (1 place): Take a stable id from the request (event id, message id, tool call id, or a hash of the payload), store it with a UNIQUE constraint before acting, and return the stored result when it is seen again.

## Scope and limitations

- This is a static review of exported workflow JSON. It does not run workflows, call your APIs or log in to your instance, and it is not a penetration test.
- Rules are heuristics tuned to avoid false alarms, so a clean result does not prove a workflow is safe. Logic inside sub-workflows, external services and databases is only visible if those workflows are included.
- Secrets are shown masked (first 4 characters). Treat any secret listed here as exposed and rotate it.
- Advisory data comes from the public npm/GitHub advisory database and is only as current as the date above.
