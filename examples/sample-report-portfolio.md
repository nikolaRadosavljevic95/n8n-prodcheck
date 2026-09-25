# Sample report: the author's own portfolio

**Subject:** [n8n-portfolio](https://github.com/nikolaRadosavljevic95/n8n-portfolio), 16 workflows, run with the reviewed ignore list in fixtures/portfolio/.prodcheck-ignore.json  
**Date:** 2026-09-25  
**Scanned:** 16 workflow(s), 170 node(s)  
**n8n version:** 2.40.5  
**Tool:** [n8n-prodcheck](https://github.com/nikolaRadosavljevic95/n8n-prodcheck), advisory data from 2026-09-25

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 0 |
| HIGH | 4 |
| MEDIUM | 0 |
| LOW | 0 |
| Suppressed (reviewed) | 5 |

**Fix first:**

1. **HIGH** Public trigger accepts requests from anyone: RFQ: API (webhooks) (portfolio/05-rfq-api.json) → "POST /rfq/quote"
2. **HIGH** Public trigger accepts requests from anyone: RFQ: API (webhooks) (portfolio/05-rfq-api.json) → "GET /rfq/quote/xlsx"
3. **HIGH** Public trigger accepts requests from anyone: RFQ: API (webhooks) (portfolio/05-rfq-api.json) → "POST /rfq/review/resolve"
4. **HIGH** Public trigger accepts requests from anyone: RFQ: Upload form (portfolio/06-rfq-upload-form.json) → "RFQ upload form"

## Findings

### 1. [HIGH] Public trigger accepts requests from anyone

- **Where:** RFQ: API (webhooks) (portfolio/05-rfq-api.json) → "POST /rfq/quote"
- **Rule:** `WEBHOOK-NO-AUTH`
- **What we found:** Webhook (POST /rfq/quote) has no authentication and no secret or signature check, and it reaches 1 node(s) that read or change data: "Run RFQ engine" (executeWorkflow).
- **Why it matters:** Anyone who finds or guesses the URL can run the workflow. When the workflow writes data, sends messages or moves money, that is an open door, and webhook paths leak through logs, browser history and screenshots.
- **How to fix:** Turn on the trigger's authentication (header auth, basic auth or JWT), or verify a shared secret or provider signature (HMAC) in the first node with a constant-time comparison, and answer 401 before anything else runs.
- **Reference:** <https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/>, <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/>

### 2. [HIGH] Public trigger accepts requests from anyone

- **Where:** RFQ: API (webhooks) (portfolio/05-rfq-api.json) → "GET /rfq/quote/xlsx"
- **Rule:** `WEBHOOK-NO-AUTH`
- **What we found:** Webhook (GET /rfq/quote/xlsx) has no authentication and no secret or signature check, and it reaches 2 node(s) that read or change data: "Load quote" (postgres), "Render quote" (executeWorkflow).
- **Why it matters:** Anyone who finds or guesses the URL can run the workflow. When the workflow writes data, sends messages or moves money, that is an open door, and webhook paths leak through logs, browser history and screenshots.
- **How to fix:** Turn on the trigger's authentication (header auth, basic auth or JWT), or verify a shared secret or provider signature (HMAC) in the first node with a constant-time comparison, and answer 401 before anything else runs.
- **Reference:** <https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/>, <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/>

### 3. [HIGH] Public trigger accepts requests from anyone

- **Where:** RFQ: API (webhooks) (portfolio/05-rfq-api.json) → "POST /rfq/review/resolve"
- **Rule:** `WEBHOOK-NO-AUTH`
- **What we found:** Webhook (POST /rfq/review/resolve) has no authentication and no secret or signature check, and it reaches 1 node(s) that read or change data: "Resolve line" (postgres).
- **Why it matters:** Anyone who finds or guesses the URL can run the workflow. When the workflow writes data, sends messages or moves money, that is an open door, and webhook paths leak through logs, browser history and screenshots.
- **How to fix:** Turn on the trigger's authentication (header auth, basic auth or JWT), or verify a shared secret or provider signature (HMAC) in the first node with a constant-time comparison, and answer 401 before anything else runs.
- **Reference:** <https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/>, <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/>

### 4. [HIGH] Public trigger accepts requests from anyone

- **Where:** RFQ: Upload form (portfolio/06-rfq-upload-form.json) → "RFQ upload form"
- **Rule:** `WEBHOOK-NO-AUTH`
- **What we found:** Form has no authentication and no secret or signature check, and it reaches 1 node(s) that read or change data: "Run RFQ engine" (executeWorkflow).
- **Why it matters:** Anyone who finds or guesses the URL can run the workflow. When the workflow writes data, sends messages or moves money, that is an open door, and webhook paths leak through logs, browser history and screenshots.
- **How to fix:** Turn on the trigger's authentication (header auth, basic auth or JWT), or verify a shared secret or provider signature (HMAC) in the first node with a constant-time comparison, and answer 401 before anything else runs.
- **Reference:** <https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/>, <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/>

## Fix plan

**Quick fixes you can usually do yourself in the editor:**

- Public trigger accepts requests from anyone (4 places): Turn on the trigger's authentication (header auth, basic auth or JWT), or verify a shared secret or provider signature (HMAC) in the first node with a constant-time comparison, and answer 401 before anything else runs.

**Changes that need design and testing (a fix sprint):**

- none

## Reviewed and suppressed

These matched a rule but were reviewed and accepted, with the reason recorded in the ignore file.

- `WEBHOOK-NO-AUTH` Mock: POS API (portfolio/09-mock-pos-api.json) → "POST /mock/pos/orders": Test double for the point-of-sale system. It only exists in the local test stack and is never deployed.
- `WEBHOOK-NO-AUTH` Mock: Agent LLM (portfolio/14-mock-agent-llm.json) → "POST /mock/llm-agent/chat/completions": Test double for the LLM provider. It only exists in the local test stack and is never deployed.
- `WEBHOOK-NO-AUTH` Mock: OpenAI-compatible LLM (portfolio/10-mock-openai-compatible-llm.json) → "POST /mock/llm/chat/completions": Test double for the LLM provider. It only exists in the local test stack and is never deployed.
- `WEBHOOK-NO-IDEMPOTENCY` Agent: Approvals and audit API (portfolio/16-agent-approvals-and-audit-api.json) → "POST /agent/approvals/decide": agent.decide_approval() locks the approval row (FOR UPDATE) and refuses a decision that is no longer pending. The end-to-end test 'Approving releases the money exactly once' approves twice and asserts one refund.
- `WEBHOOK-NO-IDEMPOTENCY` RFQ: API (webhooks) (portfolio/05-rfq-api.json) → "POST /rfq/review/resolve": rfq.resolve_line() locks the quote, sets the line to the chosen SKU and upserts the customer part number (ON CONFLICT DO UPDATE), so repeating the request gives the same result.

## Scope and limitations

- This is a static review of exported workflow JSON. It does not run workflows, call your APIs or log in to your instance, and it is not a penetration test.
- Rules are heuristics tuned to avoid false alarms, so a clean result does not prove a workflow is safe. Logic inside sub-workflows, external services and databases is only visible if those workflows are included.
- Secrets are shown masked (first 4 characters). Treat any secret listed here as exposed and rotate it.
- Advisory data comes from the public npm/GitHub advisory database and is only as current as the date above.
