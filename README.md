# n8n-prodcheck

[![ci](https://github.com/nikolaRadosavljevic95/n8n-prodcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/nikolaRadosavljevic95/n8n-prodcheck/actions/workflows/ci.yml)

A free, dependency-free check for n8n workflows that are about to run in production, or already do. Point it at your exported workflow JSON and it tells you where a webhook is open to anyone, where a retry will create a second order, where a secret is sitting in plain text, and where an AI agent can refund or delete with nothing but a prompt in the way.

```bash
npx github:nikolaRadosavljevic95/n8n-prodcheck ./workflows --n8n-version 1.121.0
```

It needs Node 20 or newer and nothing else. It never talks to your n8n instance: it reads files.

## What it catches

| Rule | Severity | What it catches |
|---|---|---|
| `N8N-VERSION-ADVISORY` | up to critical | Your n8n version has published security advisories (from the npm/GitHub advisory database, refreshed weekly) |
| `WEBHOOK-NO-AUTH` | high | A webhook, form or public chat that anyone can call, with no auth and no signature check, reaching your database or APIs |
| `HARDCODED-SECRET` | high | API keys, tokens, passwords and private keys written into nodes, code or sticky notes |
| `AGENT-WRITE-TOOL` | high | An AI agent that can write, delete, send or move money through its tools, with no limit outside the prompt |
| `SQL-INTERPOLATION` | high | Values pasted into SQL text (including values the model picks with `$fromAI`) instead of query parameters |
| `EXECUTE-COMMAND` | high | Shell commands on the n8n host, especially ones built from workflow data |
| `NON-ATOMIC-DEDUPE` | medium | "Remove Duplicates" history or static data used to stop duplicates, which fails when deliveries arrive in parallel |
| `WEBHOOK-NO-IDEMPOTENCY` | medium | A webhook with side effects and no idempotency key or unique constraint anywhere on the path, sub-workflows included |
| `WEBHOOK-RESPONDS-LATE` | medium | A webhook that answers only after slow external calls, which makes senders time out and retry |
| `HTTP-NO-RETRY` | medium | An external call with no retry and no error branch |
| `ERRORS-SWALLOWED` | medium | "Continue on error" where nothing checks whether it failed |
| `NO-ERROR-WORKFLOW` | medium | Production workflows with no error workflow, so failures go unnoticed |
| `HTTP-NO-TIMEOUT` | low | External calls relying on the default timeout |
| `PINDATA-IN-EXPORT` | low | Pinned test data (often real customer data) inside the export |
| `SAVE-ERROR-EXECUTIONS-OFF` | low | Failed executions are thrown away |

Every rule, why it matters and how to fix it: [RULES.md](RULES.md). The rules are tuned to stay quiet on well-built workflows: a false alarm costs more trust than a missed low-severity issue.

## Sample reports

- [Synthetic example](examples/sample-report-synthetic.md): workflows written to trigger every rule, on n8n 1.120.0.
- [The author's own portfolio](examples/sample-report-portfolio.md): 16 production-style workflows from [n8n-portfolio](https://github.com/nikolaRadosavljevic95/n8n-portfolio). It found four real problems there (the RFQ demo's API and form have no authentication), which are left in the report on purpose.

## Usage

```bash
# a folder, a single file, or the array written by "n8n export:workflow --all"
npx github:nikolaRadosavljevic95/n8n-prodcheck ./workflows

# also check the instance version against published advisories
npx github:nikolaRadosavljevic95/n8n-prodcheck ./workflows --n8n-version 1.121.0

# a Markdown report to hand to a colleague or a client
npx github:nikolaRadosavljevic95/n8n-prodcheck ./workflows --format md --out report.md

# in CI: fail the build on anything high or worse
npx github:nikolaRadosavljevic95/n8n-prodcheck ./workflows --fail-on high
```

Options: `--format text|md|json`, `--out <file>`, `--ignore <file>`, `--fail-on critical|high|medium|low`, `--title`, `--subject`.

### Getting the workflows out of n8n

- One workflow: in the editor, **⋯ → Download**.
- All of them, from the command line where n8n runs: `n8n export:workflow --all --separate --output=./workflows/`
- From a server you do not want to copy files off by hand: [instance-check.sh](instance-check.sh) exports every workflow (never credentials), strips pinned data and redacts secret-looking values before anything leaves the machine. See [INSTANCE-CHECK.md](INSTANCE-CHECK.md).

Before sharing exports with anyone, clean them:

```bash
npx github:nikolaRadosavljevic95/n8n-prodcheck sanitize ./workflows
```

### Reviewed findings

Some findings are fine once a person has looked at them: a test double without auth, a database function that already handles repeats. Record them in an ignore file with the reason, and they move to a "reviewed" section of the report instead of disappearing:

```json
{
  "ignore": [
    { "rule": "WEBHOOK-NO-AUTH", "workflow": "Mock: POS API", "reason": "Test double, never deployed." }
  ]
}
```

`workflow` and `node` are optional; `reason` is required.

## What it does not do

It is a static check of workflow JSON. It does not run your workflows, call your APIs or log in to your instance, and it is not a penetration test. It cannot see inside databases, external services or sub-workflows you did not include, so a clean result is a good sign, not a guarantee. Instance settings (users, roles, environment, queue mode, backups) are not part of an export.

## A human review

The checker finds the patterns. Deciding which ones matter for your business, and fixing them without breaking production, is the part that needs a person. I do fixed-price reviews of n8n setups (a written report ranked by severity, with a fix plan) and the fixes themselves, delivered as workflows-as-code with end-to-end tests like the ones in [n8n-portfolio](https://github.com/nikolaRadosavljevic95/n8n-portfolio).

<!-- TODO: replace the link below with the Upwork or Contra profile once it is live -->
Get in touch through my GitHub profile: [github.com/nikolaRadosavljevic95](https://github.com/nikolaRadosavljevic95).

## Development

```bash
npm test                 # the test suite (no dependencies)
npm run advisories       # refresh data/advisories.json from the npm advisory database
npm run samples          # regenerate RULES.md and the sample reports
```

Fixtures: `fixtures/bad` has one small workflow per rule and `fixtures/expected-bad.json` lists exactly which rules each must trigger; `fixtures/good` must produce nothing; `fixtures/portfolio` is a real set of 16 workflows whose remaining findings are asserted exactly.

## License

MIT, see [LICENSE](LICENSE).
