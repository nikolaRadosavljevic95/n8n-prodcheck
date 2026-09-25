# instance-check.sh

A small script you run on your own server to hand over your workflows for a review, without handing over anything else.

## What it does

1. Records the n8n version (`n8n --version`).
2. Exports every workflow definition with `n8n export:workflow --all --separate`.
3. Cleans each exported file in place:
   - removes `pinData` (pinned test data, often copied from real executions),
   - removes `staticData`,
   - replaces anything that looks like a secret with `***REDACTED***`: API keys and tokens in known formats (OpenAI, Anthropic, Stripe, AWS, GitHub, Slack, Google, SendGrid, Telegram, JWTs, private keys), passwords inside URLs, literal values of headers and parameters named like `Authorization`, `api_key`, `token`, `secret` or `password`, and string literals assigned to variables with those names in Code nodes.
4. Packs the folder into `<output>.tar.gz`.

## What it does not collect

- **Credentials.** It never runs `export:credentials`. Workflows only reference credentials by name and id.
- **Executions**, execution data, logs, users, environment variables or database contents.
- It makes no network calls and changes nothing in your instance.

## How to run it

Docker (container named `n8n`):

```bash
docker cp instance-check.sh n8n:/tmp/instance-check.sh
docker exec -u node n8n sh /tmp/instance-check.sh /tmp/prodcheck-export
docker cp n8n:/tmp/prodcheck-export.tar.gz .
docker exec -u node n8n rm -rf /tmp/prodcheck-export /tmp/prodcheck-export.tar.gz /tmp/instance-check.sh
```

npm install on the host:

```bash
sh instance-check.sh ./prodcheck-export
```

Then open a few files in `prodcheck-export/workflows/` and check that nothing sensitive is left before you send the archive. The redaction is pattern based: it errs on the side of removing too much, but it cannot know every internal secret format.

## Checking it yourself

The script is plain `sh` plus an inline Node program, about 90 lines. Read it before running it. You can also run the checker locally on the result:

```bash
npx github:nikolaRadosavljevic95/n8n-prodcheck ./prodcheck-export/workflows --n8n-version "$(cat prodcheck-export/n8n-version.txt)"
```
