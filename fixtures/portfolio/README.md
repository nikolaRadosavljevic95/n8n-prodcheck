Copies of the 16 workflows from [n8n-portfolio](https://github.com/nikolaRadosavljevic95/n8n-portfolio)
(same author, MIT), used as a realistic, known set in the tests.

`.prodcheck-ignore.json` records the findings that were reviewed and accepted, each with
the reason. After the ignore list these workflows must produce no findings, and
`../portfolio-before-fix` (the RFQ workflows before they got authentication) must produce
exactly four, so a rule change that adds or drops a finding shows up as a failing test.
