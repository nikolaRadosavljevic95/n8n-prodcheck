Copies of the 16 workflows from [n8n-portfolio](https://github.com/nikolaRadosavljevic95/n8n-portfolio)
(same author, MIT), used as a realistic, known set in the tests.

`.prodcheck-ignore.json` records the findings that were reviewed and accepted, each with
the reason. What remains after the ignore list is asserted exactly in `test/run.mjs`, so a
rule change that adds or drops a finding on these workflows shows up as a failing test.
