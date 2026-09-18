# Security Policy

## Supported versions

Until the first release, only the current main branch is supported.

| Version | Supported |
|---|---|
| main | Yes |
| Released versions | No released versions yet |

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/estevecastells/whois-parser-next/security/advisories/new).

Do not open a public issue or pull request for a suspected vulnerability.

Please include:

- A clear description of the issue and its impact
- A minimal reproduction or proof of concept
- The affected commit, branch, or dependency version
- The Ruby version and relevant environment details
- The TLD, WHOIS server, and observed date where relevant
- Expected behavior and actual behavior
- Sanitized response examples where needed
- Any suggested mitigation

Remove credentials, access tokens, private endpoints, personal registrant data,
and other sensitive information before submitting a report. Do not include
secrets or private source responses in public fixtures.

## Disclosure

Please do not disclose a vulnerability publicly before the maintainers have had
an opportunity to investigate, coordinate a fix or mitigation, and agree on
disclosure timing.

We expect to acknowledge reports after they reach the maintainers and provide
follow-up after triage. Workload and severity vary, so no exact response or
remediation timeline is promised.
