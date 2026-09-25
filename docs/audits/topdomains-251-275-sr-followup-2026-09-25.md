# `.sr` current-host follow-up for ranks 251-275

Date: 2026-09-25

This supplements the point-in-time audit of ICANN DNS Magnitude ranks 251-275
dated 2026-09-19. It documents parser evidence for rank 251, `.sr`, without
changing the default WHOIS client routing.

## IANA host and bounded evidence

IANA's [`.sr` delegation record](https://www.iana.org/domains/root/db/sr.html)
lists `whois.sr` as the WHOIS server and `https://whois.sr/rdap/` as the RDAP
server.

On 2026-09-25, one registered name and one generated name were queried at the
IANA-listed WHOIS host. The registered `google.sr` response exposed the domain,
creation date, registry expiry date, active status, and name-server fields.
The generated `codex-rank251-20260925.sr` response included the exact line
`Message: No Object Found`. The fixtures retain only parser-relevant fields and
contain no contact data.

The parser recognizes that exact no-object marker and a registered response
only when the domain, active status, and creation date are present. Denied,
throttled, empty, and incomplete responses remain unavailable or unknown.

## Default-client routing limit

The `whois` 6.0.3 routing catalog has no `.sr` entry. The new parser is selected
only when a response part is already keyed to `whois.sr`; it does not make the
default client query that host. Route integration must be tested separately
before counting `.sr` as effective coverage. Parser-file presence alone is not
effective coverage, and this follow-up makes no claim about broad top-1,000
coverage.
