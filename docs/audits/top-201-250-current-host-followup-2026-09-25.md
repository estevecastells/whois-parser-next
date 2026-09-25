# Current WHOIS host follow-up for ranks 201-250

Date: 2026-09-25

This follow-up checks the highest-ranked delegated rows in the pinned
ICANN DNS Magnitude snapshot whose 2026-09-19 audit did not establish current
registered-plus-absence parsing.

## IANA host and bounded live evidence

IANA's [`.mu` delegation record](https://www.iana.org/domains/root/db/mu.html)
lists `whois.tld.mu` and `https://rdap.identitydigital.services/rdap/`.
IANA's [`.africa` delegation record](https://www.iana.org/domains/root/db/africa.html)
lists `whois.nic.africa` and `https://rdap.nic.africa/rdap/`.

On 2026-09-25, bounded direct probes to both IANA-listed hosts covered one
registered name and one generated name per host. The generated `.africa`
query was repeated once to inspect its exact short response. Captures are
reduced to parser-relevant fields and omit contact values.

| Rank | TLD | IANA WHOIS host | Registered evidence | Generated-name response |
| ---: | --- | --- | --- | --- |
| 203 | `.mu` | `whois.tld.mu` | `google.mu` returned a record with a creation date, registry expiry date, EPP status fields, and four name servers. | `codex-20260925.mu` returned the exact line `Domain not found.` |
| 212 | `.africa` | `whois.nic.africa` | `google.africa` returned a record with a registry domain ID, creation date, registry expiry date, EPP status fields, and four name servers. | `codex-20260925.africa` returned the exact line `No information was found matching that query.` followed by the registry's terms and copyright footer. |

The `.iq` row at rank 201 still maps to IANA's listed `whois.cmc.iq`, but that
host did not resolve from the audit environment on 2026-09-25. At rank 205,
IANA's `.ga` record lists no WHOIS endpoint; its current mapped host also did
not resolve in the 2026-09-19 audit. Neither result supports parser
classification.

## Parser behavior and effective coverage limit

Host-specific parsers and sanitized registered/absence fixtures are provided
for the two live IANA hosts. Denials, query throttling, empty responses, and
unrecognized replies remain unavailable or unknown.

This does **not** increase effective default-client coverage yet. The pinned
`whois` 6.0.3 client definitions still route `.mu` to `whois.nic.mu` and
`.africa` to `africa-whois.registry.net.za`, while IANA lists different
WHOIS hosts. The new parsers apply only when a response part is already keyed
to the IANA-listed host. Updating the lookup mapping is outside this
parser-only change. Until that mapping changes and is verified, do not count
either row as effective coverage.

No coverage is inferred from parser-file presence alone, and no claim is made
about broad top-1,000 coverage.
