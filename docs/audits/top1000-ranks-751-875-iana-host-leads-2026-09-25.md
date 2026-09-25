# Top-1000 ranks 751-875: IANA host leads

Date: 2026-09-25

## Scope and result

This is a metadata-only follow-up to the pinned 2026-09-12 ICANN DNS Magnitude
manifest. It checks current IANA root-zone records against the locked WHOIS
6.0.3 host inventory and the existing package reports. No port-43 requests
were made, no response text was collected, and no parser behavior is newly
verified by this note.

## Leads

| Rank | TLD | Existing inventory and report | Current IANA record | Assessment |
|---:|---|---|---|---|
| 752 | `.leclerc` | The locked client maps `whois-leclerc.nic.fr`; the package-4 report records DNS failure and no parser conclusion. | [IANA lists `whois.nic.leclerc`](https://www.iana.org/domains/root/db/leclerc.html), plus `rdap.nic.leclerc`. | Host mismatch is an audit lead. Confirm routing and access before considering parser work. |
| 773 | `.corsica` | The locked client maps `whois-corsica.nic.fr`; the package-3 report records DNS failure and no parser conclusion. | [IANA lists `whois.nic.corsica`](https://www.iana.org/domains/root/db/corsica.html), plus `rdap.nic.corsica`. | Host mismatch is an audit lead. Confirm routing and access before considering parser work. |
| 857 | `.rio` | The locked client maps `whois.gtlds.nic.br`; the package-4 report records a timeout and no parser conclusion. | [IANA lists `rdap.gtlds.nic.br` and no WHOIS server](https://www.iana.org/domains/root/db/rio.html). | Treat as RDAP-only in current root-zone metadata; do not infer a port-43 parser gap. |

The IANA records are the authority for the current advertised RDDS endpoints.
These differences do not establish that the alternate AFNIC hosts accept port
43 queries, that the parser sees their replies, or that the output format
requires a change.

## Capture and terms gate

The repository and its adjacent parser worktrees contain no supported Ruby
capture/sanitizer helper. The default Ruby is 2.6.10, below the repository's
Ruby 3.2 minimum; Ruby 3.2.2 is installed, but there is no vetted helper to
preflight with it. No network probe was run.

[AFNIC's public WHOIS terms](https://www.afnic.fr/en/domain-names-and-support/everything-there-is-to-know-about-domain-names/find-a-domain-name-or-a-holder-using-whois/)
restrict high-volume automated queries and prohibit reproduction or use of a
whole or substantial part of its WHOIS database without express permission.
That page lists `.fr`, `.re`, `.tf`, `.yt`, `.pm`, and `.wf`; it does not state
the terms applicable to `.leclerc` or `.corsica`. Their redistribution rights
remain unresolved, so this note retains metadata only and does not create
fixtures.

## References in this repository

- `docs/audits/data/whois-parser-top1000-planning.csv`, ranks 752, 773, and 857
- `docs/audits/whois-parser-top1000-package-3-2026-09-19.md`, rank 773
- `docs/audits/whois-parser-top1000-package-4-2026-09-19.md`, ranks 752 and 857

No parser, routing, fixture, dependency, version, or deployment change is made.
