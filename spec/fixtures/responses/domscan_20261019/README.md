# DomScan WHOIS response-shape controls — 2026-10-19

The registered and absent files in this directory are **synthetic test
controls**, not verbatim production replies. They preserve only the observed
technical labels, punctuation, and response structure needed to exercise the
parsers. Domain names and dates are generated for tests; contact blocks and
captured record contents are omitted.

The controls cover these observed response shapes:

- `whois.nic.ga/`: ANINF's French field labels, an active status, a creation
date, and the exact `%% NOT FOUND` absence marker.
- `whois.nic.net.jo/`: a domain identity, creation date, and active domain
  status; plus the quoted-name `No match for domain` absence response with its
  echoed query name.
- `whois.sx/`: the current CIRA EPP status lines and exact `Not found: <name>`
  absence response, alongside the legacy format used by the parser.

## Live evidence and source terms

Bounded checks through the production host and the existing managed proxy pool
on 2026-10-19 UTC observed registered and absent replies for each host. The
captured replies are retained outside this fixture directory and are not
reproduced here.

IANA lists `whois.nic.net.jo` for [`.jo`](https://www.iana.org/domains/root/db/jo.html)
and `whois.sx` for [`.sx`](https://www.iana.org/domains/root/db/sx.html). IANA
has no WHOIS listing for `.ga`; ANINF's [official webWHOIS](https://whois.nic.ga/)
and [registration policy](https://www.mon.ga/policy/registry_policies.pdf)
provide the `.ga` source context. ANINF's policy states that it holds rights to
the WHOIS database and that registrant data is subject to restricted
circulation. The `.sx` response refers users to [CIRA's legal notice and WHOIS
terms](https://www.cira.ca/en/resources/documents/about/website-terms-use/),
which limit use and collection of WHOIS information. No permission to
redistribute the original `.ga` or `.sx` replies is asserted here; neither is
included in these fixtures.
