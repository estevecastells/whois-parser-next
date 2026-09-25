# High-rank unresolved TLD follow-up: `.es`, `.pk`, `.shop`, `.dev`, `.app`

Date: 2026-09-25

## Scope and outcomes

This follow-up uses source ranks from the pinned ICANN DNS Magnitude snapshot
dated 2026-09-12 (generated 2026-09-18), not rankings from other TLD lists.
The ranks are `.dev` 43, `.app` 47, `.es` 52, `.pk` 84, and `.shop` 157.
The WHOIS parser can now classify the exact PKNIC port-43 registered and
explicitly available response forms. This is parser support only: the `whois`
6.0.3 server table maps `.pk` to a legacy web adapter, not PKNIC port-43, so
DomScan does not gain effective `.pk` coverage until its routing is separately
corrected and deployed.

| ICANN source rank | TLD | Current authoritative path | Parser outcome |
|---:|---|---|---|
| 43 | `.dev` | Google Registry RDAP; IANA lists no WHOIS server | Leave legacy WHOIS result unresolved; route through official RDAP |
| 47 | `.app` | Google Registry RDAP; IANA lists no WHOIS server | Leave legacy WHOIS result unresolved; route through official RDAP |
| 52 | `.es` | `whois.nic.es`; access restricted to registry-approved IPs; no IANA RDAP bootstrap entry | No authorized probe; preserve unknown |
| 84 | `.pk` | `whois.pknic.net.pk`; no IANA RDAP bootstrap entry | Parse exact registered and explicit availability markers; do not infer availability from a bare “Not Registered” status |
| 157 | `.shop` | Official GMO Registry RDAP; legacy WHOIS endpoint now returns its retirement notice | No WHOIS classification; route through official RDAP |

## Evidence and limits

IANA's delegation records list `whois.nic.es` for `.es` and
`whois.pknic.net.pk` for `.pk`; the current IANA RDAP bootstrap has no entries
for either TLD. IANA lists `whois.nic.shop` and the GMO Registry RDAP endpoint
for `.shop`, and lists only Google Registry RDAP for `.dev` and `.app`.
The `whois` gem 6.0.3 nevertheless returns `whois.nic.google` for `.dev` and
`.app`; this is not an IANA-designated WHOIS endpoint for those TLDs and must
not be treated as a successful registry route.

On 2026-09-25, bounded direct port-43 probes to the IANA-listed PKNIC host
returned these sanitized results:

```text
google.pk
Domain: google.pk
Status: Domain is Registered

codex-audit-20260925-7418321.pk
Domain: codex-audit-20260925-7418321.pk
Status: Not Registered, and may be available if valid
Available: Yes.
```

The `.pk` fixtures retain only the domain and exact status lines; no registrant
or contact information is included. The parser requires both the echoed `.pk`
domain and the registry's exact `Available: Yes.` line before returning
`:available`. Conflicting markers return `:unknown`. Empty, denied, throttled,
and incomplete absence responses have adversarial coverage.

Probe limits were a 4-second connection timeout, 7-second response deadline,
64 KiB response cap, and at least 2 seconds between WHOIS queries. No `.es`
query was attempted: Dominios.es documents that port-43 access is limited to
IP addresses individually authorized by Red.es. No port-43 query was sent to
`.dev` or `.app`, because IANA does not list a WHOIS service for them. The
`.shop` endpoint returned its retirement notice; a bounded request to the
official GMO RDAP endpoint returned HTTP 200 with a domain object for
`nic.shop`. These responses support routing conclusions, not availability
classification for any of the five TLDs.

## `.pk` routing handoff for DomScan

The parser class resolves from the official host name
`whois.pknic.net.pk`, but `Whois::Server.find_for_domain('google.pk')` returns
`Whois::Server::Adapters::Web` with no WHOIS host (and URL
`http://www.pknic.net.pk/`) under `whois` 6.0.3. That is the exact routing gap:
the standard client cannot select PKNIC port-43 for a `.pk` query, even though
the parser exists. `Whois::Client.new(host: 'whois.pknic.net.pk')` is not a
working override for this route in 6.0.3: `Client#lookup` first selects the
registered Web adapter, and `Web#request` raises `Whois::WebInterfaceError`
regardless of the configured host. A fixed-host socket path can instead call
`Whois::Server::Adapters::Standard.new(:tld, 'pk',
'whois.pknic.net.pk').lookup(domain)`. DomScan must invoke such a path through
its managed relay and with bounded WHOIS timeouts. This routing change belongs
in DomScan and must be deployed before `.pk` is counted as effective coverage.

For `.dev`, `.app`, and `.shop`, DomScan should use the official RDAP endpoints
(`https://pubapi.registry.google/rdap/` for `.dev` and `.app`, and
`https://rdap.gmoregistry.net/rdap/` for `.shop`) instead of interpreting
legacy WHOIS responses. For `.es`, keep the outcome unknown unless DomScan has
an authorized Red.es query path; the registry restriction is not evidence of
absence.

## Official sources

- [ICANN DNS Magnitude historical snapshot](https://magnitude.research.icann.org/historic/20260912.full.html)
- [IANA `.es` delegation record](https://www.iana.org/domains/root/db/es.html)
- [IANA `.pk` delegation record](https://www.iana.org/domains/root/db/pk.html)
- [IANA `.shop` delegation record](https://www.iana.org/domains/root/db/shop.html)
- [IANA `.dev` delegation record](https://www.iana.org/domains/root/db/dev.html)
- [IANA `.app` delegation record](https://www.iana.org/domains/root/db/app.html)
- [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json)
- [Dominios.es WHOIS access procedure](https://www.dominios.es/sites/dominios/files/es_Procedimiento%20de%20alta%20servicio%20whois%20puerto%2043%20v4_cambio%20sede%20%28ult%29.pdf)
- [PKNIC official site and WHOIS lookup](https://www.pknic.net.pk/)
- [Google Registry registration-data request](https://www.registry.google/registration-data-request/)
- [GMO Registry](https://www.gmoregistry.com/en/)
