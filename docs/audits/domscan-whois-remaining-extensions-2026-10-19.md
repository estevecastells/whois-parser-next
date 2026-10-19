# DomScan WHOIS remaining-extension diagnostics (2026-10-19)

This diagnostic follow-up tracks the 46 usage namespaces that were still
unpaired in the frozen production-validation snapshot. Their pinned
[registry-demand weights](data/domscan-whois-registry-demand-2026-10-17.csv)
sum to 233 request items. A weight is an aggregate request-item count, not a
unique-domain count or a count of current live requests. The pinned
registry-demand CSV and frozen 30-day usage window remain unchanged; the
[2026-10-17 usage audit](domscan-whois-usage-2026-10-17.md) now reflects these
follow-up results in its current-outcome section.

**Production validation status (2026-10-19).** Production build
`cdc6fc3a59ec0a12d2f6c8e0ac6ebf226d5c4705` is active on blue with parser 0.4.7;
workflow [39193322142](https://github.com/estevecastells/domscan/actions/runs/39193322142)
completed successfully. The registered and absent v1/v2 control pairs for
`.ga`, `.jo`, `.sx`, `.gt`, and `.com.gt` passed on this build. The 12 `.ga`,
`.jo`, and `.sx` checks and all eight `.gt`/`.com.gt` checks returned HTTP 200
from WHOIS. The GT checks ran between 03:18:08 and 03:18:49 UTC. Together with
the earlier successful `.mw` pair, these results add six paired usage
namespaces to the tally.

`.mw` retains its earlier successful registered/absent pair on build
`740c1e8db6952a9537d2dd842e0b5cebf660e7c8`. On the current build, the
registered control passed, but the absent control returned unknown with source
`unknown` after 2.84 seconds. This is an
intermittent outcome, so the older pair remains evidence of paired capability
without establishing a stable `.mw` route.

Relative to the frozen 46-namespace / 233-request-item baseline, the six newly
paired namespaces leave 40 unpaired namespaces / 226 weighted request items.
The final tally is 302 of 342 usage namespaces, 315 total paired namespaces
including 13 zero-demand namespaces, 282 distinct root TLDs, and 23,479 of
23,705 weighted requests paired (99.0466%). These are paired-capability
results for the audited samples, not a historical accuracy or uptime measure.

The clearest access constraints are `.ph` (written permission or an approved
unchallenged interface), `.es` (a signed request, an authorized source IP, and
a stated query limit), and `.mt` (an approved automated interface after a real
`cap-widget` and human-verification gate persisted despite a normal session).
`.az` also presents a CAPTCHA on its premium lookup, `.hu` uses reCAPTCHA, and
`.al` limits how registrars may offer automated availability checks. For `.py`,
the published policy restricts redistribution and publication of WHOIS data;
it does not document a machine endpoint. These are distinct findings, not a
single access diagnosis for all 40 remaining namespaces.

Endpoint discovery and transport failures are tracked separately. `.gr` has a
current public WHOIS page and documentation of a registrar-facing HTTPS REST
API, but no exact API base URL; the documented static-IP condition is scoped
to registrar services and has not been shown to govern the public lookup.
Timeouts, connection refusals, DNS failures, TLS errors, and stale-route 404s
show a network or route problem only; they do not prove registry denial or
domain status. “Not resolved” means no current authoritative protocol or
production pair was established in this follow-up.

The table records the observed evidence and next action for each originally
unpaired namespace. No challenge was bypassed and no authentication control
was evaded.

| Namespace | Frozen weight | Current diagnostic and next action |
| --- | ---: | --- |
| `.ph` | 108 | Proxy access returned HTTP 403 with a Cloudflare challenge. [dotPH's official terms](https://whois.dot.ph/) prohibit high-volume automated queries and repackaging without prior written consent. Stop automated queries; continue only with written permission or an approved interface. |
| `.es` | 34 | The production query timed out; this does not establish whether its source IP is authorized. The official [port-43 procedure](https://www.dominios.es/es/sobre-dominios/valores-anadidos/whois-43) requires a signed access request, one authorized IP per person or organization, and a 10-query-per-minute limit. Obtain authorization for the production IP, then run a paced pair. |
| `.mt` | 31 | An ordinary query returned a real `cap-widget` challenge. Preserving server-issued session cookies still led to human verification and a `whois-cap-form` POST response, not a domain record. Obtain a registry-approved automated interface; no challenge was bypassed. |
| `.hu` | 5 | Direct WHOIS reset; US and Japan proxy attempts were empty or failed. The public lookup form uses reCAPTCHA. The [official status page](https://status.domain.hu/) lists WHOIS as operational and shows a resolved external-abuse incident from Oct 14. Seek an approved interface or registry guidance; do not bypass reCAPTCHA. |
| `.mp` | 4 | The official storefront loaded and exposes a domain-search API in its front end, but no query was submitted and no public WHOIS/RDAP endpoint was identified. Review official API documentation and terms before a permitted test. |
| `.et` | 3 | Not resolved in this follow-up; no new production pair. Identify the current official service and permitted query method, then run a bounded pair if available. |
| `.gr` | 3 | The current [registry WHOIS lookup](https://grweb.ics.forth.gr/public/whois?lang=en) is a public web interface. Its [registrar guidance](https://grweb.ics.forth.gr/public/registrars?lang=en) documents an HTTPS REST API for registrar integration, but gives no exact API base URL. The static-IP requirement is scoped to services offered to registrars; these sources do not apply it to the public lookup. Treat the API as an endpoint-discovery lead, not a routeable target; the earlier legacy-path 404 was not domain absence. |
| `.ms` | 3 | WHOIS TCP was refused. IANA lists `whois.nic.ms` and RDAP base `https://rdap.nic.ms`; the attempted paths `/domain/nic.ms` and `/rdap/domain/gov.ms` returned HTML 404, not RDAP responses or an absence result. Validate the current RDAP object path or repair the route before another pair. |
| `.ne` | 3 | Not resolved in this follow-up; no new production pair. Identify the current official endpoint and permitted query method. |
| `.az` | 2 | The current official [WHOIS page](https://whois.az/) presents a CAPTCHA on its Premium WHOIS Lookup. The older `www.nic.az` under-construction page was a stale route, not the current lookup. No challenge was bypassed, and no approved machine endpoint was documented; use an interface supplied by the registry if one is available. |
| `.com.gt` | 2 | All registered/absent v1/v2 checks against the official [UVG web WHOIS](https://www.gt/sitio/whois.php?dn={domain}) passed on current production build `cdc6fc3a59ec0a12d2f6c8e0ac6ebf226d5c4705`; counted as one paired namespace. |
| `.al` | 1 | [AKEP's availability page](https://akep.al/en/kerkoni-domain-te-lire/) is an availability search, not a public WHOIS endpoint. Its [registrar guidance](https://akep.al/wp-content/uploads/2021/07/VKD_Nr__41_dt_4_6_2018_per_disa_shtesa_dhe_ndryshime_ne_Rreg__nr__2_te_domain_al-1.pdf) says automated checks must follow AKEP instructions and cannot be offered by registrars to third parties. No public WHOIS/RDAP machine endpoint was found; seek registry-approved instructions before automation. |
| `.ao` | 1 | Not resolved in this follow-up; no new production pair. Check the current registry service and permitted query path. |
| `.bo` | 1 | A registered query worked, but the absent-name query returned `whois.nic.bo solo acepta consultas con dominios .bo`, an invalid-query response. Repair the query format or route and obtain an authoritative absence reply; do not classify this text as absence. |
| `.bt` | 1 | The official page loaded with a GET form asking for a website URL; no query was submitted. Determine from registry documentation whether this is a domain lookup and which interface is approved before testing. |
| `.bw` | 1 | An earlier protocol probe returned a prohibited-string response for both states; this was not a fresh probe. Verify current documented query syntax and access rules before a bounded pair. |
| `.cf` | 1 | Not resolved in this follow-up; no new production pair. Check the current official service and permitted query path. |
| `.com.sy` | 1 | The official WHOIS connection timed out. Verify the current host and service status before a bounded retry; timeout is not an absence result. |
| `.com.vn` | 1 | The older VNNIC `/en/domain` route returned HTTP 404; no `.com.vn` query was submitted. Resolve the current official route for this second-level namespace before testing. |
| `.cy` | 1 | The current site is a WordPress homepage; no domain query was submitted. Identify an official registry lookup interface rather than treating the general site search as WHOIS. |
| `.dj` | 1 | The legacy `whois.php` path returned HTTP 404. Locate the current official service before retrying. |
| `.eg` | 1 | The official lookup target timed out before returning content. Retry only after the documented service is reachable; no domain result was observed. |
| `.ga` | 1 | The registered and absent v1/v2 control pairs passed on active production build `cdc6fc3a59ec0a12d2f6c8e0ac6ebf226d5c4705`; counted as one paired namespace. |
| `.gp` | 1 | Direct access timed out and both proxy attempts failed at the proxy-infrastructure layer. Restore a working authorized path before a bounded registry check; the failures do not establish registry access denial. |
| `.gq` | 1 | An earlier Freenom reply said the TLD had no WHOIS server; that is not an absence result. IANA currently lists `whois.dominio.gq`. Verify the current official route and query method before a bounded pair. |
| `.gt` | 1 | All registered/absent v1/v2 checks against the official [UVG web WHOIS](https://www.gt/sitio/whois.php?dn={domain}) passed on current production build `cdc6fc3a59ec0a12d2f6c8e0ac6ebf226d5c4705`; counted as one paired namespace. This is web WHOIS, not a TCP/43 or RDAP service. |
| `.gw` | 1 | The legacy WHOIS page returned HTTP 404. Find a current official service route before retrying. |
| `.il` | 1 | Registered and generated-absent direct queries returned the same 790-byte policy disclaimer without the exact absence marker. The exact-marker fix is deployed in parser 0.4.7; its policy regression check passed with the disclaimer-only reply unknown. A separate `.org.il` registered WHOIS control passed, but no `.il` absence pair was established, so `.il` adds no coverage. |
| `.iq` | 1 | DNS resolution failed for `whois.cmc.iq`; no WHOIS response was obtained. Verify the current registry host or protocol before a bounded retry. |
| `.jo` | 1 | Both registered/absent v1/v2 control pairs from IANA-listed `whois.nic.net.jo` passed on active production build `cdc6fc3a59ec0a12d2f6c8e0ac6ebf226d5c4705`; counted as one paired namespace. Direct access timed out, while the managed proxy succeeded. |
| `.lk` | 1 | Not resolved in this follow-up; no new production pair. Check the current official service and permitted query path. |
| `.mv` | 1 | Not resolved in this follow-up; no new production pair. Check the current official service and permitted query path. |
| `.mw` | 1 | A registered/absent pair passed on build `740c1e8db6952a9537d2dd842e0b5cebf660e7c8` and remains the evidence for counting this namespace. On current build `cdc6fc3a59ec0a12d2f6c8e0ac6ebf226d5c4705`, the registered control passed but the absent control was unknown with source `unknown` after 2.84 seconds. Intermittent outcomes remain unknown; the earlier pair does not establish a stable route. |
| `.ni` | 1 | The current site loaded a Vue application, but no domain query was submitted. Inspect its official client/API documentation and terms before using any lookup endpoint. |
| `.nr` | 1 | The legacy WHOIS page timed out. Find a current official service path before a bounded retry. |
| `.pa` | 1 | TLS certificate-chain validation failed. Repair or confirm the official chain before retrying; do not disable certificate validation. |
| `.pro.vn` | 1 | Not resolved in this follow-up; no new production pair. Establish the official lookup route for this second-level namespace. |
| `.ps` | 1 | TCP was refused and the proxy attempt failed at the infrastructure layer. Verify the current official host and a working authorized route before retrying. |
| `.py` | 1 | The current official [NIC.PY form](https://www.nic.py/consultdompy.php) provides active-domain information. Its [delegation policy](https://www.nic.py/politicas-de-delegacion.php) prohibits redistribution or retransmission of WHOIS database information and requires prior administrator authorization to publish it. Do not redistribute or republish results without authorization. No TCP/43 or RDAP endpoint was documented; the old path's 404 was not a domain result. |
| `.sv` | 1 | The public homepage contains a POST lookup form; no query was submitted. Review its official instructions and terms before a permitted test. |
| `.sx` | 1 | Both registered/absent v1/v2 control pairs from IANA-listed `whois.sx` passed on active production build `cdc6fc3a59ec0a12d2f6c8e0ac6ebf226d5c4705`; counted as one paired namespace. |
| `.tj` | 1 | The legacy WHOIS page timed out. Verify the current official endpoint and network path before retrying. |
| `.tt` | 1 | Not resolved in this follow-up; no new production pair. Check the current official service and permitted query path. |
| `.vn` | 1 | The older VNNIC `/en/domain` route returned HTTP 404. Locate the current official lookup path before testing; no absence result was obtained. |
| `.za` | 1 | [ZADNA's registry information](https://www.zadna.org.za/) explains that registrations are handled under second-level zones such as `.co.za`; no root `.za` WHOIS endpoint was established. Resolve the applicable delegated zone before selecting its registry. |
| `.zw` | 1 | IANA publishes no root `.zw` WHOIS/RDAP base. [ZISPA](https://www.zispa.org.zw/) describes registry scope for `.co.zw`, not a general root `.zw` service. Resolve the queried second-level zone before selecting a registry; no root `.zw` endpoint was established. |

## Interpretation and sources

A timeout, refusal, DNS failure, HTTP error, human-verification prompt, protocol
error, invalid query, disclaimer, or missing result is not proof of registration
or absence. The frozen baseline remains unchanged. Six follow-up namespaces
have paired evidence, and the weighted result is 99.0466% paired capability
for the audited sample, not a historical accuracy or uptime measure. No
unverified source query or local parser result is counted as a production API
pair. This report labels an explicit policy or observed challenge
as an access constraint, a page without a documented machine endpoint as an
endpoint gap, and a timeout/refusal/DNS/TLS/HTTP failure as a transport or route
diagnostic. No challenge was bypassed and no authorization was forged.

Official references used for route provenance and access constraints include
[dotPH's WHOIS terms](https://whois.dot.ph/), [Dominios.es' port-43 access
procedure](https://www.dominios.es/es/sobre-dominios/valores-anadidos/whois-43),
the [ISZT service-status page](https://status.domain.hu/), the official
[.gr WHOIS page](https://grweb.ics.forth.gr/public/whois?lang=en) and
[registrar API information](https://grweb.ics.forth.gr/public/registrars?lang=en),
[AKEP's .al availability page](https://akep.al/en/kerkoni-domain-te-lire/) and
[registrar guidance](https://akep.al/wp-content/uploads/2021/07/VKD_Nr__41_dt_4_6_2018_per_disa_shtesa_dhe_ndryzime_ne_Rreg__nr__2_te_domain_al-1.pdf),
[NIC.PY's query form](https://www.nic.py/consultdompy.php) and
[delegation policy](https://www.nic.py/politicas-de-delegacion.php),
[whois.az](https://whois.az/), [ZADNA](https://www.zadna.org.za/),
[ZISPA](https://www.zispa.org.zw/), and the official
[IANA root records for `.ph`](https://www.iana.org/domains/root/db/ph.html),
[`.bo`](https://www.iana.org/domains/root/db/bo.html),
[`.bw`](https://www.iana.org/domains/root/db/bw),
[`.gq`](https://www.iana.org/domains/root/db/gq.html),
[`.gt`](https://www.iana.org/domains/root/db/gt.html),
[`.il`](https://www.iana.org/domains/root/db/il.html),
[`.jo`](https://www.iana.org/domains/root/db/jo.html),
[`.ms`](https://www.iana.org/domains/root/db/ms.html),
[`.mw`](https://www.iana.org/domains/root/db/mw.html), and
[`.sx`](https://www.iana.org/domains/root/db/sx.html). The official
[UVG `.gt` registry](https://www.gt/sitio/) and its
[registration policy](https://www.gt/sitio/registration_policy.php?lang=en)
document the public web WHOIS route and individual-name search restriction.
ANINF's current
[`.ga` webWHOIS](https://whois.nic.ga/) and
[registration policy](https://www.mon.ga/policy/registry_policies.pdf) provide
`.ga` provenance. These sources establish service context, not successful
application-level coverage.
