# DomScan WHOIS parser usage audit

Observed 2026-09-28 at approximately 21:15 UTC. Source: DomScan's production
`api_request_logs`, retained for 30 days. This is a privacy-safe aggregate:
customer domains, accounts, contacts, and raw WHOIS bodies are not published.

## What was used

The [usage CSV](data/domscan-whois-usage-2026-09-28.csv) contains every root
suffix in syntactically valid domain inputs to `/v1/whois`, `/v2/whois`, and
`/v1/whois/bulk` from 2026-08-29 through the observation time. The
[read-only SQL](../../scripts/domscan_whois_usage.sql) reproduces it while the
logs are retained.

| Measure | Observed count |
| --- | ---: |
| Valid-looking domain items in endpoint requests | 44,975 |
| Distinct root suffixes in those requests | 519 |
| Domain items associated with an HTTP 200 response | 24,797 |
| Single-domain responses recording traditional WHOIS use | 4,101 |
| Root suffixes with recorded traditional WHOIS use | 113 |

The [mapping CSV](data/domscan-whois-parser-mapping-2026-09-28.csv) compares all
113 traditional-WHOIS suffixes with the current parser tree and DomScan's
explicit relay hosts. The [mapping audit](../../scripts/audit_domscan_whois_usage.rb)
can be rerun against the aggregate. Before this change, `.mn` was the only
observed live-response host without a parser class. The other unmapped host,
`whois.nic.shop`, returns a WHOIS-retirement notice pointing to RDAP. Its 345
recorded traditional calls are not registration evidence, so no WHOIS parser
is added for that retired service. The remaining host mappings resolve to a
parser class, including `.co.za` and the relay's explicit `.africa`, `.ge`,
`.pk`, and `.sr` routes. A class mapping is structural coverage, not proof that
every live response shape is parsed correctly.

## Changes and observed evidence

- `.mn`: four recorded traditional WHOIS responses used `whois.nic.mn`: three
  record-shaped replies and one `Domain not found.` reply. Added a parser for
  those shapes, with CRLF, denial, incomplete, and contradictory regressions.
  [IANA lists `whois.nic.mn` as the registry WHOIS host](https://www.iana.org/domains/root/db/mn.html).
- `.cl`: 126 recorded traditional responses. The old parser inferred
  registration from every reply that was not an absence marker. It now requires
  current record fields or the legacy `ACE` record shape. Denials and partial
  replies remain unknown. [IANA lists `whois.nic.cl`](https://www.iana.org/domains/root/db/cl.html).
- `.eu`: 190 recorded traditional responses. The old parser used the same
  unsafe inverse-of-absence rule. It now requires a domain record plus a
  registrar or nameserver section and rejects contradictory evidence. The
  registry's disclaimer alone remains unknown. [IANA lists `whois.eu`](https://www.iana.org/domains/root/db/eu.html).
- `.shop`: the observed body says the traditional service retired on
  2026-05-01 and directs queries to RDAP. Existing retirement regression
  coverage already preserves an unknown WHOIS result.

Fixtures added for this audit are minimal synthetic parser regression shapes
derived from observed fields and markers. They are not copied or redacted
registry responses. Bounded live observations are summarized separately in
this report; existing historical parser fixtures remain regression inputs.

A privacy-safe [streaming replay](../../scripts/replay_domscan_whois_previews.rb)
of the retained response previews checked the changes against actual traffic
without writing those previews to disk. All 126 `.cl` previews and all four
`.mn` previews matched the API's recorded available/registered class. The
190 `.eu` previews are capped at 2,048 characters and end in the registry's
long disclaimer before the record section, so this replay classifies them
unknown; the full existing `.eu` registered and available fixtures pass.
The [replay query](../../scripts/domscan_whois_replay_previews.sql) streams only
the three changed suffixes and must not be saved to a file.

## Reliability boundary

This audit closes the unmapped parser-host gap among observed traditional
responses and removes two false-registration patterns. It does not establish
100% end-to-end reliability. Most of the 519 suffixes did not reach traditional
WHOIS in a retained successful response; they may be served by RDAP, cache,
or never pass validation, rate limiting, or credit checks. The request log is
retained for 30 days, its response preview is bounded, and bulk replies do
not provide per-item traditional-WHOIS telemetry. Registries can retire WHOIS,
limit access, change formats, or return ambiguous data. Such results must stay
unknown rather than become an available or registered claim.

`.mn` uses an official, publicly listed registry host and no paid source.
The registry's rate-limit and reuse terms were not established by this audit;
it adds parsing only and does not change query volume or routing. If registry
evidence is unavailable, the parser returns unknown. The sample is too small
to estimate a live error rate.

## Pinned high-demand coverage gate

The original mapping inventory is supplemented by a frozen first-class
coverage ledger for every suffix with more than five endpoint request items.
It contains 153 suffixes and 44,402 request items. The usage CSV, IANA service
page observations, and IANA root-label list are stored with their SHA-256
digests; this preserves the evidence after the production request logs expire.
The executable audit is
[`audit_domscan_whois_coverage.rb`](../scripts/audit_domscan_whois_coverage.rb).

At this audit revision, the ledger reports 94 registered/absence fixture pairs,
one `.za` multi-label route observation, one tested temporary WHOIS exception
(`.uk`), one restricted registered-record-only case (`.open`), 37 RDAP-only
classifications, two explicitly unsupported historical routes (`.info` and
`.news`), one retired endpoint, and no parser-pending rows. The `.uk` tests use
current redacted registered and absence responses from `whois.nic.uk`, plus a
synthetic denial regression; no live Nominet denial was observed, and its live
banner is policy text. The gate verifies each row against the pinned usage
data, IANA response snapshot, direct parser classes, and referenced specs. A
class mapping without response truth cases does not satisfy the strict parser
gate.

The 94 registered/absence pairs count regression cases, not independent live
registry captures. The ledger describes bounded live observations separately;
where redistribution terms restrict raw WHOIS text, tests use minimal synthetic
shapes or marker lines instead of copied response bodies.

The `.uk` exception preserves a current fact that IANA's service fields alone
miss: official [Nominet guidance](https://theukdomain.uk/rdap/) says WHOIS at
`whois.nic.uk` continues through 2027-02-09, even though IANA stopped listing
the WHOIS field in August 2026. The manifest keeps IANA's RDAP-only fields as
captured, records this exception separately, and points to current registered,
absence, denial, mixed-evidence, partial-record, and throttle tests. The
explicit denial fixture is synthetic. The DomScan 30-day snapshot has zero
traditional WHOIS calls for `.uk`.

Parser evidence and installed runtime routing remain separate. The pinned
`whois` 6.0.3 route audit finds 52 route differences. Three are already
covered by pinned DomScan host mappings: `.za` via the multi-label `.co.za`
service, `.pk`, and `.africa` (154 items total). The remaining 49 are unresolved
against the installed upstream `whois` gem in this parser-worktree audit and
cover 7,840 request items:

| Installed-route state | Suffixes | Items | Highest-volume examples |
| --- | ---: | ---: | --- |
| Existing DomScan host mapping verified; excluded as blocker | 3 | 154 | `.za` 139; `.pk` 8; `.africa` 7 |
| Installed host differs from current IANA WHOIS host | 9 | 2,985 | `.org` 2,231; `.gift` 323; `.ie` 121; `.help` 118; `.click` 53 |
| RDAP-only suffix still has a stale configured WHOIS route | 36 | 3,729 | `.app` 1,316; `.dev` 496; `.live` 432; `.today` 306; `.gifts` 102 |
| RDAP-only legacy route needs an application skip | 2 | 638 | `.info` 617; `.news` 21 |
| Retired endpoint remains configured | 1 | 470 | `.shop` 470 |
| IANA WHOIS service has no installed library route | 1 | 18 | `.open` 18 |

The nine IANA-host mismatches are `.org`, `.gift`, `.ie`, `.help`, `.click`,
`.biz`, `.homes`, `.to`, and `.dk`. The 36 stale RDAP-only route labels are
`.app`, `.dev`, `.live`, `.today`, `.pro`, `.gifts`, `.events`, `.promo`,
`.games`, `.money`, `.bet`, `.casino`, `.day`, `.mobi`, `.network`, `.studio`,
`.support`, `.life`, `.services`, `.photography`, `.world`, `.bio`, `.company`,
`.email`, `.business`, `.solutions`, `.team`, `.market`, `.education`,
`.media`, `.you`, `.builders`, `.how`, `.digital`, `.red`, and `.reviews`.
The historical `.info` and `.news` calls do not establish WHOIS as a current
protocol. Their exact unsupported responses are tested; the application still
needs to skip the obsolete WHOIS routes.

The official [Amex `.open` registration policy](https://web.aexp-static.com/content/dam/amex/us/staticassets/pdf/nic/Registry-Policies-OPEN.pdf)
restricts registration and control to the operator, qualifying affiliates, and
trademark licensees. A current official WHOIS response for the registry-owned
`nic.open` returned a complete record with registry ID `D511-OPEN`, Amex
registrar/IANA ID `9999`, dates, statuses, and nameservers. A bounded lookup for
`google.open` returned `No Data Found` and policy text. RDAP returned HTTP 200
for `nic.open`; sampled 404 responses for other names are not authoritative
absence. These are bounded live observations, not fixture contents. Published
parser tests use minimal synthetic registered and no-data shapes, with no
copied or redacted raw WHOIS body. The parser marks only the complete exact
`nic.open` record registered; `No Data Found` remains unknown, it is not
public-availability evidence, and there is no authoritative public-absence
case in this ledger. The parser-worktree
installed client still has no route for IANA's listed server, so `.open` remains
one of the upstream route-audit blockers below. The separate DomScan patch now
overrides it to `whois.nic.open`. The `.za` observation is traffic served
through `.co.za`; it does not establish direct `.za` parser coverage, and its
volume cannot be isolated from final-label-only statistics.

These counts describe the installed `whois` gem in this parser worktree. At the
2026-09-29 audit cutoff, a separate DomScan worktree contained a locally
verified route patch; that patch does not change the installed-gem counts
above. It adds explicit official-host
overrides for `.biz`, `.click`, `.dk`, `.gift`, `.help`, `.homes`, `.ie`, `.org`,
`.to`, and temporary `.uk`. It skips the 39 used IANA RDAP-only suffixes,
retired `.shop`, and the existing operational `.ai` skip. The RDAP-only skip
set is `.app`, `.bet`, `.bio`, `.builders`, `.business`, `.casino`, `.company`,
`.day`, `.dev`, `.digital`, `.education`, `.email`, `.events`, `.games`,
`.gifts`, `.how`, `.info`, `.life`, `.live`, `.market`, `.media`, `.microsoft`,
`.mobi`, `.money`, `.network`, `.news`, `.photography`, `.pro`, `.promo`,
`.red`, `.reviews`, `.services`, `.solutions`, `.studio`, `.support`, `.team`,
`.today`, `.world`, and `.you`. The `.ai` skip is an application policy, not an
RDAP-only classification: IANA lists WHOIS and RDAP for `.ai`, and the snapshot
has 1,132 requests but no traditional WHOIS calls.
The patch retains the existing `.africa`, `.ge`, `.mu`, `.pk`, `.sr`, and
multi-label `.co.za` handling. With the new `.open` override, it addresses all
49 upstream route blockers at the DomScan application layer. The parser
worktree's strict runtime gate still reports 49 because it checks the installed
upstream `whois` gem, independently of DomScan's overrides and skips. At the
2026-09-29 audit cutoff, these application changes were local and verified, but
had not been committed or pushed; the parser gem had not been released or
pinned in a production dependency, and DomScan had not been deployed.

The DomScan route patch passed its focused routing suite (97 tests), the `.open`
relay route matrix (16 tests), and full `npm test` (9,480 passed, 89 skipped).
The `.open` parser suite passes (46 examples, 0 failures). After fixture
minimization, the integrated full parser RSpec suite passes (7,001 examples,
0 failures). On Ruby 3.4.5, the
parser worktree's default integrity audit and strict parser gate succeed;
strict runtime still reports 49 installed-gem route blockers. The coverage
audit spec passes (3 examples, 0 failures). At the 2026-09-29 audit cutoff, no
gem release, dependency pin, push, or production deployment had occurred.
