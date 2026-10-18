# DomScan WHOIS usage audit (2026-10-17)

This report uses a frozen 30-day window from `2026-09-18T02:30:00Z` inclusive
to `2026-10-18T02:30:00Z` exclusive. The snapshot was prepared locally on
2026-10-17 after the window closed. Customer domains and raw WHOIS response
text are not included in the checked-in data files.

## Request mix

A separate log-level summary counted 25,563 HTTP requests to `/v1/whois`,
`/v2/whois`, and `/v1/whois/bulk`, including invalid or missing-domain
requests and admission-rejected calls. The suffix aggregate expands bulk
inputs into items and keeps domain strings matching the query-shape check. It
contains 24,718 request items across 455 final-label buckets; these are not
unique domains, eligible registration attempts, or WHOIS calls. The suffix
snapshot records 23,419 HTTP 200 items and 2,822 items whose response recorded
traditional WHOIS use.

An independent source-split query counted single-domain HTTP 200 rows by the
API's `edge_summary.authoritative_source` field, excluding malformed Unicode
responses. It does not use the usage aggregate's syntactically valid domain
filter. Although both queries sum to 23,419 here, they do not necessarily
describe the same population.

The recorded source split is:

| Recorded response source | Single-domain HTTP 200 rows |
| --- | ---: |
| RDAP | 16,835 |
| WHOIS | 2,822 |
| Cache | 1,713 |
| Unknown | 2,049 |

These are source labels stored by the API, not verified successful registry
answers. The `.lu` false-availability cases below are included in the
recorded WHOIS count.

The pinned 0.4.0 ledger contains 94 suffixes with registered/absence fixture
pairs. Exact suffix matching finds 83 of them in the October snapshot,
accounting for 17,491 of 24,718 request items (70.76%). Those suffixes account
for 2,568 of the 2,822 recorded traditional WHOIS calls (91.00%). This is
fixture-pair overlap by request volume, not live parser accuracy.

Sixteen suffixes above the ledger's five-item cutoff were absent from that
September baseline. Counts below are request items / recorded traditional
WHOIS calls:

| Suffix | Items / WHOIS calls | Suffix | Items / WHOIS calls |
| --- | ---: | --- | ---: |
| `.si` | 2,992 / 3 | `.nz` | 60 / 60 |
| `.bz` | 13 / 2 | `.ge` | 12 / 0 |
| `.new` | 12 / 0 | `.tr` | 11 / 11 |
| `.su` | 8 / 8 | `.buzz` | 8 / 0 |
| `.place` | 8 / 0 | `.bond` | 7 / 1 |
| `.nu` | 7 / 7 | `.st` | 7 / 7 |
| `.gl` | 6 / 6 | `.il` | 6 / 5 |
| `.qpon` | 6 / 0 | `.vg` | 6 / 4 |

The source query keeps only the final label, so multi-label registration
namespaces such as `.co.uk` cannot be separated from their final-label bucket.

## `.lu` false availability and bounded checks

The IANA root record lists `whois.dns.lu` for `.lu`. DNS-LU documents `FREE`
as available to register, `ACTIVE` as registered and active, and `RESERVED` as
registered and reserved in its WHOIS response fields. See the [IANA `.lu`
record](https://www.iana.org/domains/root/db/lu.html) and [DNS-LU's API and
protocol documentation](https://dns.lu/en/domains/apiprotocols).

In the frozen window, 741 `.lu` HTTP 200 previews with `domaintype: ACTIVE`
were recorded by the API as `available=true`. The installed parser 0.4.0
classified these previews as registered. The local parser change now requires
both a domain name and an exact active-status field, leaves contradictory or
incomplete evidence unknown, and treats `%% Maximum query rate reached` as a
typed throttle. The separate DomScan application change ignores
non-authoritative comment text when looking for availability markers.

The on-host replay compared the API's recorded class with parser 0.4.0 for
2,821 response previews across 119 suffixes. Its query excludes malformed
Unicode records and its output flags previews at the 2,048-character limit as
possibly truncated. It is a comparison of stored previews, not a post-change
replay or a ground-truth accuracy score. Disagreements outside the 741 `.lu`
cases remain review candidates unless independently validated. The source
split likewise reports recorded source labels only.

Two bounded `.lu` probes saw one valid registered `dns.lu` record and a
generated absent-name query answered with `%% Maximum query rate reached`;
probing stopped at the throttle. A direct `.io` relay probe returned HTTP 429
with `whois_rate_limited`, and probing stopped. The production log aggregate
also contains 215 `.lu` raw previews with the maximum-query-rate marker among
1,212 single-lookup HTTP 200 responses. These observations establish that
rate limiting must remain unknown; they do not establish broad live coverage.

The 99% live-accuracy target was **not achieved or demonstrated** by the
original frozen-window data. Fixture pairs, host mappings, source labels, and
the bounded replay do not prove end-to-end success. At the original audit
cutoff, the application/relay revision was
`636bb42b2336e82ce1e5dd77c2b30cc4a090f86a` and used parser 0.4.0; the 0.4.1
parser and application changes were still local. Their later release and
deployment milestones are recorded in the dated follow-ups below.

The report's usage, source-split, and replay tables are in
[`data/domscan-whois-usage-2026-10-17.csv`](data/domscan-whois-usage-2026-10-17.csv),
[`data/domscan-whois-sources-2026-10-17.csv`](data/domscan-whois-sources-2026-10-17.csv),
and [`data/domscan-whois-replay-2026-10-17.csv`](data/domscan-whois-replay-2026-10-17.csv).
The frozen usage, source, and total-request queries are
[`scripts/domscan_whois_usage_20261017.sql`](../../scripts/domscan_whois_usage_20261017.sql),
[`scripts/domscan_whois_sources_20261017.sql`](../../scripts/domscan_whois_sources_20261017.sql),
and [`scripts/domscan_whois_summary_20261017.sql`](../../scripts/domscan_whois_summary_20261017.sql).
The [on-host replay script](../../scripts/replay_domscan_whois_on_host.rb)
streams response text on the relay host and emits only aggregated classes; it
must not be run by exporting raw WHOIS previews. The full parser suite passes
7,016 examples with 0 failures, and the package smoke check passes on Ruby
3.2 and 3.4.5. Snapshot integrity is checked by
`spec/audits/domscan_whois_20261017_spec.rb`.

## Release follow-up (2026-10-18 UTC)

The parser release is now published. Commit
[`13f075d14ca4c7717154ce39cc245defbb217a72`](https://github.com/estevecastells/whois-parser-next/commit/13f075d14ca4c7717154ce39cc245defbb217a72)
was pushed and tagged `v0.4.1`; its [trusted release workflow](https://github.com/estevecastells/whois-parser-next/actions/runs/39091306093)
succeeded. The [Ruby 3.2, 3.3, 3.4, and 4.0.7 CI matrix](https://github.com/estevecastells/whois-parser-next/actions/runs/39091180829)
passed. RubyGems reports SHA-256
`0575c7f00d0a5bd6617191d4c8d3d00629483650ad4a8d9bd2cda8dbf22cb867` for
[`whois-parser-next` 0.4.1](https://rubygems.org/gems/whois-parser-next/versions/0.4.1);
a clean install also passed the `require "whois-parser"` check and the
registered/available fixture smoke checks.

The downstream DomScan change pins parser 0.4.1 without changing transitive
lockfile versions and includes availability and transport-classification
corrections. A review found that `WhoIsProxyTransport.target_throttled?` could
match the unanchored phrase `too many queries` in general registry policy text,
misclassifying otherwise valid registered or absent responses as
`rate_limited`. The correction recognizes explicit rate-response lines and
continues to recognize the `.lu` `%% Maximum query rate reached` response.
This means the earlier `.io` HTTP 429 labeled `whois_rate_limited` may have
been a local false classification; no further `.io` probes had been made at
the time of this first follow-up. The DomScan deployment was then pending
final tests and build.

Before deployment, a public sample matrix covered 20 checks across 10
suffixes. Registered and generated-absent checks for `.com`, `.si`, `.ai`,
`.net`, `.app`, `.info`, `.de`, `.dev`, and `.org` produced authoritative RDAP
results for all 18 checks. Both `.shop` checks (`get.shop` and a generated
absent name) remained `unknown` at the source-classification step. A separate
single-attempt `.shop` diagnostic, with an eight-second timeout, received
target HTTP 200 through the existing proxy in 1,229 ms but did not establish a
classification or a `.shop` fix. These are public sample checks, not a
traffic-weighted measure. The 99% live-accuracy target remains unverified, and
deployment had not been verified when this first follow-up was written.

### Root-zone denominator check (2026-10-18 UTC)

To add root-zone context to the 455 observed final-label buckets, I compared
the frozen usage aggregate with IANA's TLD list snapshot, version `2026101700`
(last updated `2026-10-17 07:07:01 UTC`). The snapshot is preserved at
[`data/domscan-whois-iana-tlds-2026-10-17.txt`](data/domscan-whois-iana-tlds-2026-10-17.txt)
with SHA-256
`992903eab7913a4a4f629e4a03906d174efaf44c43a6374bec3d4e2113f89b8c`.
An exact lowercase final-label comparison finds 139 labels absent from the
root list. Their buckets account for 327 of the 24,718 request items (1.32%).
These items have no corresponding delegated root-zone namespace at that
final label in the snapshot; they are not available-domain results. The
approved denominator for the 99% target is valid delegated registry-domain
requests; undelegated requests are tracked separately. The accuracy target
remains unverified.

### Normalized denominator and deployment update (2026-10-18 UTC)

A separate on-host normalization of the frozen request cohort used IDNA,
bulk expansion, and the ICANN Public Suffix List to identify exact
registry-domain requests across 342 namespaces. It classified 25,576 input
items as 823 invalid-format items, 327 undelegated requests, 721 non-registry
apexes, and 23,705 eligible exact registry-domain request items. These
normalized counts use a broader input population than the original ASCII
usage snapshot of 24,718 syntactically valid-looking WHOIS endpoint items in
455 final-label buckets; they do not replace or alter its CSV. The 23,705
items define the approved denominator, not a measured success rate, and no
99% accuracy claim follows from the normalization.

DomScan commit `253393bd` was deployed successfully. A production relay sample
then checked registered `nic.io` and a generated absent `.io` name; both
returned HTTP 200 with correct classifications in under one second. This
confirms that the earlier `.io` HTTP 429 marked `whois_rate_limited` was a
local false classification of response terms, not evidence of a registry
rate limit. A later DomScan change removed generic absence inference in
`ea3457b`; the latest pushed commit,
`bfa39c0eca10fdd27e8b8be98393da142ac8ff35`, adds a shared classifier for
profile responses and two regression tests. Its full suite passed 14,570
examples with 88 existing skips, and the build passed. Deployment workflow
39092623115 was still running at that point; the later deployment status is
recorded below. The safe, paced production pair probe had started and had no
results yet at that point.

### Latest staged follow-up (2026-10-18 UTC)

Deployment workflow 39092623115 has now succeeded. The active DomScan build
is commit `bfa39c0eca10fdd27e8b8be98393da142ac8ff35`; relay health reports the
same commit and parser 0.4.1. The blue environment is active and green is
inactive, and the DomScan `main` and `develop` branches are fast-forward
synced. A registered `.lu` query and a generated absent-name query both
passed through the WHOIS source: the first returned `registered=true` and
`available=false`, and the second returned `registered=false` and
`available=true`. Each completed in under 0.3 seconds.

At that stage, the strict registered/absent pair run was checking roughly 40
namespaces representing about 90% of request volume. That is run progress,
not a success rate; no final percentage was frozen and the 99% accuracy target
was not claimed. The positive `.shop` RDAP check passed, while the negative
check remains unknown. A bounded normal-relay diagnostic for `.shop` received
a target HTTP 429 after 755 ms with JSON `errorCode: 429`. Probing that host
stopped; the audit resumed on other namespaces while excluding every IANA
root whose RDAP mapping is `rdap.gmoregistry.net`.

The production check also exposed a proxy-first RDAP path that could bypass
the host budget. At that stage, a local correction acquired the budget and
recorded upstream HTTP 403/429 responses; its 54 focused tests passed, but it
had not been deployed. The earlier full suite passed 14,572 examples with 88
existing skips before those edits; the corresponding build was still in
progress. Subsequent exact-tree validation and deployment state are recorded
below.

Separately, a generated absent `.microsoft` name was reported as
`available=true`, despite Microsoft's policy limiting registration to
Microsoft and its affiliates. Application work is extending the existing
closed-registry eligibility rule for `.apple` to `.microsoft`, `.google`, and
`.dhl`. The official policies limit `.Microsoft` registration to Microsoft
and its affiliates ([policy, p. 3](https://nic.microsoft/PDF/RegistrationPolicy/MicrosoftTLDregistrationpolicyMicrosoftTLD.pdf#page=3)),
limit `.google` registration to Google and its affiliates
([Google Registry policy](https://www.registry.google/policies/registration/google/)),
and identify only the registry as eligible for `.dhl`
([DHL eligibility criteria](https://www.dhl.com/de-en/home/nic/registration-policy-nic/attachment-3-nic.html)).
At that stage, these application changes and focused tests were in progress
and had not been deployed. No 99% live-accuracy result is established by
these policy checks.

The privacy-safe registry-demand aggregate for the 342 normalized namespaces,
its frozen SQL, and the normalization script are available in the
[demand CSV](data/domscan-whois-registry-demand-2026-10-17.csv),
[query](../../scripts/domscan_whois_registry_demand_20261017.sql), and
[on-host normalizer](../../scripts/normalize_domscan_registry_demand.mjs). The
[CSV builder](../../scripts/build_domscan_registry_demand_csv.rb) consumes
only privacy-safe namespace-aggregate JSONL. These artifacts document demand
and denominator preparation; they are not a result table for the ongoing
production pair run.

### Current validation and deployment stage (2026-10-18 UTC)

The parser-only full suite now passes 7,018 examples with 0 failures. The
evidence audit passes 5 examples. The checked-in registry-demand CSV was
regenerated by the new Ruby builder from a privacy-safe aggregate JSONL; the
builder, query, and normalizer are linked above.

DomScan commit `c99a6089074cc26a66ccefc9d47dbdb83c526968` is pushed to `main`.
Its exact-tree full suite passed 14,578 examples with 88 existing skips, and
the build passed. Deployment workflow 39093748573 is still in progress, so
this commit is not yet confirmed deployed. It includes the proxy-first RDAP
backoff fix and extends the existing `.apple` closed-registry policy to
`.microsoft`, `.google`, and `.dhl`, with the policy note localized in all 15
languages.

Fresh public controls now cover `.my` and `.co.uk`. The `.my` pair for
`mynic.my` and a generated absent name both passed through WHOIS. The earlier
private `.my` control was stale and is not a confirmed parser bug. For
`.co.uk`, `nominet.co.uk` passed as registered through WHOIS and the paired
absent name passed through RDAP; this replaces the earlier cache-only
observation with a fresh registered/absent pair.

The current strict pair run is still active across roughly 95 namespaces.
That is in-progress workload only, not a completed-coverage count or success
rate. No interim coverage percentage is reported, all-namespace validation
has not been claimed, and the 99% target remains unverified.

### Parser 0.4.2 candidate and latest deployment stage (2026-10-18 UTC)

The DomScan deployment workflow for commit
`c99a6089074cc26a66ccefc9d47dbdb83c526968` has since succeeded (workflow
39093748573). The separate registered/absent production pair run continues
across roughly 140 namespaces. This is still in-progress work; no percentage
has been frozen, and it does not establish the 99% target.

The parser worktree contains a local 0.4.2 candidate for two response-shape
cases. For `.ma`, it accepts the `active https://icann.org/epp#active` status
as registered only with exactly one valid `.ma` domain name and no
contradictory absence marker. Registre.ma documents Active as registered,
declared in DNS and WHOIS; IANA lists `whois.registre.ma` as the official
WHOIS host ([status definitions](https://www.registre.ma/language/en/domain-name/e-statuts),
[IANA .ma record](https://www.iana.org/domains/root/db/ma.html)). An on-host
public technical response contained the domain name, active status, and
creation, update, and expiry fields; personal response data was not copied.
The `.sh` change accepts an exact `Domain not found.` response as absence
while retaining `NOT FOUND`; partial, repeated, mixed, or error responses
remain unknown or unavailable. IANA lists `whois.nic.sh` as the official host
([IANA .sh record](https://www.iana.org/domains/root/db/sh.html)). The
generated absent-name response began with the exact marker and ordinary
service terms, not a rate-limit message. No raw response text was saved.

The focused parser checks for these cases pass 40 examples. The parser full
suite passes 7,024 examples with 0 failures on Ruby 3.2.2 and 3.4.5; the
package smoke check also passes on both versions. The supported-Ruby CI matrix
for 0.4.2 is pending. These parser fixtures and samples establish neither
broad live coverage nor a traffic-weighted accuracy rate; the 99% target
remains unverified.
