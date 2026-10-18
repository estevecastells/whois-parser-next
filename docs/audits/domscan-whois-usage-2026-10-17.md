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
deployment status is summarized in the current outcome section below.

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
must not be run by exporting raw WHOIS previews. At the original 0.4.1 audit
checkpoint, the full suite passed 7,016 examples with 0 failures and package
smoke passed on Ruby 3.2 and 3.4.5; the later 0.4.3 validation is summarized
below. Snapshot integrity is checked by
`spec/audits/domscan_whois_20261017_spec.rb`.

## Current outcome (2026-10-18 UTC)

The pre-managed-proxy production baseline has passing registered/absent pairs
for 271 namespaces. Using the pinned registry-demand CSV weights, those pairs
represent 22,912 of 23,705 eligible request items, or 96.6547%. This is below
the 99% target and is not the final post-change result. The earlier 22,911
numerator undercounted `.org.au` by one item: the pinned CSV assigns that
suffix a weight of three, while the earlier control tally counted two.

Thirteen additional public registered/absent pairs passed for zero-demand
legacy roots. They are outside the frozen demand denominator and are not
included in the percentage. The `.shop` slice has 519 eligible request items
(2.19% of the denominator) and remains outside the passing numerator; it is
only part of the 793-item baseline remainder.

The owned-primary `.shop` check returned HTTP 429, after which direct probes
to GMO-mapped hosts stopped. GMO has since approved managed-proxy usage. The
planned retry is one attempt through that proxy, with no
alternate host or egress change if denied. Its result, the final achieved
count, and the final deployed DomScan SHA await live verification. No 99%
result is claimed.

## Parser release and application evidence

Parser 0.4.3 is published from commit
[`e7b4e639452c815d1ea590371b154c6bcb24da5f`](https://github.com/estevecastells/whois-parser-next/commit/e7b4e639452c815d1ea590371b154c6bcb24da5f),
tagged `v0.4.3`. The [trusted release workflow](https://github.com/estevecastells/whois-parser-next/actions/runs/39172562630)
and the [final-commit Ruby matrix](https://github.com/estevecastells/whois-parser-next/actions/runs/39172449347)
passed. RubyGems reports SHA-256
`db33c01e68f0be490ad3501b6d1034e0a5c1dee751aed67c332f1a707fad63be` for the
[published gem](https://rubygems.org/gems/whois-parser-next/versions/0.4.3).
The 119,808-byte package contains 633 files and no native extensions. The
full parser suite passed 7,040 examples on Ruby 3.2.2 and 3.4.5; package
smoke passed on both. In an isolated empty gem home, all 576 packaged parser
files loaded and five new registered/absent fixture pairs passed.

Version 0.4.3 covers the `.ma` and `.sh` response variants, current synthetic
CoCCA status controls for `.ki`, `.bi`, and `.ci`, the `.ax` dotted-field
format, and the `.ls` WHOIS shape. These parser tests do not by themselves
prove the downstream request-weighted result above.

The last confirmed DomScan deployment before the managed-proxy update was
commit `ee6d0a966aa0f621dc6946a67bb9917c5862078d` (workflow 39170927600); its
full suite passed 15,439 tests with 88 skips and its build passed. Fresh
registered/absent `.ma` and `.sh` pairs passed through the v2 production
path. The final deployment SHA for the managed-proxy change remains pending
live verification.

## Denominator and evidence

The original ASCII suffix aggregate contains 24,718 syntactically
valid-looking WHOIS endpoint items across 455 final-label buckets. It is not
the eligible-domain denominator. On-host normalization classified 25,576
items: 823 invalid-format, 327 undelegated, 721 non-registry apex, and 23,705
eligible exact registry-domain requests. An exact comparison with the frozen
IANA root-zone list found 139 absent final labels covering 327 items; these
are not available-domain results. The frozen
[IANA list](data/domscan-whois-iana-tlds-2026-10-17.txt), version `2026101700`,
has SHA-256 `992903eab7913a4a4f629e4a03906d174efaf44c43a6374bec3d4e2113f89b8c`.

The pinned denominator and builder are documented in the [data README](data/README.md)
and [registry-demand CSV](data/domscan-whois-registry-demand-2026-10-17.csv);
the [CSV builder](../../scripts/build_domscan_registry_demand_csv.rb) consumes
only privacy-safe aggregate JSONL. Original suffix, source, and bounded
replay evidence remains in the [usage CSV](data/domscan-whois-usage-2026-10-17.csv),
[source CSV](data/domscan-whois-sources-2026-10-17.csv),
[replay CSV](data/domscan-whois-replay-2026-10-17.csv), and their frozen
[usage query](../../scripts/domscan_whois_usage_20261017.sql),
[source query](../../scripts/domscan_whois_sources_20261017.sql), and
[request summary query](../../scripts/domscan_whois_summary_20261017.sql).
The [on-host replay script](../../scripts/replay_domscan_whois_on_host.rb)
prints aggregate classes only; it must not be run by exporting raw previews.
API source labels and the 0.4.0 preview replay are historical context, not
current live-accuracy measurements. Raw WHOIS text and customer domains are
not included.
