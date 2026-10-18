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

The 99% live-accuracy target is **not achieved or demonstrated** by these
data. Fixture pairs, host mappings, source labels, and this bounded replay do
not prove end-to-end success. The application/relay revision observed before
this work was `636bb42b2336e82ce1e5dd77c2b30cc4a090f86a` and used parser 0.4.0.
The 0.4.1 parser changes and application correction are local; no
package release or production deployment is recorded here.

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
