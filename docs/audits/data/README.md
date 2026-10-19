# ICANN DNS Magnitude snapshot manifest

`icann-dns-magnitude-20260912-ranks-1-1000.csv` is the repository-owned,
machine-readable manifest for source ranks 1 through 1,000 in the ICANN DNS
Magnitude historical snapshot:

- Source: <https://magnitude.research.icann.org/historic/20260912.full.html>
- Snapshot date: 2026-09-12
- Generated date stated by the source: 2026-09-18
- Retrieved: 2026-09-19

The source page contains more than the manifest range. The CSV preserves the
source rank and label exactly for ranks 1 through 1,000 and records the source
row classification as `delegated`, `special-use`, or `undelegated`. For
undelegated rows, the source identifies the classification on the table row
while its display cell is empty; the manifest records that source
classification without inferring a different status.

The canonical SHA-256 is calculated over UTF-8 lines in source-rank order,
using `source_rank:tld\n` for each CSV row and excluding the header:

```
6f1411e1323ed09683480b47314188c71c19d62979d2d7cc2894669b4dd9e681
```

The first 300 rows retain the previously pinned digest:

```
3f30997fd02e9481a316f2eaee541143b16cb445198cbf35956f5ae1c5950b62
```

The manifest has no unresolved rank or label ambiguity. The audit spec
verifies contiguity, uniqueness, classifications, and both digests.

The static 301-1000 WHOIS inventory and five-package ownership plan lives in
[`whois-parser-top1000-planning.csv`](whois-parser-top1000-planning.csv). Its
server columns come from the locked `whois` 6.0.3 definitions, and its parser
columns come from the current parser tree. See the accompanying
[`whois-parser-top1000-work-packages-2026-09-19.md`](../whois-parser-top1000-work-packages-2026-09-19.md)
for state definitions and implementation boundaries.

The corrected, bounded report crosswalk is documented in the [evidence-ledger
methodology](../top1000-evidence-ledger-methodology-2026-09-25.md) and stored as
[`whois-parser-top1000-evidence-ledger-subset-2026-09-25.csv`](whois-parser-top1000-evidence-ledger-subset-2026-09-25.csv).
It reproduces 130 direct row-pair observations and 31 rows whose package
reports lack enough detail to normalize `verified` into a pair. It is not a
full 1,000-row ledger or effective-coverage claim. Regenerate and validate it
from the repository root with `ruby scripts/build_top1000_evidence_ledger.rb`
and `bundle exec rspec spec/audits/top1000_evidence_ledger_spec.rb`.

The complete 1,000-row rank/status ledger is stored as
[`whois-parser-top1000-rank-status-ledger-2026-09-25.csv`](whois-parser-top1000-rank-status-ledger-2026-09-25.csv).
Its unknown rows retain report provenance, while later observations remain in
separate follow-up columns. See the [full-ledger methodology](../top1000-rank-status-ledger-methodology-2026-09-25.md).
Regenerate and validate it with `ruby scripts/build_top1000_rank_status_ledger.rb`
and `bundle exec rspec spec/audits/top1000_rank_status_ledger_spec.rb`.

## DomScan WHOIS usage snapshot (2026-09-28)

The privacy-safe endpoint aggregate and first-class parser coverage ledger are
stored in `domscan-whois-usage-2026-09-28.csv` and
`domscan-whois-first-class-coverage-2026-09-28.csv`. The latter pins all 153
root labels with more than five request items (44,402 items total), the IANA
service-page fields, root-zone state, per-host parser classes, response-test
references, and outstanding client-route blockers. The API logs expire after
30 days, so these snapshots preserve the audit baseline and are not regenerated
from current logs.

The accompanying `domscan-whois-iana-services-2026-09-28.csv` stores the IANA
root database observations; `domscan-whois-iana-tlds-alpha-2026-09-28.txt`
pins root-zone membership version `2026092800`; and
`domscan-whois-parser-mapping-2026-09-28.csv` preserves the DomScan-observed
traditional WHOIS host/parser map. SHA-256 digests for all four source
snapshots are enforced by `scripts/audit_domscan_whois_coverage.rb`.

From the repository root, run the integrity audit, parser evidence gate, and
runtime-route gate with:

```sh
bundle exec ruby scripts/audit_domscan_whois_coverage.rb
bundle exec ruby scripts/audit_domscan_whois_coverage.rb --strict
bundle exec ruby scripts/audit_domscan_whois_coverage.rb --strict-runtime
bundle exec rspec spec/audits/domscan_whois_coverage_spec.rb
```

`--strict` fails while parser evidence or protocol resolution remains pending.
`--strict-runtime` also fails while the installed `whois` gem route needs an
IANA-host correction, an RDAP-only skip, or an explicit application override.
The manifest and gate describe the installed upstream `whois` route map in
this parser worktree. A separate DomScan route patch is locally verified, but
these files do not verify its integration here or claim that a gem release,
dependency pin, or production deployment has occurred.

## DomScan WHOIS usage snapshot (2026-10-17)

The privacy-safe, final-label usage aggregate, recorded-source split, and
on-host parser replay are stored in `domscan-whois-usage-2026-10-17.csv`,
`domscan-whois-sources-2026-10-17.csv`, and
`domscan-whois-replay-2026-10-17.csv`. Their SHA-256 digests are
`bbfc25a4d2c2a76871cba6a80604625f35ab119ce74855d941c081adc927c4`,
`1cfbfec7858c40188c287cbf4a222dc51b2cadacb9d5346f5d17953a86649e5f`, and
`a22267b3da6dba0816ec8615d5e309907d13fe34a06e8eac70ececfeefdb60cc`,
respectively. They summarize a frozen window from
`2026-09-18T02:30:00Z` inclusive to `2026-10-18T02:30:00Z` exclusive. The
usage CSV contains 24,718 domain-shaped request items across 455 final-label
buckets; it is not a unique-domain or eligible-domain count. The source split
independently groups single-domain HTTP 200 rows by the API's recorded source,
without applying the usage query's domain-shape filter. It is not an
authoritative-success count. The replay compares the API's stored outcome
with the installed parser 0.4.0 on bounded response previews. Some previews
are truncated. See the
[`2026-10-17 audit`](../domscan-whois-usage-2026-10-17.md) for methodology and
limits.

The frozen aggregate SQL files are
[`domscan_whois_usage_20261017.sql`](../../../scripts/domscan_whois_usage_20261017.sql),
[`domscan_whois_sources_20261017.sql`](../../../scripts/domscan_whois_sources_20261017.sql),
and [`domscan_whois_summary_20261017.sql`](../../../scripts/domscan_whois_summary_20261017.sql).
They query the same window while the source logs are retained.
[`replay_domscan_whois_on_host.rb`](../../../scripts/replay_domscan_whois_on_host.rb)
reads raw previews on the relay host, parses them in memory, and prints only
aggregate classes. Do not export or save raw response text. To replay from a
checkout readable by the `deploy` account, use the relay's installed bundle
and write only the aggregate CSV:

```sh
cd /path/to/whois-parser-next
sudo -u deploy env \
  BUNDLE_GEMFILE=/opt/whois-proxy/Gemfile \
  BUNDLE_PATH=/opt/whois-proxy/vendor/bundle \
  BUNDLE_FROZEN=true \
  /usr/bin/ruby -rbundler/setup scripts/replay_domscan_whois_on_host.rb \
  > /tmp/domscan-whois-replay-2026-10-17.csv
```

The replay ran against the installed parser 0.4.0. It is not a replay of the
local 0.4.1 changes and does not establish 99% live accuracy.

### Root-zone denominator context

[`domscan-whois-iana-tlds-2026-10-17.txt`](domscan-whois-iana-tlds-2026-10-17.txt)
is the frozen IANA TLD list retrieved from
[`data.iana.org/TLD/tlds-alpha-by-domain.txt`](https://data.iana.org/TLD/tlds-alpha-by-domain.txt).
It identifies version `2026101700`, last updated `2026-10-17 07:07:01 UTC`,
and has SHA-256
`992903eab7913a4a4f629e4a03906d174efaf44c43a6374bec3d4e2113f89b8c`.
Comparing the usage aggregate's lowercase final-label values exactly against
the snapshot after lowercasing its labels finds 139 of 455 labels absent,
covering 327 of 24,718 request items (1.32%). This is only a root-zone
membership comparison: those items are not WHOIS availability results and
cannot be classified as available. The approved denominator for the 99%
target is valid delegated registry-domain requests; undelegated requests are
tracked separately.

A separate on-host normalization of the frozen cohort used IDNA, bulk
expansion, and the ICANN Public Suffix List to classify 25,576 input items
across 342 namespaces:
823 invalid-format items, 327 undelegated requests, 721 non-registry apexes,
and 23,705 eligible exact registry-domain request items. This broader,
normalized input differs from the original ASCII usage CSV's 24,718
syntactically valid-looking endpoint items and does not replace that snapshot.
The eligible-item count defines the approved denominator; it is not a success
count or an accuracy result. See the [audit's current outcome](../domscan-whois-usage-2026-10-17.md#current-outcome-2026-10-19-utc)
for the latest weighted pair status.

### Registry-demand CSV builder

The 342-namespace table is
[`domscan-whois-registry-demand-2026-10-17.csv`](domscan-whois-registry-demand-2026-10-17.csv).
Its frozen on-host query is
[`domscan_whois_registry_demand_20261017.sql`](../../../scripts/domscan_whois_registry_demand_20261017.sql);
the on-host normalizer is
[`normalize_domscan_registry_demand.mjs`](../../../scripts/normalize_domscan_registry_demand.mjs).
Normalization used `tldts` 7.4.8 from DomScan's bundled dependency. The
normalized inputs stay on-host; the checked-in Ruby builder consumes only the
privacy-safe namespace-aggregate JSONL and writes the CSV:

```sh
ruby scripts/build_domscan_registry_demand_csv.rb \
  < /path/to/safe-registry-demand-aggregate.jsonl \
  > docs/audits/data/domscan-whois-registry-demand-2026-10-17.csv
```

[`build_domscan_registry_demand_csv.rb`](../../../scripts/build_domscan_registry_demand_csv.rb)
validates the aggregate fields and namespaces before writing. Do not pass
private domain-level input to the builder. The CSV's
`registered_control_available` field is only a historical-positive or public
override control flag; it is not a parser fixture-pair result or live coverage
proof. The CSV was regenerated from the safe aggregate and the evidence audit
passes 5 examples with:

```sh
bundle exec rspec spec/audits/domscan_whois_20261017_spec.rb
```

### Dated production pair-validation evidence (2026-10-18–19)

The canonical production-validation snapshot contains 355 namespace
observations: 342 usage namespaces from the frozen demand table and 13
zero-demand legacy roots. These pair checks were recorded on 2026-10-18 and
2026-10-19 UTC. Those observation dates do not extend or replace the frozen
usage window or the 23,705-item eligible denominator.

The final tally passes 296 of 342 usage namespaces, weighted as 23,472 of
23,705 eligible requests (99.0171%). Thirteen zero-demand legacy pairs also
passed outside the denominator. All 342 usage namespaces and 13 legacy roots
were attempted. Treat this as paired-source capability evidence for the
audited sample, not a historical accuracy or uptime measure; intermittent
`.ws` connection failures remain unknown. The audit's
[current outcome](../domscan-whois-usage-2026-10-17.md#current-outcome-2026-10-19-utc)
contains the interpretation and production build details.

The privacy-safe source JSONL is
[`domscan-whois-production-validation-2026-10-18.jsonl`](domscan-whois-production-validation-2026-10-18.jsonl).
Its top-level fields are limited to `namespace`, `requests` (pinned weight),
`checked_on`, `production_build`, `evidence_set`, and `checks`. Each check may
contain only `expected_registered`, `http`, `registered`, `available`, and
`source`; outcome fields may be booleans or null. It contains no customer
domain names or raw WHOIS responses. The generated
[`production-validation CSV`](domscan-whois-production-validation-2026-10-18.csv)
is reproducible from that JSONL with
[`build_domscan_whois_validation_csv.rb`](../../../scripts/build_domscan_whois_validation_csv.rb):

```sh
ruby scripts/build_domscan_whois_validation_csv.rb \
  < docs/audits/data/domscan-whois-production-validation-2026-10-18.jsonl \
  > docs/audits/data/domscan-whois-production-validation-2026-10-18.csv
```

A namespace contributes to a passing pair only after review against the
registry's official WHOIS or RDAP service, with both `source` labels recorded
as `whois` or `rdap` and both checks returning HTTP 200. The registered
example must be classified as registered and not available; the absence
example must be classified as unregistered with availability consistent with
registry policy. Cache or DNS-only results, unknown sources, denials, timeouts,
contradictory or malformed results, and unpaired checks are excluded from the
passing numerator. The [production validation spec](../../../spec/audits/domscan_whois_validation_20261018_spec.rb)
checks the output and these exclusion rules. See the [audit's current outcome](../domscan-whois-usage-2026-10-17.md#current-outcome-2026-10-19-utc)
for the latest weighted result; the frozen denominator and window remain as
documented above.

### Dated production pair-validation follow-up (2026-10-19)

The follow-up snapshot in
[`domscan-whois-production-validation-2026-10-19.jsonl`](domscan-whois-production-validation-2026-10-19.jsonl)
and its generated
[`CSV`](domscan-whois-production-validation-2026-10-19.csv) preserve the
dated namespace observations. The `.ga`, `.jo`, `.sx`, `.gt`, and `.com.gt`
v1/v2 registered/absent checks use production build
`cdc6fc3a59ec0a12d2f6c8e0ac6ebf226d5c4705`; all returned HTTP 200 from WHOIS.
The `.mw` pair remains from build `740c1e8db6952a9537d2dd842e0b5cebf660e7c8`;
on the current build its registered control passed but the absence result was
unknown, so intermittent `.mw` outcomes remain unknown. The new
[follow-up audit spec](../../../spec/audits/domscan_whois_validation_20261019_spec.rb)
rebuilds the CSV from the JSONL, verifies the 355-row observation set, and
checks the paired counts and frozen weights without changing the 2026-10-18
baseline snapshot.

The follow-up validates paired WHOIS/RDAP capability for 302 of 342
usage namespaces, representing 23,479 of 23,705 eligible weighted requests
(99.0466%). Thirteen zero-demand legacy namespaces also have verified pairs,
for 315 paired namespaces across 282 distinct root TLDs. The other 40 usage
namespaces, weighted at 226 request items, remain outside the paired numerator.
Intermittent `.mw` label timeouts and `.ws` connection failures remain unknown;
a passing pair is evidence for the checked examples, not a continuous-uptime
or historical-accuracy claim.

These results are follow-up checks against the frozen 30-day usage cohort from
`2026-09-18T02:30:00Z` inclusive to `2026-10-18T02:30:00Z` exclusive; they do
not extend that window. The approved denominator remains 23,705 eligible exact
registry-domain requests. The 327 requests whose final labels were
undelegated remain excluded from that denominator; they are not WHOIS
availability results. Keep the pinned baseline CSV and the earlier snapshot
unchanged.
