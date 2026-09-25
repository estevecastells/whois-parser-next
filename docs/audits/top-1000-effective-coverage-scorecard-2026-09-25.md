# ICANN DNS Magnitude top-1,000 WHOIS evidence scorecard

Date: 2026-09-25

Parser-tree baseline: `f2c822cc498e2d319cd15349716d3a4f0c98d599`.

## Scope and evidence boundary

The ranking basis is the repository-pinned ICANN DNS Magnitude snapshot dated
2026-09-12 (generated 2026-09-18), ranks 1 through 1,000. These are observed
TLD strings, not registrable domains, a list of 1,000 functioning WHOIS
services, or a registration/availability guarantee. The canonical snapshot
digest is
`6f1411e1323ed09683480b47314188c71c19d62979d2d7cc2894669b4dd9e681`.

Most response observations are point-in-time port-43 checks dated 2026-09-19.
The `.top`/`.us` follow-up is dated 2026-09-25. The `.ch` denial fixture and
safety regression are present in the current source revision, `f2c822c`.
Endpoint access and response formats can change; this is an evidence inventory,
not a live-availability score.

The row evidence comes from the [Top 100 report](top-100-tlds-2026-09-19.md),
the [ranges 101-125](top-101-125-tlds-2026-09-19.md),
[126-150](top-126-150-tlds-2026-09-19.md),
[151-175](topdomains-151-175-2026-09-19.md),
[176-200](top-176-200-tlds-2026-09-19.md),
[201-225](top-201-225-tlds-2026-09-19.md),
[226-250](topdomains-226-250-2026-09-19.md),
[251-275](topdomains-251-275-2026-09-19.md),
[276-300](topdomains-276-300-2026-09-19.md), the five
[301-1000 package reports](whois-parser-top1000-work-packages-2026-09-19.md),
and the [current `.top`/`.us` follow-up](top-us-current-2026-09-25.md).
The static planning CSV is used for rank, host, and initial inventory context
only. Its `parser_present_unverified` value is not treated as effective
coverage.

## Classification rules

- **Paired:** the rowwise report says both a current record-shaped registered
  response and an authoritative absence response were observed and parse.
- **Registered only:** a registered response is reported, but no authoritative
  absence response is reported. A registry disclaimer can keep a no-data reply
  unknown even when its wording resembles an absence marker.
- **Absence only:** an authoritative absence marker is reported, but a current
  registered response is not. A legacy fixture does not substitute for a
  current registered probe in this scorecard.
- **Explicit unsupported:** the report records a specific unsupported-registry
  response and the parser preserves it as unavailable, not registered or
  available.
- **RDAP-only:** the report records a WHOIS-retirement response directing
  clients to RDAP. It is not WHOIS registration or absence coverage.
- **Unknown/unsafe:** empty, timeout, refusal, denial, reserved, restricted,
  prohibited, malformed, ambiguous, or otherwise non-authoritative evidence.
- **Classification/non-port-43:** source-classification rows, web-only rows,
  and rows with no port-43 target. These are not parser targets for this audit.
- **Summary-only:** the Top 100 report's `Healthy`, `Fixed`, or `Unsupported`
  label does not state row-by-row whether both registered and authoritative
  absence cases were verified. These rows are deliberately not promoted into
  paired or explicit-unsupported counts.

## Corrected rowwise pair reconciliation

Correction dated 2026-09-25: the previously published count of 175 paired
rows is retracted. The reports do not provide a rowwise crosswalk that
reproduces that total. The bounded hand-audited ledger and validator below
reproduce 130 directly traceable pair observations in the pinned snapshot:

| Rank range | Previously published pairs | Directly traceable report pairs |
| --- | ---: | ---: |
| 101–300 | 64 | 61 |
| 301–1000 | 111 | 69 |
| **Total** | **175 (retracted)** | **130** |

The old tally did not enumerate its rows, so its row identities cannot be
reconstructed. At the aggregate level, the old ranks 301–1000 total was
7 + 34 + 31 + 39 = 111 across packages 1, 3, 4, and 5. The rowwise audit
reproduces 7 + 1 + 22 + 39 = 69: package 3 falls by 33 because 31 generic
`verified` rows and two absence-only rows do not document pairs; package 4
falls by 9 because its rowwise crosswalk has eight absence-only and one
RDAP-only row among outcomes included in the old summary. The ranks 101–300
difference of three (64 previously stated, 61
rowwise reproduced) has no identified rank IDs and remains unresolved. These
count differences explain the 45-row aggregate change, but do not supply a
row-by-row reconciliation. Do not treat either tally as effective parser
coverage.

The 69 directly traceable rank-301–1000 observations split by the published
planning packages as follows:

| Planning package | Directly traceable pairs |
| --- | ---: |
| Package 1 | 7 |
| Package 2 | 0 |
| Package 3 | 1 (`.aw`, rank 729) |
| Package 4 | 22 |
| Package 5 | 39 |
| **Total** | **69** |

The same package reports contain 31 package-3 rows with a generic `verified`
outcome but no rowwise detail naming both registered and authoritative
absence evidence. These remain `report_detail_insufficient`, not pairs. Other
ambiguous, unsafe, blocked, throttled, or non-authoritative rows remain
unknown; this correction does not promote them to absence or registration.

The Top-100 table's summary labels are separately retained without pair
inference:

| Top-100 evidence state | Rows |
| --- | ---: |
| `Healthy`/`Fixed` summary only | 76 |
| `Unsupported` summary only | 6 |
| Classification-only | 6 |
| Unknown/unsafe | 11 |
| Registered-only current `.us` follow-up | 1 |
| **Rows** | **100** |

The reproducible CSV contains these 100 Top-100 rows, the 130 direct rank-101+
pairs, the 31 detail-insufficient rows, and three additional post-snapshot
follow-up ranks: `.top` (103), `.uz` (104), and `.sa` (105). A fourth dated
point-in-time pair observation for `.cam` (rank 315) supplements one of the
already included detail-insufficient rows. Its response is represented only
by hashes because no redistributable exact fixture was verified. All four
observations use follow-up fields and stay outside the pinned 130-pair
baseline. The CSV is a bounded evidence subset, not a fully normalized
1,000-row state ledger. See the [methodology and validation rules](top1000-evidence-ledger-methodology-2026-09-25.md)
and [machine-readable subset](data/whois-parser-top1000-evidence-ledger-subset-2026-09-25.csv).

No effective-coverage percentage is asserted. A report pair is not by itself
proof of a supported parser, the default client's route, or an effective
application integration.

## Snapshot-time evidence gaps and follow-ups

These items describe the pinned 2026-09-19 audit snapshot and its subsequent
bounded follow-ups. They are evidence-refresh or validation opportunities,
not promised parser changes. Blocked or restricted services remain unknown.

| Rank | TLD | Current evidence | Safest next action |
| ---: | --- | --- | --- |
| 24 | `.us` | Registered record observed. The generated-name reply is `No Data Found`, but the registry disclaimer says this does not indicate availability. | Keep registration and absence separate; do not add an available marker without authoritative registry evidence. |
| 33 | `.ch` | Current sanitized port-43 denial: `Requests of this client are not permitted.` The current parser regression keeps denial, empty, and ambiguous responses unknown. | No parser expansion while access is denied. Revisit only after the official service supplies permitted, classifiable responses. |
| 43 | `.dev` | The Top 100 report says `Unavailable`; it does not include row-level response evidence. | Capture or cite the exact official response before deciding whether the state is unsupported, retired, or unknown. |
| 47 | `.app` | The Top 100 report says `Unavailable`; it does not include row-level response evidence. | Same evidence gap as `.dev`; do not infer unsupported or RDAP-only from the label. |
| 52 | `.es` | The 2026-09-19 audit recorded a transient port-43 refusal. | Recheck with a bounded, paced official query; keep the outcome unknown until a current record and authoritative absence are observed. |
| 59 | `.vn` | The Top 100 report labels the result restricted. | Verify current access policy/source semantics; do not work around the restriction or classify it as absence. |
| 68 | `.za` | The Top 100 report labels the result restricted. | Confirm the applicable registry scope and access policy before any parser work. |
| 72 | `.gr` | The Top 100 report labels the result restricted. | Confirm official source semantics; restricted output remains unknown, not absent. |
| 104 | `.uz` | The pinned row reports registration only; a 2026-09-25 follow-up adds registered and exact generated-name no-entry evidence. | Keep the later pair separately dated; do not backfill it into the pinned count. |
| 105 | `.sa` | The pinned row reports registration only; a 2026-09-25 follow-up adds registered and exact generated-name no-match evidence. | Keep the later pair separately dated; do not backfill it into the pinned count. |

The list reflects the `f2c822c` parser snapshot and the earlier rank audit.
The later current-source follow-up described below supersedes several of these
items; it does not change the snapshot counts above.

## Remaining reporting limits

- The machine-readable CSV is a bounded evidence subset, not a normalized
  ledger for all 1,000 ranks. Rows not in the subset must be read from their
  linked reports; no aggregate state is inferred for them here.
- The package reports use different outcome schemas. A generic `verified`
  outcome without row-level evidence detail remains insufficient to establish
  a pair.
- Keep registered-only and absence-only observations distinct. A parser file
  or legacy fixture does not substitute for two current evidence cases.
- `Unavailable`, `Restricted`, `Unresolved`, denial, throttle, timeout, and
  ambiguous results do not establish availability. Keep them unknown unless
  exact authoritative evidence supports a narrower classification.

## Reproducing the rank-manifest check

From the repository root, this verifies rank contiguity and the pinned source
digest used by this scorecard:

```sh
ruby -rcsv -rdigest -e 'p="docs/audits/data/icann-dns-magnitude-20260912-ranks-1-1000.csv"; rows=CSV.table(p); ranks=rows.map { |r| r[:source_rank] }; abort "rank mismatch" unless ranks == (1..1000).to_a; canonical=rows.map { |r| "#{r[:source_rank]}:#{r[:tld]}\n" }.join; puts "rows=#{rows.length} ranks=#{ranks.first}-#{ranks.last} sha256=#{Digest::SHA256.hexdigest(canonical)}"'
```

Expected output:

```text
rows=1000 ranks=1-1000 sha256=6f1411e1323ed09683480b47314188c71c19d62979d2d7cc2894669b4dd9e681
```

The corrected pair, summary-only, and detail-insufficient counts are
reproduced by `scripts/build_top1000_evidence_ledger.rb` and checked by
`spec/audits/top1000_evidence_ledger_spec.rb`. The script validates the source
rank digest and does not infer pairs from parser-file names or the static
`parser_present_unverified` planning field. The accompanying methodology
documents the hand review and limits.

## Post-snapshot follow-up

After the scorecard baseline, commit `a226471` added a conservative `.pk`
parser using current registered and exact explicit-availability evidence.
This does not make `.pk` effective coverage for the standard WHOIS client:
`whois` 6.0.3 still maps it to a legacy web adapter, and DomScan's separate
port-43 routing work is pending. This does not make `.pk` a pair in the
directly traceable subset; parser-file presence is not counted.

The 2026-09-25 follow-ups record separate row-pair observations for `.top`,
`.uz`, `.sa`, and `.cam`. The `.cam` result is a dated, row-specific
point-in-time observation with hashes only; its response body is not retained,
so it is not an independently reproducible parser fixture or proof of
effective coverage. These observations are listed in the subset's follow-up
columns and are deliberately excluded from its 130-pair pinned baseline. See
the [rank-315 `.cam` follow-up](top1000-rank315-cam-followup-2026-09-25.md).

The same later report established that IANA lists only Google Registry RDAP,
not WHOIS, for `.dev` and `.app`; `.es` port-43 is limited to registry-approved
IP addresses. Those clarify their baseline `Unavailable`/refusal labels but
do not create a WHOIS parser opportunity. See
[`top1000-es-pk-shop-dev-app-2026-09-25.md`](top1000-es-pk-shop-dev-app-2026-09-25.md)
for exact evidence and limits.

## Release note context for 0.3.2

The 0.3.2 changelog carries this scorecard's dated correction: the unsupported
175-pair total is retracted, and the bounded rowwise crosswalk reproduces 130
directly traceable report-pair observations. The 31 detail-insufficient rows
and three post-snapshot pairs remain separately identified. These are audit
evidence counts, not effective WHOIS coverage.

The 0.3.2 parser additions for `.mu`, `.africa`, and `.sr` are host-keyed.
They do not change the default `whois` client's routing, establish effective
application coverage, or change the scorecard's row totals. The
[changelog](../../CHANGELOG.md) records the release metadata; check the
[RubyGems project page](https://rubygems.org/gems/whois-parser-next) for the
publication status of version 0.3.2.
