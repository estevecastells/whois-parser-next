# Top-1,000 WHOIS evidence ledger methodology

Date: 2026-09-25

This note and the linked CSV preserve a bounded, reproducible subset of the
ICANN DNS Magnitude 2026-09-12 ranking. They do not establish parser or
effective coverage for all 1,000 ranks.

## Source and reproducibility

The pinned source is
[`icann-dns-magnitude-20260912-ranks-1-1000.csv`](data/icann-dns-magnitude-20260912-ranks-1-1000.csv).
The validator checks the exact ordered ranks 1–1,000 and SHA-256 digest
`6f1411e1323ed09683480b47314188c71c19d62979d2d7cc2894669b4dd9e681`,
calculated over `rank:tld\n` lines. The bounded ledger is generated with:

```sh
ruby scripts/build_top1000_evidence_ledger.rb
bundle exec rspec spec/audits/top1000_evidence_ledger_spec.rb
```

The output is
[`whois-parser-top1000-evidence-ledger-subset-2026-09-25.csv`](data/whois-parser-top1000-evidence-ledger-subset-2026-09-25.csv).
Its columns record source rank and status, evidence state and date, report
reference, fixture collection or exact fixture reference when reported,
whether fixture provenance is row-specific or report-collection scoped, a
short evidence note, and separate follow-up fields. A report collection is not
claimed to be an exact per-row fixture unless the source report says so.

## Audited counts

The reproducible subset has 264 unique rank rows: the 100 Top-100 rows, the
130 directly traceable rank-101+ report pairs, 31 rank-301+ package rows with
insufficient row-level detail, and three later paired follow-ups. The pinned
baseline pair split is:

| Scope | Direct row-pair observations |
| --- | ---: |
| Ranks 101–300 | 61 |
| Ranks 301–1000 | 69 |
| **Pinned report snapshot** | **130** |

The 69 rank-301+ rows split by planning package as package 1: 7, package 2: 0,
package 3: 1, package 4: 22, and package 5: 39. The package-3 pair is rank 729
(`.aw`). The earlier 111 count for ranks 301–1000 was tallied as package 1: 7,
package 3: 34, package 4: 31, and package 5: 39. The direct rowwise audit gives
7, 1, 22, and 39 respectively. Package 3's reduction is 31 generic `verified`
rows without pair detail plus two absence-only rows; package 4's reduction is
eight absence-only plus one RDAP-only row in the rowwise crosswalk. At ranks
101–300, the old count 64 exceeds the rowwise count 61 by three, but the old
tally has no row IDs to identify those observations. The word `verified` alone
is not normalized to a pair.

The Top-100 report provides only summary labels for most rows. Its 100 rows
remain split as 76 `Healthy`/`Fixed` summary-only, 6 `Unsupported`
summary-only, 6 classification-only, 11 unknown/unsafe, and 1 registered-only
follow-up row. None is inferred to be a pair from a summary label.

Three later pairs are kept in the CSV follow-up columns and excluded from the
pinned baseline total: rank 103 `.top`, rank 104 `.uz`, and rank 105 `.sa`.
Other later work, including `.pk`, `.ge`, `.dev`, and `.app`, is also outside
the baseline pair count and does not establish default-client effective
coverage.

## Retraction and limitations

The scorecard previously stated 175 paired rows (64 at ranks 101–300 and 111
at ranks 301–1000). That count is retracted: the published reports do not
provide a rowwise crosswalk that reproduces it. The hand-checked, directly
traceable row-pair count is 130, a difference of 45 from that earlier claim.
The aggregate rank-301+ discrepancy is attributable to the package-3 and
package-4 summary differences described above; the separate three-row
ranks-101–300 discrepancy remains unidentified because the earlier tally has
no row IDs. Other labels that remain ambiguous, unsafe, blocked, rate-limited,
or otherwise non-authoritative remain unknown; they are not promoted to
absence or pairs.

This is a source-report evidence count, not a count of parsers, supported
registries, default client routes, successful production requests, or
effective coverage. No effective-coverage percentage is asserted. The ledger
contains no new registry requests or customer data.
