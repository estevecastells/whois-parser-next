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

## Scorecard

| Evidence state | Ranks 1-100 | Ranks 101-300 | Ranks 301-1000 | Total |
| --- | ---: | ---: | ---: | ---: |
| Registered and authoritative absence both reported | Not normalized | 64 | 111 | **175** |
| Registered response only | 1 | 4 | 21 | **26** |
| Authoritative absence only | 0 | 10 | 11 | **21** |
| Explicit unsupported response | 0 | 36 | 169 | **205** |
| WHOIS retired; RDAP-only notice | 0 | 1 | 6 | **7** |
| Unknown/unsafe, including reserved or restricted | 11 | 30 | 190 | **231** |
| Classification-only or no port-43 target | 6 | 55 | 192 | **253** |
| Top-100 summary label only (`Healthy`/`Fixed`) | 76 | 0 | 0 | **76** |
| Top-100 `Unsupported` label without row-level marker evidence | 6 | 0 | 0 | **6** |
| **Rows** | **100** | **200** | **700** | **1,000** |

The 175 paired rows are the strict count explicitly supported by row-level
evidence descriptions in the reports; ranks 1-100 are not included in that
number. The Top 100 report labels 76 rows `Healthy` or `Fixed`, but its table
does not expose per-row evidence pairs. Treating those labels as verified
registered-plus-absence coverage would overstate what can be reproduced from
that report. The six Top 100 `Unsupported` labels also lack the row-level
response details needed to count them as exact unsupported-marker evidence.
The current `.us` follow-up supersedes its earlier `Ambiguous` label: a
registered response is observed, while `No Data Found` remains unknown because
the registry says a missing record does not establish availability.

The 253 classification/non-port-43 rows include source-classification rows,
web-only mappings, and rows with no applicable standard WHOIS port-43 parser
target. They are grouped together here because the audit question is parser
coverage over this source list, not how many TLD strings are theoretically
delegated. No claim is made that web-only or unsupported adapters are effective
registration coverage.

This scorecard intentionally does not publish one effective-coverage
percentage. Parser presence, one-sided evidence, unsupported responses, and
successful parsing of both evidence states are different outcomes.

## Next 10 ranked evidence gaps

These are ordered by source rank. They are evidence-refresh or validation
opportunities, not ten promised parser changes. Blocked or restricted services
must remain unknown; none is a reason to infer availability.

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
| 104 | `.uz` | A registered response is reported for the mapped server; the row does not report an authoritative absence response. | Low-cost follow-up: capture an exact generated-name response and add a paired fixture/spec only if the registry response is authoritative. |
| 105 | `.sa` | A registered response is reported for the mapped server; the row does not report an authoritative absence response. | Same low-cost paired-evidence follow-up as `.uz`; do not infer absence from a non-record response. |

The list reflects the `f2c822c` parser snapshot and the earlier rank audit.
The later current-source follow-up described below supersedes several of these
items; it does not change the snapshot counts above.

## Cheap validation and reporting gaps

- Normalize the Top 100 row ledger to state explicitly whether each row has
  registered, authoritative-absence, unsupported, RDAP-only, or unknown
  evidence. Its current summary labels do not support the same count rules as
  the later rowwise reports.
- Add a machine-readable evidence-state column to the existing 301-1000
  planning/ownership data, or a companion ledger, and preserve evidence date
  and report/fixture reference. The package reports currently use different
  outcome schemas, so the aggregate requires a manual crosswalk.
- Keep registered-only and absence-only rows visible. They are not paired
  coverage, even if a parser file or legacy fixture exists.
- For rows with only an `Unavailable`, `Restricted`, or `Unresolved` label,
  record the exact observed marker or say explicitly that the response detail
  was not retained. Do not convert those labels into stronger availability or
  parser claims.

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

The evidence-state tallies above are a manual classification of the linked
rowwise reports under the rules in this document; they are not regenerated
from parser-file names or the static planning inventory.

## Post-snapshot follow-up

After the scorecard baseline, commit `a226471` added a conservative `.pk`
parser using current registered and exact explicit-availability evidence.
This does not make `.pk` effective coverage for the standard WHOIS client:
`whois` 6.0.3 still maps it to a legacy web adapter, and DomScan's separate
port-43 routing work is pending. The `.pk` row therefore remains in the
unknown/unresolved baseline tally above; parser-file presence is not counted.

The same later report established that IANA lists only Google Registry RDAP,
not WHOIS, for `.dev` and `.app`; `.es` port-43 is limited to registry-approved
IP addresses. Those clarify their baseline `Unavailable`/refusal labels but
do not create a WHOIS parser opportunity. See
[`top1000-es-pk-shop-dev-app-2026-09-25.md`](top1000-es-pk-shop-dev-app-2026-09-25.md)
for exact evidence and limits.

## Draft release note for maintainer consideration

**0.3.0 (unreleased, draft only)**

- Added current `.top` registered and authoritative-absence parsing; `.us`
  registration is parsed while non-authoritative `No Data Found` remains
  unknown.
- Hardened `.ch` so blocked, empty, and ambiguous responses remain unknown.
- Added explicit unavailable-only handling for observed unsupported responses
  from `.digital`, `.email`, `.live`, `.media`, `.network`, and `.services`.

This draft describes verified parser behavior on the current source branch; it
does not imply that a release has been created or published.
