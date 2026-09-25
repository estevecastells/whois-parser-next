# Top-1,000 WHOIS rank/status ledger methodology

Date: 2026-09-25

The generated [rank/status ledger](data/whois-parser-top1000-rank-status-ledger-2026-09-25.csv)
contains one row for every source rank in the pinned ICANN DNS Magnitude
2026-09-12 snapshot. It records report evidence and its provenance. It is not
a count of parser files, default-client routes, or effective application
coverage.

## Source and regeneration

The rank and TLD sequence comes from
[`icann-dns-magnitude-20260912-ranks-1-1000.csv`](data/icann-dns-magnitude-20260912-ranks-1-1000.csv),
validated against SHA-256
`6f1411e1323ed09683480b47314188c71c19d62979d2d7cc2894669b4dd9e681`.
Statuses and report references are derived from the existing audit reports
through `scripts/build_top1000_evidence_ledger.rb`. No parser-file inventory
or parser-presence field is used to assign an evidence state.

Regenerate and validate the artifact with:

```sh
ruby scripts/build_top1000_rank_status_ledger.rb
bundle exec rspec spec/audits/top1000_rank_status_ledger_spec.rb
```

Every row retains the source rank, TLD, source classification, report path,
fixture reference and scope when available, and the report's evidence note.
An unknown result still points to the report that recorded the ambiguous,
blocked, restricted, unavailable, summary-only, or otherwise unverified
outcome. Fixture collection scope is not represented as a dedicated fixture
for each TLD.

## Evidence state rules

`paired` means the audit row's prose identifies both a registered response
and an authoritative absence response. `registered_only` and `absence_only`
retain one-sided observations. `explicit_unsupported` means the referenced
rank/TLD-specific detail row reports an exact unsupported-TLD or registry
denial response. Its fixture reference is only a report-level collection
reference; the ledger does not claim there is a retained, replayable fixture
for each TLD, nor does that directory independently verify the report claim.
A generic `Unsupported` summary, a missing port-43 server, and a report that
only says a TLD has no WHOIS server do not qualify. `rdap_only` records an
explicit WHOIS retirement or RDAP-only result.

`classification_only` is restricted to manifest rows whose source status is
`undelegated` or `special-use`, plus `.arpa`, whose report explicitly
classifies it as infrastructure. A web-only observation, absent adapter, or
missing server mapping does not establish a source classification and remains
`unknown`.

`unknown` is the default whenever a row does not establish one of those
states. This includes Top-100 labels such as `Healthy`, `Fixed`, and
`Unsupported`, package rows that only say `verified`, plus denied, restricted,
throttled, timed-out, empty, ambiguous, or unresolved outcomes. Their source
labels and report provenance remain in the row; they are not upgraded into
parser support, registration, or absence. This also includes delegated rows
whose prior report outcome was based only on web-only access, no parser
adapter, or no locked WHOIS mapping.

Pinned baseline counts across all 1,000 rows are: 130 paired, 27
registered-only, 32 absence-only, 205 explicit unsupported, 7 RDAP-only, 157
classification-only, and 442 unknown. These counts do not include the 19
separate current follow-ups below.

The baseline contains 130 rank-101+ paired observations. The generator and
spec pin the rank/TLD set as well as the count. Later observations are stored
in `follow_up_*` columns so they cannot increase or rewrite that baseline.
The current follow-up entries are a selected, non-exhaustive set, not a full
reconciliation of every newer report. They include `.us`, `.top`, `.uz`,
`.sa`, `.ge`, `.hn`, `.ma`, `.pk`, `.dev`, `.app`, `.shop`, `.mu`, `.africa`,
`.sr`, and `.cam`, along with unresolved or access-limited checks for `.ch`,
`.es`, `.iq`, and `.ga`. Rank 315 `.cam` is labeled
`observed_pair_unreplayable`: registered and authoritative-absence outcomes
were observed on 2026-09-25, but terms prevented retaining exact response
fixtures. Its follow-up fixture reference is blank, and the hashes in its
report cannot replay or independently validate parsing. Follow-up notes
preserve default-route limits where the report identifies them.

No effective-coverage percentage is asserted. A parser response pair alone
does not prove that the default client selects that endpoint or that an
application integrates it.
