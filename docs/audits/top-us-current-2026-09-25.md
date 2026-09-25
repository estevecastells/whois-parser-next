# Current `.top` and `.us` WHOIS evidence

Date: 2026-09-25

## Scope and rank labels

This is a bounded follow-up to the 2026-09-19 parser audits, not a replacement
for their source tables. In the DNIB Q2 2026 top-overall list, `.top` is rank 9.
In the ICANN DNS Magnitude snapshot dated 2026-09-12, `.top` is source rank 103
and `.us` is source rank 24. The two rank systems are independent and must not
be interchanged.

The official IANA delegation records identify `whois.nic.top` and
`whois.nic.us` as their respective WHOIS servers ([`.top` delegation data](https://www.iana.org/domains/root/db/top.html),
[`.us` delegation data](https://www.iana.org/domains/root/db/us.html)). Probes
used only those endpoints, with per-query connection and total time bounds,
sequential requests, and a two-second pause between queries.

## Observed evidence

| TLD | Probe | Current response evidence | Classification in this package |
|---|---|---|---|
| `.top` | `google.top` | ICANN-shaped record with `Domain Name`, registry ID, registrar, EPP `Domain Status` lines, and name servers | Registered |
| `.top` | `codex-top-20260925-731604283.top` | Exact line: `The queried object does not exist: codex-top-20260925-731604283.top` | Available, only for this exact complete response line shape |
| `.us` | `google.us` | Record with matching `Domain Name` and six EPP `Domain Status` lines | Registered |
| `.us` | `codex-us-20260925-731604283.us` | `No Data Found`; registry disclaimer says failure to locate a record is not indicative of availability | Unknown, not available |

The `.top` parser reuses the ICANN record parser and adds only the observed
complete `.top` absence line. Similar-looking or malformed text stays unknown.
The `.us` parser requires both a `.us` `Domain Name` field and an EPP-format
`Domain Status` value to report registration. Its registry disclaimer
prevents no-record responses from being reported available, so `.us`
availability remains unresolved by these probes.

Fixtures under `spec/fixtures/responses/whois.nic.top/top/` and
`spec/fixtures/responses/whois.nic.us/us/` contain only classification-relevant
fields. The `.us` registered fixture omits contact information; the generated
`.top` absence sample uses a synthetic label. Denial, throttling, empty, and
malformed-marker cases are adversarial fixtures/spec inputs and are not
classified as domain outcomes.
