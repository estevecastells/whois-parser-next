# Changelog

This project uses [Semantic Versioning 2.0.0](http://semver.org/).

#### Release 0.3.1 (2026-09-25)

- ADDED: Added paired registered and exact authoritative-absence parsing for
  `.ma` and `.hn`. Empty and denied replies remain unavailable, rate limits
  remain throttled, and conflicting or incomplete replies remain unknown.
- FIXED: Corrected `.pk` parsing for PKNIC's observed indented response
  fields. Registration and availability still require explicit markers;
  incomplete or conflicting replies remain unknown, and denied or throttled
  replies remain non-positive.
- EVIDENCE: [Current `.ma` and `.hn` responses](docs/audits/top-126-150-tlds-2026-09-19.md)
  and [production-shaped `.pk` responses](docs/audits/top1000-es-pk-shop-dev-app-2026-09-25.md).


#### Release 0.3.0 (2026-09-25)

- ADDED: Added evidence-backed `.top` registration and exact authoritative
  absence parsing. `.us` now recognizes registration evidence while keeping
  the registry's non-authoritative `No Data Found` response unknown.
- ADDED: Added conservative `.pk` parsing for exact PKNIC registered and
  explicitly available responses. The standard `whois` 6.0.3 mapping selects
  a legacy web adapter, and `Whois::Client.new(host: ...)` cannot override
  that adapter. DomScan needs a fixed-host port-43 route through its managed
  relay before `.pk` counts as effective coverage.
- ADDED: Tightened `.uz` and `.sa` parsing against current registered and
  exact authoritative-absence responses. `.uz` reserved names remain
  `:reserved`, not registered or available. Added a conservative `.ge` parser
  for exact registered and absence responses from IANA's `whois.nic.ge` host;
  `whois` 6.0.3 defaults `.ge` to `whois.registration.ge`, so a fixed-host
  route is still required before counting it as effective coverage.
- SAFETY: Kept blocked, empty, and ambiguous `.ch` responses unknown, and
  added unavailable-only handling for explicit unsupported responses from
  `.digital`, `.email`, `.live`, `.media`, `.network`, and `.services`.
- DOCS: Added a scorecard for 1,000 observed TLD strings from the ICANN DNS
  Magnitude snapshot dated 2026-09-12. Its strict count of 175 paired rows is
  pinned to parser baseline `f2c822c` and excludes the Top 100, whose summary
  labels do not expose row-level evidence pairs. The scorecard does not claim
  1,000 effective WHOIS integrations or a single effective-coverage rate.
  Later `.uz`/`.sa` evidence and `.pk`/`.ge` parsers are follow-ups, not
  additions to that pinned count.
- SOURCES: The audit notes link to the [ICANN DNS Magnitude
  snapshot](https://magnitude.research.icann.org/historic/20260912.full.html),
  [IANA `.top`](https://www.iana.org/domains/root/db/top.html),
  [IANA `.us`](https://www.iana.org/domains/root/db/us.html),
  [IANA `.ch`](https://www.iana.org/domains/root/db/ch.html),
  [IANA `.pk`](https://www.iana.org/domains/root/db/pk.html), and the
  [official PKNIC site](https://www.pknic.net.pk/). The
  [rank 104-105 report](docs/audits/top-101-125-tlds-2026-09-19.md) cites
  [IANA `.uz`](https://www.iana.org/domains/root/db/uz.html),
  [UZINFOCOM](https://www.cctld.uz/),
  [IANA `.sa`](https://www.iana.org/domains/root/db/sa.html), and
  [IANA `.ge`](https://www.iana.org/domains/root/db/ge.html).
- EVIDENCE: [Top-1,000 scorecard](docs/audits/top-1000-effective-coverage-scorecard-2026-09-25.md),
  [current `.top`/`.us` observations](docs/audits/top-us-current-2026-09-25.md),
  [`.pk` routing and registry evidence](docs/audits/top1000-es-pk-shop-dev-app-2026-09-25.md),
  and [rank 101-125 follow-up evidence](docs/audits/top-101-125-tlds-2026-09-19.md).


#### Release 0.2.0 (2026-09-25)

- ADDED: Extended the usage-ranked audit and parser work through 1,000 ICANN
  DNS Magnitude TLD strings from the 2026-09-12 snapshot.
- CLARIFIED: The 1,000 rows are observed TLD strings, not 1,000 guaranteed
  working registries or domain-availability results. The audit keeps verified
  parser evidence, explicit unavailable or unsupported responses,
  unknown or unresolved endpoints, and classification-only rows distinct.
- ADDED: Preserved the source manifest, verification evidence, planning
  inventory, and five implementation-package reports for ranks 301-1000.
- TESTED: The combined parser and audit suite passes 6,768 examples with 0
  failures on Ruby 3.2.2 and 3.4.5.


#### Release 0.1.0 (2026-09-19)

- CHANGED: Continued the project as `whois-parser-next`, with the original MIT
  license, attribution, and Git history preserved.
- CHANGED: Established Ruby 3.2 as the minimum supported version and refreshed
  the maintained dependency range.
- TESTED: Verified CI support through Ruby 4.0.7; Ruby 3.2 remains the minimum
  supported version.
- ADDED: Audits and regression fixtures for current registry responses.
- ADDED: Documented the 2026-09-19 usage-ranked audit through rank 300, using the ICANN DNS
  Magnitude snapshot dated 2026-09-12 and generated 2026-09-18, retaining
  source daily-rank positions and classifying `.arpa` outside registrable-domain
  parser scope.
- TESTED: The combined audit suite passes 6,640 examples with 0 failures.
- PACKAGING: The published gem is runtime-only, containing the library and
  essential documentation while excluding tests, fixtures, and repository
  automation.


#### Release 2.0.0

- CHANGED: Minimum Ruby version 2.6

- FIXED: Addressed security issues with eval and YAML.load. Thanks Francis Beaudoin


#### Release 1.2.0

- CHANGED: Updated .ORG parser to the latest response (GH-98, GH-97). [Thanks @talarini]
- CHANGED: Updated .IO, .AC, .SH, .TM parsers to the latest response.
- CHANGED: Renamed WhoisDomainKg to WhoisKg (GH-48)


#### Release 1.1.0

- NEW: Added .FM parser (GH-74). [Thanks @thomas07vt]
- NEW: Added .BR parser contacts (GH-31). [Thanks @forain]

- CHANGED: Updated WhoisAi to WhoisNicAi.
- CHANGED: WhoizBiz to the new response (GH-73). [Thanks @thomas07vt]
- CHANGED: WhoizNicSt to the new response (GH-72). [Thanks @fturmel]
- CHANGED: WhoisRegistryNetZa to the new response (GH-43). [Thanks @sheldonh]

- FIXED: Bug where .EU domain property had double .eu suffix (GH-63).
- FIXED: Fix scanning issue with .ca when keys have no value (GH-36).


#### Release 1.0.1

- CHANGED: Updated GoDaddy parser to the new response (GH-60).
- CHANGED: Updated Donuts parser to the new response. It looks like Donuts is now more compliant with base ICANN parser.
- CHANGED: Updated Verisign parser to the new response (GH-57). [Thanks @phcyso]
- CHANGED: Updated .BR parser to the new response (GH-51). [Thanks @otaviojr]
- CHANGED: Add support for :expires_on to base_nic_fr (GH-54). [Thanks @yastupin]


#### Release 1.0

**1.0.0-beta2**

- NEW: Added whois.cdmon.com parser (GH-27). [Thanks @sfumanal]

- FIXED: Fix for Record#respond_to?(:available?) (GH-28, GH-29, GH-30). Thanks [@marcandre]

**1.0.0-beta1**

Initial import from the `whois` library.

- NEW: whois.dk-hostmaster.dk parser now recognizes throttled responses (whois/GH-382). [Thanks @troelskn]
- NEW: Safer time parsing (GH-18). [Thanks @davidcornu]
- NEW: Detect reserved .INFO domains (whois/GH-468).

- CHANGED: whois.audns.net.au removed the registrar ID field (GH-20, GH-21). Thanks [@afoster]
- CHANGED: Updated .JOBS from obswhois.verisign-grs.com to whois.nic.jobs (GH-23).
- CHANGED: Updated .PRO from whois.dotproregistry.net to whois.afilias.net (GH-24).
