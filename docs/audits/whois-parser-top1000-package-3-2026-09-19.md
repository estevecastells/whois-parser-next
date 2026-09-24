# WHOIS parser audit, package-3 ranks 301-1000

Date: 2026-09-19

## Scope and evidence

This package owns the 140 rows marked package-3 in the locked planning CSV (data/whois-parser-top1000-planning.csv), derived from the ICANN DNS Magnitude snapshot dated 2026-09-12. The rows are observed TLD strings, not a list of registrable domains.

For mapped Standard rows, I queried only the assigned official port-43 WHOIS host. The registered probe was google.<tld> where syntactically valid; the absence probe was codexp3-<source-rank>-20260919.<tld>. Queries were sequential, bounded to six seconds, and paced at approximately 0.75 seconds between requests. No web pages, RDAP endpoints, or non-registry sources were used. Captures were reduced to response markers and field names; contact data and service disclaimers were not retained.

Outcome counts across all 140 owned rows:

- Verified parser evidence: 34
- Explicitly unavailable or unsupported: 37
- Unknown or unresolved: 31
- Classification-only exclusions: 38

## Implementation decisions

BaseTop1000Icann is a conservative shared family for current ICANN-style responses. It recognizes only complete, observed absence markers such as No Data Found, The queried object does not exist: DOMAIN NOT FOUND, The queried object does not exist: no matching objects found, exact Radix availability lines, and exact reserved markers. Empty, denied, throttled, malformed, and otherwise ambiguous responses remain unknown or unavailable and never become registrations.

Identity Digital's exact TLD is not supported. response uses the existing BaseUnsupportedRegistry family and raises Whois::ResponseIsUnavailable. The three GMO endpoints that answered with the exact May 1, 2026 WHOIS-retirement notice use BaseTop1000Retired and also raise unavailable. The Aruba, .укр, Beijing Tele-info, and IDN endpoints use small host adapters because their current port-43 formats are not ICANN key/value responses or require an additional exact marker.

The hosts with DNS failure, timeout, or connection reset, plus the partial .fishing probe, remain unknown. The twenty-one Google Registry rows share one unresolved whois.nic.google host and do not receive a fabricated parser.

## Complete row audit

| Rank | TLD | WHOIS host | Outcome | Evidence-backed action |
|---:|---|---|---|---|
| 304 | .fox | whois.nic.fox | verified | Added BaseTop1000Icann adapter with exact current markers |
| 307 | .agency | whois.nic.agency | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 312 | .buzz | whois.nic.buzz | verified | Added BaseTop1000Icann adapter with exact current markers |
| 315 | .cam | whois.nic.cam | verified | Added BaseTop1000Icann adapter with exact current markers |
| 331 | .codes | whois.nic.codes | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 337 | .bind | — | excluded | ICANN undelegated; classification-only |
| 346 | .casa | whois.nic.casa | verified | Added BaseTop1000Icann adapter with exact current markers |
| 347 | .academy | whois.nic.academy | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 359 | .files | — | excluded | ICANN undelegated; classification-only |
| 361 | .love | whois.nic.love | verified | Added BaseTop1000Icann adapter with exact current markers |
| 366 | .monster | whois.nic.monster | verified | Added BaseTop1000Icann adapter with exact current markers |
| 377 | .energy | whois.nic.energy | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 385 | .rest | whois.nic.rest | verified | Added BaseTop1000Icann adapter with exact current markers |
| 389 | .nexus | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 392 | .dog | whois.nic.dog | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 394 | .fan | whois.nic.fan | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 403 | .mp | — | excluded | Server adapter None; no port-43 parser |
| 419 | .bar | whois.nic.bar | verified | Added BaseTop1000Icann adapter with exact current markers |
| 427 | .army | whois.nic.army | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 429 | .xin | whois.nic.xin | verified | Added BaseTop1000Icann adapter with exact current markers |
| 439 | .capital | whois.nic.capital | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 441 | .berlin | whois.nic.berlin | verified | Added BaseTop1000Icann adapter with exact current markers |
| 445 | .sap | whois.nic.sap | verified | Added BaseTop1000Icann adapter with exact current markers |
| 446 | .boo | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 449 | .place | whois.nic.place | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 458 | .zip | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 461 | .nrw | whois.nic.nrw | verified | Added BaseTop1000Icann adapter with exact current markers |
| 464 | .surf | whois.nic.surf | verified | Added BaseTop1000Icann adapter with exact current markers |
| 465 | .dummy | — | excluded | ICANN undelegated; classification-only |
| 481 | .style | whois.nic.style | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 485 | .ing | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 486 | .day | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 511 | .adsl | — | excluded | ICANN undelegated; classification-only |
| 514 | .rent | whois.nic.rent | verified | Added BaseTop1000Icann adapter with exact current markers |
| 523 | .photography | whois.nic.photography | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 529 | .dad | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 533 | .estate | whois.nic.estate | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 540 | .gle | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 542 | .mov | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 557 | .ns | — | excluded | ICANN undelegated; classification-only |
| 562 | .university | whois.nic.university | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 567 | .new | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 570 | .immo | whois.nic.immo | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 584 | .tld | — | excluded | ICANN undelegated; classification-only |
| 588 | .ceo | whois.nic.ceo | verified | Added BaseTop1000Icann adapter with exact current markers |
| 595 | .football | whois.nic.football | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 597 | .how | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 602 | .food | — | excluded | Server adapter None; no port-43 parser |
| 608 | .museum | whois.nic.museum | verified | Added BaseTop1000Icann adapter with exact current markers |
| 609 | .rodeo | whois.nic.rodeo | verified | Added BaseTop1000Icann adapter with exact current markers |
| 612 | .wedding | whois.nic.wedding | verified | Added BaseTop1000Icann adapter with exact current markers |
| 614 | .bingo | whois.nic.bingo | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 617 | .quebec | whois.nic.quebec | verified | Added BaseTop1000Icann adapter with exact current markers |
| 618 | .schwarz | whois.nic.schwarz | verified | Added BaseTop1000Icann adapter with exact current markers |
| 624 | .basketball | whois.nic.basketball | verified | Added BaseTop1000Icann adapter with exact current markers |
| 632 | .col | — | excluded | ICANN undelegated; classification-only |
| 643 | .shoes | whois.nic.shoes | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 645 | .foo | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 647 | .workgroup | — | excluded | ICANN undelegated; classification-only |
| 651 | .sky | whois.nic.sky | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 660 | .meme | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 661 | .va | — | excluded | Server adapter None; no port-43 parser |
| 673 | .glass | whois.nic.glass | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 678 | .insure | whois.nic.insure | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 680 | .hamburg | whois.nic.hamburg | verified | Added BaseTop1000Icann adapter with exact current markers |
| 682 | .wlan0 | — | excluded | ICANN undelegated; classification-only |
| 689 | .gdn | whois.nic.gdn | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 697 | .graphics | whois.nic.graphics | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 699 | .limo | whois.nic.limo | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 701 | .futbol | whois.nic.futbol | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 710 | .none | — | excluded | ICANN undelegated; classification-only |
| 716 | .med | whois.nic.med | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 726 | .srv | — | excluded | ICANN undelegated; classification-only |
| 728 | .jewelry | whois.nic.jewelry | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 729 | .aw | whois.nic.aw | verified | Added WhoisNicAw compact registered/free adapter |
| 733 | .boston | whois.nic.boston | verified | Added BaseTop1000Icann adapter with exact current markers |
| 735 | .broker | whois.nic.broker | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 744 | .mobile | whois.nic.mobile | verified | Added BaseTop1000Icann adapter with exact current markers |
| 746 | .cpa | — | excluded | No locked WHOIS server mapping; no parser target |
| 756 | .exposed | whois.nic.exposed | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 759 | .feedback | whois.nic.feedback | verified | Added BaseTop1000Icann adapter with exact current markers |
| 766 | .ic | — | excluded | ICANN undelegated; classification-only |
| 767 | .claims | whois.nic.claims | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 771 | .channel | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 772 | .holiday | whois.nic.holiday | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 773 | .corsica | whois-corsica.nic.fr | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 781 | .yokohama | whois.nic.yokohama | unavailable | Added BaseTop1000Retired adapter; exact RDAP-retirement notice raises unavailable |
| 791 | .ads | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 793 | .cooking | whois.nic.cooking | verified | Added BaseTop1000Icann adapter with exact current markers |
| 798 | .diamonds | whois.nic.diamonds | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 799 | .tennis | whois.nic.tennis | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 801 | .xn--j1amh | whois.dotukr.com | verified | Added WhoisDotukrCom exact No-match adapter |
| 802 | .dom | — | excluded | ICANN undelegated; classification-only |
| 809 | .xn--3ds443g | whois.teleinfo.cn | verified | Added WhoisTeleinfoCn ICANN/IDN adapter |
| 818 | .talk | whois.nic.talk | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 820 | .cnhttp | — | excluded | ICANN undelegated; classification-only |
| 825 | .rsvp | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 830 | .fishing | whois.nic.fishing | unknown | Reserved marker observed; generated absence query reset, so availability unresolved |
| 831 | .soy | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 836 | .googledomains | — | excluded | ICANN undelegated; classification-only |
| 844 | .lease | whois.nic.lease | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 847 | .dlinkrouter | — | excluded | ICANN undelegated; classification-only |
| 853 | .realty | whois.nic.realty | verified | Added BaseTop1000Icann adapter with exact current markers |
| 854 | .phd | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 860 | .scloud | — | excluded | ICANN undelegated; classification-only |
| 862 | .cricket | whois.nic.cricket | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 864 | .vodka | whois.nic.vodka | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 866 | .xn--mk1bu44c | whois.nic.xn--mk1bu44c | verified | Added BaseTop1000Icann IDN No-match adapter |
| 876 | .esq | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 878 | .dehttp | — | excluded | ICANN undelegated; classification-only |
| 889 | .crs | — | excluded | Server adapter None; no port-43 parser |
| 890 | .spot | whois.nic.spot | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 899 | .tires | whois.nic.tires | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 900 | .login | — | excluded | ICANN undelegated; classification-only |
| 907 | .config | — | excluded | ICANN undelegated; classification-only |
| 914 | .omicron | — | excluded | ICANN undelegated; classification-only |
| 915 | .osaka | whois.nic.osaka | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 921 | .pharmacy | — | excluded | Server adapter None; no port-43 parser |
| 924 | .xn--q9jyb4c | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 928 | .hola | — | excluded | ICANN undelegated; classification-only |
| 932 | .condos | whois.nic.condos | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 936 | .mibhigh | — | excluded | ICANN undelegated; classification-only |
| 937 | .kyoto | whois.nic.kyoto | unavailable | Added BaseTop1000Retired adapter; exact RDAP-retirement notice raises unavailable |
| 942 | .android | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 944 | .go | — | excluded | ICANN undelegated; classification-only |
| 950 | .toyota | whois.nic.toyota | unavailable | Added BaseTop1000Retired adapter; exact RDAP-retirement notice raises unavailable |
| 952 | .grp | — | excluded | ICANN undelegated; classification-only |
| 958 | .data | whois.nic.data | verified | Added BaseTop1000Icann adapter with exact current markers |
| 960 | .admin | — | excluded | ICANN undelegated; classification-only |
| 962 | .man | whois.nic.man | verified | Added BaseTop1000Icann adapter with exact current markers |
| 965 | .prof | whois.nic.google | unknown | Port-43 response unresolved (DNS failure, timeout, or connection reset); no parser conclusion |
| 968 | .degree | whois.nic.degree | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 969 | .wifi | — | excluded | ICANN undelegated; classification-only |
| 975 | .belkin | — | excluded | ICANN undelegated; classification-only |
| 976 | .yun | whois.teleinfo.cn | verified | Added WhoisTeleinfoCn ICANN/IDN adapter |
| 983 | .pdfpro | — | excluded | ICANN undelegated; classification-only |
| 989 | .yu | — | excluded | ICANN undelegated; classification-only |
| 993 | .viajes | whois.nic.viajes | unavailable | Added BaseUnsupportedRegistry adapter; exact TLD-not-supported response raises unavailable |
| 995 | .hotspot-50 | — | excluded | ICANN undelegated; classification-only |
| 1000 | .redis | — | excluded | ICANN undelegated; classification-only |

## Fixtures and verification

Sanitized fixtures are under spec/fixtures/responses/top1000_package3/. The focused suite is spec/whois/parsers/top1000_package3_spec.rb; it covers registered, available, reserved, unsupported, retired, empty, denial, ambiguous, compact Aruba/.укр/Tele-info, and IDN cases, and verifies that every safe package-3 host resolves to a non-Blank parser.

Focused verification on 2026-09-19:

    6 examples, 0 failures

No changes were made to the planning CSV, canonical manifest, README, changelog, version, or other packages.
