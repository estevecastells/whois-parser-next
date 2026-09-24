# WHOIS parser audit, package-4

Date: 2026-09-19

## Scope and evidence

This report covers the 140 rows assigned to `package-4` in
[`whois-parser-top1000-planning.csv`](data/whois-parser-top1000-planning.csv),
which preserves the ICANN DNS Magnitude snapshot for 2026-09-12. The source
rank is observed DNS-query magnitude, not registration volume.

The live checks used only the mapped registry WHOIS endpoints on TCP port 43.
Requests were bounded, serialized, and paced. Registered probes used
`google.<tld>` or another stable registry-owned name where available. Absence
probes used the syntactically valid generated label
`codex-package4-20260919.<tld>`. Captures were reduced to parser-relevant
markers and contain no personal contact data.

An adapter is marked verified only when the endpoint supplied an authoritative
record marker and an authoritative absence marker, or when the endpoint
supplied an explicit denial/reservation that must remain unavailable. Empty,
throttled, timed-out, retired, DNS-failed, and ambiguous responses remain
unresolved and never become availability or registration claims.

## Outcome summary

| Outcome | Rows |
|---|---:|
| Verified parser adapter, registered and available/absent markers | 16 |
| Verified unavailable or reserved safety adapter | 50 |
| Existing parser revalidated, with small marker fixes where needed | 5 |
| Existing parser revalidated, no change | 10 |
| Unknown or unavailable live endpoint, left unresolved | 20 |
| Classification-only (undelegated, special-use, None, or unmapped) | 39 |
| **Total** | **140** |

The unavailable/reserved total includes 42 exact `TLD is not supported.`
responses and 8 explicit reservation responses. The parser changes do not
claim that those names are available or registered.

## Complete row audit

| Rank | TLD | Port-43 mapping | Outcome | Parser action |
|---:|---|---|---|---|
| 301 | `.blog` | `whois.nic.blog` | Verified registered + `Not found:` | Added CIRA-family host adapter |
| 306 | `.null` | none | Excluded, undelegated | Classification only |
| 327 | `.int` | `whois.iana.org` | Verified authoritative zero objects | Existing IANA parser retained |
| 334 | `.fit` | `whois.nic.fit` | Unknown, query limit exceeded | No parser conclusion |
| 338 | `.no-op-domain` | none | Excluded, undelegated | Classification only |
| 345 | `.coop` | `whois.nic.coop` | Verified registered + Radix available | Added current availability marker to existing parser |
| 348 | `.bayern` | `whois.nic.bayern` | Verified registered + no matching objects | Added CentralNic-family adapter |
| 349 | `.fyi` | `whois.nic.fyi` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 350 | `.partners` | `whois.nic.partners` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 360 | `.gd` | `whois.nic.gd` | Verified registered + `DOMAIN NOT FOUND` | Added current absence marker to existing parser |
| 362 | `.pm` | `whois.nic.pm` | Verified registered + `%% NOT FOUND` | Added current AFNIC absence marker |
| 363 | `.onion` | none | Excluded, special-use | Classification only |
| 368 | `.cool` | `whois.nic.cool` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 369 | `.xn--p1ai` | `whois.tcinet.ru` | Verified no entries | Existing TCI parser retained |
| 372 | `.land` | `whois.nic.land` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 376 | `.express` | `whois.nic.express` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 378 | `.ax` | `whois.ax` | Verified registered + `Domain not found` | Added current absence marker to existing parser |
| 381 | `.international` | `whois.nic.international` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 384 | `.eus` | `whois.nic.eus` | Verified registered + no matching objects | Added CentralNic-family adapter |
| 398 | `.cash` | `whois.nic.cash` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 399 | `.tf` | `whois.nic.fr` | Verified AFNIC `%% NOT FOUND` | Added current absence marker to shared parser |
| 405 | `.mo` | `whois.monic.mo` | Verified `No match for` absence | Existing Monic parser retained |
| 406 | `.bot` | `whois.nic.bot` | Unknown, endpoint timed out | No parser conclusion |
| 408 | `.sx` | `whois.sx` | Unknown, DNS failure | No parser conclusion |
| 409 | `.uno` | `whois.nic.uno` | Verified registered + Radix available | Added Radix-family adapter |
| 410 | `.quest` | `whois.nic.quest` | Verified registered + `DOMAIN NOT FOUND` | Added CentralNic-family adapter |
| 413 | `.microsoftofficehub` | none | Excluded, undelegated | Classification only |
| 417 | `.photos` | `whois.nic.photos` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 433 | `.coffee` | `whois.nic.coffee` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 436 | `.download` | `whois.nic.download` | Unknown, query limit exceeded | No parser conclusion |
| 448 | `.baby` | `whois.nic.baby` | Verified registered + `DOMAIN NOT FOUND` | Added CentralNic-family adapter |
| 450 | `.nyc` | `whois.nic.nyc` | Unknown, query limit exceeded/reset | No parser conclusion |
| 452 | `.legal` | `whois.nic.legal` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 453 | `.fans` | `whois.nic.fans` | Verified registered + `DOMAIN NOT FOUND` | Added CentralNic-family adapter |
| 460 | `.free` | `whois.nic.free` | Unknown, empty/timeout response | No parser conclusion |
| 466 | `.science` | `whois.nic.science` | Unknown, query limit exceeded | No parser conclusion |
| 467 | `.cards` | `whois.nic.cards` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 469 | `.con` | none | Excluded, undelegated | Classification only |
| 470 | `.gmbh` | `whois.nic.gmbh` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 488 | `.directory` | `whois.nic.directory` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 499 | `.management` | `whois.nic.management` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 500 | `.ruhr` | `whois.nic.ruhr` | Verified registered + `DOMAIN NOT FOUND` | Added CentralNic-family adapter |
| 502 | `.nc` | `whois.nc` | Verified `No entries found` absence | Existing parser retained |
| 503 | `.date` | `whois.nic.date` | Unknown, query limit exceeded | No parser conclusion |
| 510 | `.camera` | `whois.nic.camera` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 528 | `.shopping` | `whois.nic.shopping` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 534 | `.mc` | None adapter | Excluded, adapter is None | Classification only |
| 539 | `.film` | `whois.nic.film` | Verified reserved-domain response | Added reservation safety adapter |
| 543 | `.college` | `whois.nic.college` | Verified registered + `DOMAIN NOT FOUND` | Existing CentralNic-family parser retained |
| 551 | `.loan` | `whois.nic.loan` | Unknown, query limit exceeded/reset | No parser conclusion |
| 560 | `.globo` | `whois.gtlds.nic.br` | Unknown, endpoint timed out | No parser conclusion |
| 563 | `.braze` | none | Excluded, undelegated | Classification only |
| 576 | `.toys` | `whois.nic.toys` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 581 | `.bzh` | `whois.nic.bzh` | Verified registered + `%% NOT FOUND` | Added ICANN/AFNIC-marker adapter |
| 585 | `.ngo` | `whois.publicinterestregistry.net` | Verified reserved-policy response | Added reservation safety adapter |
| 586 | `.ky` | `whois.kyregistry.ky` | Verified registered + Radix available | Added Radix-family adapter |
| 587 | `.sz` | None adapter | Excluded, adapter is None | Classification only |
| 589 | `.engineer` | `whois.nic.engineer` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 596 | `.brussels` | `whois.nic.brussels` | Unknown, DNS failure | No parser conclusion |
| 600 | `.horse` | `whois.nic.horse` | Unknown, query limit exceeded/reset | No parser conclusion |
| 603 | `.php` | none | Excluded, undelegated | Classification only |
| 604 | `.wien` | `whois.nic.wien` | Verified registered + `Available` | Added reserved/available ICANN adapter |
| 620 | `.xn--p1acf` | `whois.nic.xn--p1acf` | Unknown, DNS failure | No parser conclusion |
| 621 | `.you` | `whois.nic.you` | Unknown, timeout | No parser conclusion |
| 622 | `.restaurant` | `whois.nic.restaurant` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 635 | `.haus` | `whois.nic.haus` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 637 | `.as132673` | none | Excluded, undelegated | Classification only |
| 638 | `.rentals` | `whois.nic.rentals` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 649 | `.dlink` | none | Excluded, undelegated | Classification only |
| 650 | `.gratis` | `whois.nic.gratis` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 662 | `.barcelona` | `whois.nic.barcelona` | Verified registered + no matching objects | Added CentralNic-family adapter |
| 665 | `.www` | none | Excluded, undelegated | Classification only |
| 666 | `.recipes` | `whois.nic.recipes` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 693 | `.moda` | `whois.nic.moda` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 694 | `.mail` | none | Excluded, undelegated | Classification only |
| 702 | `.construction` | `whois.nic.construction` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 707 | `.bible` | `whois.nic.bible` | Verified reserved-domain response | Added reservation safety adapter |
| 711 | `.bbrouter` | none | Excluded, undelegated | Classification only |
| 715 | `.hm` | `whois.registry.hm` | Unknown, endpoint timed out | No parser conclusion |
| 721 | `.luxe` | `whois.nic.luxe` | Unknown, query limit exceeded | No parser conclusion |
| 730 | `.v1` | none | Excluded, undelegated | Classification only |
| 732 | `.tirol` | `whois.nic.tirol` | Verified registered + `Available` | Added reserved/available ICANN adapter |
| 736 | `.soccer` | `whois.nic.soccer` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 738 | `.kaufen` | `whois.nic.kaufen` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 747 | `.cleaning` | `whois.nic.cleaning` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 749 | `.intranet` | none | Excluded, undelegated | Classification only |
| 752 | `.leclerc` | `whois-leclerc.nic.fr` | Unknown, DNS failure | No parser conclusion |
| 754 | `.charity` | `whois.nic.charity` | Verified reserved-policy response | Added reservation safety adapter |
| 758 | `.xn--90ais` | `whois.cctld.by` | Verified `object does not exist` absence | Existing parser retained |
| 760 | `.tatar` | `whois.nic.tatar` | Verified registered + object-specific no-entry | Added Tatar marker adapter |
| 762 | `.immobilien` | `whois.nic.immobilien` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 763 | `.voyage` | `whois.nic.voyage` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 769 | `.sarl` | `whois.nic.sarl` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 774 | `.associates` | `whois.nic.associates` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 776 | `.ong` | `whois.publicinterestregistry.net` | Verified reserved-policy response | Added reservation safety adapter |
| 777 | `.villas` | `whois.nic.villas` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 778 | `.default` | none | Excluded, undelegated | Classification only |
| 779 | `.cruises` | `whois.nic.cruises` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 780 | `.gent` | `whois.nic.gent` | Verified registered + `DOMAIN NOT FOUND` | Added CentralNic-family adapter |
| 782 | `.nagoya` | `whois.nic.nagoya` | Unknown, WHOIS retired for RDAP | No parser conclusion |
| 784 | `.sucks` | `whois.nic.sucks` | Unknown, query limit exceeded | No parser conclusion |
| 785 | `.ss` | `whois.nic.ss` | Verified no-object; prohibited string stays unknown | Added SSNIC safety adapter |
| 786 | `.xn--55qx5d` | `whois.ngtld.cn` | Verified reserved-list response | Added reservation safety adapter |
| 800 | `.mortgage` | `whois.nic.mortgage` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 803 | `.czhttp` | none | Excluded, undelegated | Classification only |
| 819 | `.xn--3e0b707e` | `whois.kr` | Verified registered + not-found absence | Existing Korean parser retained |
| 823 | `.rugby` | `whois.centralnic.com` | Verified `DOMAIN NOT FOUND` absence | Existing CentralNic parser retained |
| 826 | `.forex` | `whois.nic.forex` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 827 | `.spa` | no mapping | Excluded, no server mapping | Classification only |
| 832 | `.xn--io0a7i` | `whois.ngtld.cn` | Verified reserved-list response | Added reservation safety adapter |
| 837 | `.plumbing` | `whois.nic.plumbing` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 838 | `.xn--o3cw4h` | `whois.thnic.co.th` | Verified registered + no-match absence | Existing Thai parser retained |
| 839 | `.citrix` | none | Excluded, undelegated | Classification only |
| 849 | `.gvc884571451de` | none | Excluded, undelegated | Classification only |
| 857 | `.rio` | `whois.gtlds.nic.br` | Unknown, endpoint timed out | No parser conclusion |
| 863 | `.lr` | None adapter | Excluded, adapter is None | Classification only |
| 875 | `.accountant` | `whois.nic.accountant` | Verified reserved-domain response | Added reservation safety adapter |
| 879 | `.getcacheddhcpresultsforcurrentconfig` | none | Excluded, undelegated | Classification only |
| 891 | `.domainforsale` | none | Excluded, undelegated | Classification only |
| 892 | `.theater` | `whois.nic.theater` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 898 | `.surgery` | `whois.nic.surgery` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 901 | `.mp3` | none | Excluded, undelegated | Classification only |
| 903 | `.xn--5tzm5g` | `whois.nic.xn--5tzm5g` | Excluded, None adapter | Classification only |
| 909 | `.williamhill` | none | Excluded, None adapter | Classification only |
| 916 | `.exe` | none | Excluded, undelegated | Classification only |
| 922 | `.dealer` | none | Excluded, None adapter | Classification only |
| 930 | `.tcs` | none | Excluded, undelegated | Classification only |
| 931 | `.xn--j6w193g` | `whois.hkirc.hk` | Verified not-registered absence | Existing HKIRC parser retained |
| 938 | `.private` | none | Excluded, undelegated | Classification only |
| 946 | `.lcl` | none | Excluded, undelegated | Classification only |
| 953 | `.hkhttp` | none | Excluded, undelegated | Classification only |
| 954 | `.democrat` | `whois.nic.democrat` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 963 | `.cisco` | none | Excluded, None adapter | Classification only |
| 970 | `.cnnull` | none | Excluded, undelegated | Classification only |
| 974 | `.memorial` | `whois.nic.memorial` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 977 | `.fk` | none | Excluded, None adapter | Classification only |
| 978 | `.airforce` | `whois.nic.airforce` | Verified explicit unsupported-TLD denial | Added unavailable adapter |
| 984 | `.cahttp` | none | Excluded, undelegated | Classification only |
| 990 | `.master` | none | Excluded, undelegated | Classification only |
| 997 | `.behnam` | none | Excluded, undelegated | Classification only |

## Safety and verification

The new fixtures are sanitized and retain only status, availability, denial,
reservation, or no-object markers needed by the parser. Focused tests cover
registered and available responses for every positive adapter, explicit
unsupported and reserved responses, SSNIC's prohibited-string ambiguity, and
empty/temporary response safety. Empty, timeout, DNS-failure, throttled, and
WHOIS-retired rows have no parser added.

Focused command:

```text
PATH=/Users/esteve/.rbenv/versions/3.2.2/bin:$PATH bundle exec rspec \
  spec/whois/parsers/topdomains_package_4_spec.rb
11 examples, 0 failures
```

No changes were made to the planning CSV, canonical source manifest, README,
CHANGELOG, gem version, or deployment configuration. This package is local
only and is not pushed or deployed by this audit.
