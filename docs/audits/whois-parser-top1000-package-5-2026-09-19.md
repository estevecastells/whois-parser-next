# WHOIS parser audit, package 5

Date: 2026-09-19

## Scope and method

This package owns the 140 rows marked `package-5` in
`docs/audits/data/whois-parser-top1000-planning.csv`, covering source ranks
308 through 998. The source ranks are the ICANN DNS Magnitude TLD-string
snapshot, not a list of registrable domain names.

Each non-empty mapped host was queried directly over the registry's port-43
WHOIS service with the macOS `whois -h HOST DOMAIN` client. Probes used a
known registered `google.<tld>` name where that supplied positive evidence and
the generated label `zzzz-whois-parser-20260919.<tld>` for an absence probe.
Requests were paced between hosts and bounded by the command's connection
timeout. Responses were classified only from explicit registry evidence.

An empty response, DNS failure, timeout, WHOIS denial, GlobalBlock notice,
RDAP-only notice, prohibited-string response, or malformed/ambiguous record
is not treated as available. The generated probe is evidence of absence only
when the registry returned an authoritative absence marker.

## Summary

| Outcome | Rows |
|---|---:|
| Registered and authoritative absence both verified | 39 |
| Authoritative absence verified, registered probe unresolved | 5 |
| Registered response verified, absence probe blocked or ambiguous | 4 |
| Explicit registry denial (`TLD is not supported`) | 44 |
| Endpoint unavailable (DNS failure or timeout) | 8 |
| WHOIS retired, RDAP-only notice | 1 |
| GlobalBlock or other non-classifying notice | 1 |
| Delegated row with no server mapping | 1 |
| Delegated row intentionally mapped to `None` | 7 |
| Undelegated or special-use row excluded | 30 |
| **Total assigned rows** | **140** |

The parser changes add reusable adapters for the ICANN key/value layouts with
registry-specific absence markers, the CoreNIC/KNET/Ryce family, AFNIC's `.yt`,
the JWhoisServer family used by `.gf` and `.mq`, and the `cwhois.cnnic.cn`
alias. Existing `.cx`, `.gs`, `.tc`, `.tel`, `.aero`, `.lc`, and `.post`
parsers were rechecked against current port-43 responses and retained unless
the live response was explicitly unavailable or ambiguous.

## Row-by-row result

| Rank | TLD | WHOIS host/source | Current result | Action |
|---:|---|---|---|---|
| 308 | `.bid` | `whois.nic.bid` | registered + authoritative absence | Adapter/fixture |
| 310 | `.cx` | `whois.nic.cx` | registered; absence ambiguous/blocked | Existing parser; unresolved absence |
| 311 | `.build` | `whois.nic.build` | registered + authoritative absence | Adapter/fixture |
| 313 | `.events` | `whois.nic.events` | explicit registry denial | No fake support |
| 314 | `.sbs` | `whois.nic.sbs` | registered + authoritative absence | Adapter/fixture |
| 316 | `.social` | `whois.nic.social` | explicit registry denial | No fake support |
| 317 | `.moe` | `whois.nic.moe` | registered + authoritative absence | Adapter/fixture |
| 320 | `.lat` | `whois.nic.lat` | registered + authoritative absence | Adapter/fixture |
| 321 | `.aero` | `whois.aero` | registered; absence ambiguous/blocked | Existing parser; unresolved absence |
| 322 | `.wpad` | no server | undelegated; excluded | No parser |
| 325 | `.wiki` | `whois.nic.wiki` | registered + authoritative absence | Adapter/fixture |
| 329 | `.finance` | `whois.nic.finance` | explicit registry denial | No fake support |
| 330 | `.travel` | `whois.nic.travel` | explicit registry denial | No fake support |
| 340 | `.tc` | `whois.nic.tc` | registered + authoritative absence | Existing parser verified |
| 342 | `.care` | `whois.nic.care` | explicit registry denial | No fake support |
| 343 | `.event` | no server | undelegated; excluded | No parser |
| 352 | `.marketing` | `whois.nic.marketing` | explicit registry denial | No fake support |
| 354 | `.engineering` | `whois.nic.engineering` | explicit registry denial | No fake support |
| 355 | `.box` | `whois.aridnrs.net.au` | endpoint unavailable | Unknown; no parser |
| 365 | `.localhost` | no server | special-use; excluded | No parser |
| 370 | `.inc` | `whois.nic.inc` | registered + authoritative absence | Adapter/fixture |
| 374 | `.gs` | `whois.nic.gs` | registered; absence ambiguous/blocked | Existing parser; unresolved absence |
| 380 | `.trade` | `whois.nic.trade` | registered + authoritative absence | Adapter/fixture |
| 382 | `.show` | `whois.nic.show` | explicit registry denial | No fake support |
| 387 | `.tel` | `whois.nic.tel` | registered; absence ambiguous/blocked | Existing parser; unresolved absence |
| 388 | `.gold` | `whois.nic.gold` | explicit registry denial | No fake support |
| 391 | `.casino` | `whois.nic.casino` | explicit registry denial | No fake support |
| 393 | `.press` | `whois.nic.press` | registered + authoritative absence | Adapter/fixture |
| 400 | `.community` | `whois.nic.community` | explicit registry denial | No fake support |
| 404 | `.tokyo` | `whois.nic.tokyo` | WHOIS retired; RDAP-only notice | No parser |
| 415 | `.sy` | `whois.tld.sy` | endpoint unavailable | Unknown; no parser |
| 416 | `.undefined` | no server | undelegated; excluded | No parser |
| 418 | `.swiss` | `whois.nic.swiss` | registered + authoritative absence | Adapter/fixture |
| 440 | `.scot` | `whois.nic.scot` | registered + authoritative absence | Adapter/fixture |
| 444 | `.farm` | `whois.nic.farm` | explicit registry denial | No fake support |
| 459 | `.wang` | `whois.gtld.knet.cn` | registered + authoritative absence | Adapter/fixture |
| 462 | `.cab` | `whois.nic.cab` | explicit registry denial | No fake support |
| 463 | `.beauty` | `whois.nic.beauty` | registered + authoritative absence | Adapter/fixture |
| 478 | `.comhttp` | no server | undelegated; excluded | No parser |
| 479 | `.men` | `whois.nic.men` | registered + authoritative absence | Adapter/fixture |
| 491 | `.parts` | `whois.nic.parts` | explicit registry denial | No fake support |
| 494 | `.gal` | `whois.nic.gal` | registered + authoritative absence | Adapter/fixture |
| 498 | `.clinic` | `whois.nic.clinic` | explicit registry denial | No fake support |
| 506 | `.band` | `whois.nic.band` | explicit registry denial | No fake support |
| 507 | `.vin` | `whois.nic.vin` | explicit registry denial | No fake support |
| 509 | `.boutique` | `whois.nic.boutique` | explicit registry denial | No fake support |
| 513 | `.dating` | `whois.nic.dating` | explicit registry denial | No fake support |
| 515 | `.fitness` | `whois.nic.fitness` | explicit registry denial | No fake support |
| 519 | `.consulting` | `whois.nic.consulting` | explicit registry denial | No fake support |
| 524 | `.wales` | `whois.nic.wales` | endpoint unavailable | Unknown; no parser |
| 525 | `.lc` | `whois.afilias-grs.info` | registered + authoritative absence | Existing parser verified |
| 530 | `.cymru` | `whois.nic.cymru` | endpoint unavailable | Unknown; no parser |
| 545 | `.comhttps` | no server | undelegated; excluded | No parser |
| 548 | `.courses` | `whois.aridnrs.net.au` | endpoint unavailable | Unknown; no parser |
| 553 | `.yt` | `whois.nic.yt` | registered + authoritative absence | Adapter/fixture |
| 555 | `.amsterdam` | `whois.nic.amsterdam` | registered + authoritative absence | Adapter/fixture |
| 558 | `.paris` | `whois-paris.nic.fr` | endpoint unavailable | Unknown; no parser |
| 564 | `.kitchen` | `whois.nic.kitchen` | explicit registry denial | No fake support |
| 565 | `.mi` | no server | undelegated; excluded | No parser |
| 566 | `.camp` | `whois.nic.camp` | explicit registry denial | No fake support |
| 568 | `.tax` | `whois.nic.tax` | explicit registry denial | No fake support |
| 572 | `.dental` | `whois.nic.dental` | explicit registry denial | No fake support |
| 590 | `.comnull` | no server | undelegated; excluded | No parser |
| 592 | `.moscow` | `whois.nic.moscow` | registered + authoritative absence | Adapter/fixture |
| 598 | `.review` | `whois.nic.review` | registered + authoritative absence | Adapter/fixture |
| 607 | `.living` | no WHOIS adapter | delegated, no WHOIS adapter | Keep `None` |
| 611 | `.koeln` | `whois.ryce-rsp.com` | registered + authoritative absence | Adapter/fixture |
| 613 | `.fail` | `whois.nic.fail` | explicit registry denial | No fake support |
| 626 | `.gifts` | `whois.nic.gifts` | explicit registry denial | No fake support |
| 636 | `.healthcare` | `whois.nic.healthcare` | explicit registry denial | No fake support |
| 639 | `.investments` | `whois.nic.investments` | explicit registry denial | No fake support |
| 640 | `.intra` | no server | undelegated; excluded | No parser |
| 648 | `.forsale` | `whois.nic.forsale` | explicit registry denial | No fake support |
| 652 | `.cw` | no WHOIS adapter | delegated, no WHOIS adapter | Keep `None` |
| 656 | `.coupons` | `whois.nic.coupons` | explicit registry denial | No fake support |
| 659 | `.racing` | `whois.nic.racing` | registered + authoritative absence | Adapter/fixture |
| 667 | `.repair` | `whois.nic.repair` | explicit registry denial | No fake support |
| 669 | `.kids` | no server mapping | delegated, no server mapping | No parser |
| 677 | `.loans` | `whois.nic.loans` | explicit registry denial | No fake support |
| 691 | `.xn--fiqs8s` | `cwhois.cnnic.cn` | registered + authoritative absence | Adapter/fixture |
| 695 | `.observer` | `whois.nic.observer` | registered + authoritative absence | Adapter/fixture |
| 696 | `.domain` | no server | undelegated; excluded | No parser |
| 698 | `.frl` | `whois.nic.frl` | registered + authoritative absence | Adapter/fixture |
| 705 | `.madrid` | `whois.madrid.rs.corenic.net` | registered + authoritative absence | Adapter/fixture |
| 709 | `.luxury` | `whois.nic.luxury` | registered + authoritative absence | Adapter/fixture |
| 712 | `.lifestyle` | `whois.nic.lifestyle` | explicit registry denial | No fake support |
| 717 | `.cheap` | `whois.nic.cheap` | explicit registry denial | No fake support |
| 719 | `.url` | no server | undelegated; excluded | No parser |
| 722 | `.krd` | `whois.aridnrs.net.au` | endpoint unavailable | Unknown; no parser |
| 724 | `.discount` | `whois.nic.discount` | explicit registry denial | No fake support |
| 734 | `.navy` | `whois.nic.navy` | explicit registry denial | No fake support |
| 737 | `.orghttp` | no server | undelegated; excluded | No parser |
| 748 | `.bmw` | `whois.nic.bmw` | registered + authoritative absence | Adapter/fixture |
| 750 | `.tickets` | `whois.nic.tickets` | registered + authoritative absence | Adapter/fixture |
| 753 | `.abb` | no WHOIS adapter | delegated, no WHOIS adapter | Keep `None` |
| 755 | `.saarland` | `whois.nic.saarland` | registered + authoritative absence | Adapter/fixture |
| 757 | `.supplies` | `whois.nic.supplies` | explicit registry denial | No fake support |
| 764 | `.melbourne` | `whois.aridnrs.net.au` | endpoint unavailable | Unknown; no parser |
| 775 | `.gf` | `whois.mediaserv.net` | registered + authoritative absence | Adapter/fixture |
| 788 | `.krhttp` | no server | undelegated; excluded | No parser |
| 790 | `.vacations` | `whois.nic.vacations` | explicit registry denial | No fake support |
| 805 | `.xn--80asehdb` | `whois.online.rs.corenic.net` | authoritative absence only | Adapter; registered probe unresolved |
| 808 | `.ruhttp` | no server | undelegated; excluded | No parser |
| 812 | `.xn--80adxhks` | `whois.nic.xn--80adxhks` | authoritative absence only | Adapter; registered probe unresolved |
| 813 | `.rehab` | `whois.nic.rehab` | explicit registry denial | No fake support |
| 815 | `.mq` | `whois.mediaserv.net` | registered + authoritative absence | Adapter/fixture |
| 816 | `.storage` | `whois.nic.storage` | registered + authoritative absence | Adapter/fixture |
| 821 | `.cologne` | `whois.ryce-rsp.com` | registered + authoritative absence | Adapter/fixture |
| 829 | `.pvt` | no server | undelegated; excluded | No parser |
| 840 | `.statefarm` | no WHOIS adapter | delegated, no WHOIS adapter | Keep `None` |
| 846 | `.hospital` | `whois.nic.hospital` | explicit registry denial | No fake support |
| 850 | `.kred` | no WHOIS adapter | delegated, no WHOIS adapter | Keep `None` |
| 858 | `.attorney` | `whois.nic.attorney` | explicit registry denial | No fake support |
| 865 | `.eduhttp` | no server | undelegated; excluded | No parser |
| 872 | `.dvag` | `whois.nic.dvag` | authoritative absence only | Adapter; registered probe unresolved |
| 874 | `.gripe` | `whois.nic.gripe` | explicit registry denial | No fake support |
| 880 | `.or` | no server | undelegated; excluded | No parser |
| 885 | `.xn--czru2d` | `whois.gtld.knet.cn` | registered + authoritative absence | Adapter/fixture |
| 887 | `.xn--t60b56a` | `whois.nic.xn--t60b56a` | registered + authoritative absence | Adapter/fixture |
| 888 | `.physio` | `whois.nic.physio` | GlobalBlock/not available notice | Unknown; no parser |
| 893 | `.metadata` | no server | undelegated; excluded | No parser |
| 894 | `.xn--6qq986b3xl` | `whois.gtld.knet.cn` | registered + authoritative absence | Adapter/fixture |
| 897 | `.xn--80aswg` | `whois.online.rs.corenic.net` | authoritative absence only | Adapter; registered probe unresolved |
| 902 | `.siriinternet` | no server | undelegated; excluded | No parser |
| 908 | `.accountants` | `whois.nic.accountants` | explicit registry denial | No fake support |
| 910 | `.router` | no server | undelegated; excluded | No parser |
| 917 | `.hiboard` | no server | undelegated; excluded | No parser |
| 925 | `.priv` | no server | undelegated; excluded | No parser |
| 933 | `.mars` | no server | undelegated; excluded | No parser |
| 939 | `.jphttp` | no server | undelegated; excluded | No parser |
| 945 | `.barclays` | `whois.nic.barclays` | authoritative absence only | Adapter; registered probe unresolved |
| 947 | `.post` | `whois.dotpostregistry.net` | registered + authoritative absence | Existing parser verified |
| 948 | `.warp-svc` | no server | undelegated; excluded | No parser |
| 955 | `.ico` | no server | undelegated; excluded | No parser |
| 964 | `.nlhttp` | no server | undelegated; excluded | No parser |
| 971 | `.root` | no server | undelegated; excluded | No parser |
| 980 | `.unused` | no server | undelegated; excluded | No parser |
| 986 | `.xn--90ae` | no WHOIS adapter | delegated, no WHOIS adapter | Keep `None` |
| 991 | `.citic` | no WHOIS adapter | delegated, no WHOIS adapter | Keep `None` |
| 998 | `.ns1` | no server | undelegated; excluded | No parser |

## Fixtures and verification

Fixtures under `spec/fixtures/responses/top1000_package5/` are sanitized,
minimal response shapes. They preserve only the keys and exact marker lines
needed for status, domain, and nameserver assertions.

The focused suite is `spec/whois/parsers/top1000_package5_spec.rb`. It covers
all adapter families, every authoritative absence marker, the JWhois and AFNIC
families, explicit denial safety, empty responses, ambiguous domain-only
responses, and the 140-row package inventory.
