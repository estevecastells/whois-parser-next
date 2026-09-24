# WHOIS parser top-1000 package 1 audit

Date: 2026-09-19

## Result

This audit covers all 140 rows assigned to `package-1` in
`data/whois-parser-top1000-planning.csv`. The live checks used only the
assigned WHOIS port-43 hosts, with a bounded 5-8 second socket timeout and a
respectful pause between queries. The registered probes used `google.<tld>` or
another registry-owned/known registered label where the first probe was not
registered. The absence probes used the generated label
`zzdomscan20260919.<tld>`.

| Outcome | Rows | Meaning |
| --- | ---: | --- |
| `verified` | 11 | Seven hosts have registered and authoritative absence evidence; four have an explicit unsupported or retired response and are represented as unavailable adapters. |
| `unknown` | 6 | The host returned a meaningful absence/reserved marker, but no registered response was available in the bounded probe window. No parser was added. |
| `unavailable` | 86 | The endpoint returned an empty body, reset, timeout, or no route. Existing parsers remain unverified and no new support was inferred. |
| `excluded` | 37 | `None`, `Web`, undelegated, or delegated-without-server rows. Classification only, by design. |

No availability result is inferred from an empty, denied, throttled,
malformed, or ambiguous response.

## Verified parser adapters

The following rows have both registered and authoritative absence fixtures.
The adapters reuse an existing parser family and include safety coverage for
empty, denied, and ambiguous responses.

Complete row keys: `305:cyou`, `434:security`, `483:eco`, `538:radio`,
`569:kiwi`, `911:xn--tckwe`, `961:xn--d1acj3b`.

| Rank | TLD | Host | Adapter | Evidence |
| ---: | --- | --- | --- | --- |
| 305 | `cyou` | `whois.nic.cyou` | `Whois::Parsers::WhoisNicCyou` | CentralNic ICANN record; `DOMAIN NOT FOUND` absence marker |
| 434 | `security` | `whois.nic.security` | `Whois::Parsers::WhoisNicSecurity` | CentralNic ICANN record; `DOMAIN NOT FOUND` absence marker |
| 483 | `eco` | `whois.nic.eco` | `Whois::Parsers::WhoisNicEco` | CIRA record; `Not found:` absence marker |
| 538 | `radio` | `whois.nic.radio` | `Whois::Parsers::WhoisNicRadio` | CentralNic ICANN record; `DOMAIN NOT FOUND` absence marker |
| 569 | `kiwi` | `whois.nic.kiwi` | `Whois::Parsers::WhoisNicKiwi` | CIRA record; `Not found:` absence marker |
| 911 | `xn--tckwe` | `whois.nic.xn--tckwe` | `Whois::Parsers::WhoisNicXnTckwe` | VeriSign record; `No match for` absence marker |
| 961 | `xn--d1acj3b` | `whois.nic.xn--d1acj3b` | `Whois::Parsers::WhoisNicXnD1acj3b` | CentralNic ICANN record; object-not-found absence marker |

The following rows are explicit endpoint classifications, not availability
support:

Complete row keys: `492:solar`, `789:tienda`, `792:okinawa`, `842:maison`.

| Rank | TLD | Host | Adapter | Evidence |
| ---: | --- | --- | --- | --- |
| 492 | `solar` | `whois.nic.solar` | `Whois::Parsers::WhoisNicSolar` | `TLD is not supported.` |
| 789 | `tienda` | `whois.nic.tienda` | `Whois::Parsers::WhoisNicTienda` | `TLD is not supported.` |
| 792 | `okinawa` | `whois.nic.okinawa` | `Whois::Parsers::WhoisNicOkinawa` | WHOIS retired; response directs callers to RDAP |
| 842 | `maison` | `whois.nic.maison` | `Whois::Parsers::WhoisNicMaison` | `TLD is not supported.` |

## Unknown rows

These six delegated standard rows returned a meaningful absence or reserved
marker, but the paired registered probe was empty or reset. They remain
unresolved and do not receive a parser adapter.

Complete row keys: `324:stream`, `358:party`, `468:law`, `554:fashion`,
`671:faith`, `684:gives`.

| Rank | TLD | Host | Evidence |
| ---: | --- | --- | --- |
| 324 | `stream` | `whois.nic.stream` | `No Data Found` absence marker only |
| 358 | `party` | `whois.nic.party` | `No Data Found` absence marker only |
| 468 | `law` | `whois.nic.law` | `No Data Found` absence marker only |
| 554 | `fashion` | `whois.nic.fashion` | `Reserved Domain Name` response only |
| 671 | `faith` | `whois.nic.faith` | `No Data Found` absence marker only |
| 684 | `gives` | `whois.nic.gives` | `Domain not found.` absence marker only |

## Unavailable rows

The following complete ledger lists every row whose current standard endpoint
was empty, reset, timed out, or unreachable. The existing parser classes in
these groups remain `parser_present_unverified`; Blank rows remain unresolved.

| Host | Assigned rows (`rank:tld`) | Probe result |
| --- | --- | --- |
| `whois.nic.company` | `328:company` | empty |
| `whois.afilias-srs.net` | `332:onl`, `402:homes`, `442:porn`, `495:ist`, `537:godaddy`, `541:yachts`, `544:boats`, `547:sex`, `593:srl`, `605:audi`, `616:motorcycles`, `630:vegas`, `657:adult`, `688:istanbul`, `708:abbott`, `725:bnpparibas` | empty |
| `whois.uniregistry.net` | `336:pics`, `344:game`, `356:audio`, `425:mom`, `455:photo`, `579:auto`, `606:gift`, `619:sexy`, `628:christmas`, `634:tattoo`, `687:property`, `727:cars`, `795:car`, `856:country`, `873:diet`, `883:flowers`, `940:hiphop`, `999:guitars` | empty |
| `whois.nic.watch` | `373:watch` | empty |
| `whois.nic.exchange` | `383:exchange` | empty |
| `whois.nic.vision` | `407:vision` | empty |
| `whois.nic.school` | `428:school` | empty |
| `whois.nic.golf` | `435:golf` | empty |
| `whois.nic.guide` | `443:guide` | empty |
| `whois.nic.church` | `447:church` | empty |
| `whois.nic.gallery` | `454:gallery` | empty |
| `whois.nic.sale` | `471:sale` | empty |
| `whois.nic.report` | `474:report` | empty |
| `whois.nic.pictures` | `475:pictures` | empty |
| `whois.nic.forum` | `476:forum` | empty |
| `whois.nic.wine` | `490:wine` | empty |
| `whois.nic.industries` | `496:industries` | empty |
| `whois.nic.menu` | `497:menu` | empty |
| `whois.nic.fund` | `516:fund` | empty |
| `whois.nic.supply` | `518:supply` | empty |
| `whois.nic.tours` | `536:tours` | empty |
| `whois.nic.ventures` | `561:ventures` | empty |
| `whois.nic.taxi` | `571:taxi` | empty |
| `whois.nic.reviews` | `574:reviews` | empty |
| `whois.nic.markets` | `578:markets` | empty |
| `whois.nic.movie` | `580:movie` | empty |
| `whois.nic.financial` | `615:financial` | empty |
| `whois.nic.contact` | `623:contact` | empty |
| `whois.nic.enterprises` | `629:enterprises` | empty |
| `whois.nic.clothing` | `633:clothing` | empty |
| `whois.nic.trading` | `654:trading` | empty |
| `whois.nic.irish` | `670:irish` | empty |
| `whois.nic.productions` | `676:productions` | empty |
| `whois.nic.lighting` | `685:lighting` | empty |
| `whois.nic.diy` | `690:diy` | empty |
| `whois.nic.credit` | `692:credit` | empty |
| `whois.nic.flights` | `714:flights` | empty |
| `whois.nic.locker` | `718:locker` | empty |
| `whois.nic.next` | `731:next` | empty |
| `whois.nic.sydney` | `741:sydney` | empty |
| `capetown-whois.registry.net.za` | `745:capetown` | no route to host |
| `joburg-whois.registry.net.za` | `751:joburg` | timeout |
| `whois.nic.hockey` | `770:hockey` | empty |
| `whois.nixiregistry.in` | `806:xn--h2brj9c` | empty |
| `whois.registry.knet.cn` | `807:xn--ses554g` | timeout |
| `whois.nic.singles` | `811:singles` | empty |
| `whois.nic.catering` | `835:catering` | empty |
| `whois.nic.career` | `843:career` | timeout |
| `durban-whois.registry.net.za` | `859:durban` | no route to host |
| `whois.nic.dentist` | `867:dentist` | empty |
| `whois.nic.reise` | `869:reise` | empty |
| `whois.nic.hot` | `870:hot` | timeout |
| `whois.nic.deal` | `881:deal` | timeout |
| `whois.nic.moi` | `919:moi` | timeout |

## Excluded classification-only rows

These rows are included in the package ledger but are not parser targets.

| Classification | Assigned rows (`rank:tld`) |
| --- | --- |
| `None` adapter | `326:health`, `371:qpon`, `426:earth`, `549:sd`, `591:ren`, `641:realtor`, `833:dhl`, `868:kp`, `884:gn` |
| Web adapter | `575:bm`, `675:bb`, `926:gw` |
| Undelegated | `351:corp`, `610:html`, `655:lgwebostv`, `700:olk`, `720:comundefined`, `739:burp`, `761:ip`, `794:jpg`, `814:autodesk`, `841:json`, `851:tl-wa850re`, `895:realtek`, `905:comms-appx-web`, `912:mob`, `918:txt`, `934:cnb`, `941:argocd-repo-server`, `956:blank`, `966:comv1`, `972:content`, `981:gn-cn`, `987:empty`, `992:qtq` |
| No server mapping | `493:gay`, `949:xn--czr694b` |

## Files and verification

Added the eleven host adapters, two reusable family bases, sanitized minimal
fixtures, and `spec/whois/parsers/top1000_package1_spec.rb`. The focused spec
covers registered and absence markers for all seven supported hosts, explicit
unsupported/retired responses, and empty, denied, and ambiguous safety cases.

The audit intentionally does not change the planning CSV or the canonical
top-1000 manifest.
