# WHOIS parser top-1000 package-2 audit


Date: 2026-09-19


## Scope and outcome


This audit covers all 140 rows assigned to package-2 in docs/audits/data/whois-parser-top1000-planning.csv. Port-43 checks were limited to the mapped official WHOIS hosts, with bounded probes and respectful pacing. No arbitrary web pages were fetched. A registered result is claimed only where a current record-shaped response was observed. The .bank available result uses the exact No Data Found marker observed from its official endpoint. Denials, empty responses, reserved/ambiguous responses, timeouts, and missing mappings are never treated as available.


Current outcome counts:

| Outcome | Rows |
|---|---:|
| verified_registered | 17 |
| verified_available | 1 |
| verified_unavailable | 48 |
| unknown | 25 |
| unavailable | 10 |
| excluded | 39 |


## Implemented parser families


- Added 16 ICANN-shaped host adapters that parse current registered responses through BaseIcannCompliant.
- Added WhoisNicBank, whose exact first-line No Data Found marker is the only package-specific available marker implemented in this pass.
- Added explicit unavailable adapters for the current TLD is not supported hosts, plus .canon (WHOIS retired) and .gq (the endpoint says the TLD has no WHOIS server).
- Hardened BaseUnsupportedRegistry to recognize the denial marker when the official footer follows it, and extended shared response safety so existing Afilias-family parsers raise ResponseIsUnavailable instead of attempting to parse a denial.
- Existing .xxx registered parsing was revalidated. The shared Afilias host was observed returning an explicit denial for .bet, but per-TLD results remain unknown because the endpoint began rate-limiting the probe sequence. .jobs timed out during the bounded probe and remains unavailable/unverified.


## Row-by-row evidence


| Rank | TLD | WHOIS host | Initial state | Outcome | Parser/result | Evidence |
|---:|---|---|---|---|---|---|
| 302 | .team | [whois.nic.team] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicTeam | Port-43 explicit TLD is not supported sample google.team; SHA-256 0f67715fbfa825d9101ef17d33f65c499f77e6b8b807213b2e03842ee73d0d9d. |
| 303 | .support | [whois.nic.support] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicSupport | Port-43 explicit TLD is not supported sample google.support; SHA-256 5e780d231d3175e843053a06ae1ba8ea024e9322289faf57650a2b7ee0a4189f. |
| 309 | .bet | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 318 | .center | [whois.nic.center] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicCenter | Port-43 explicit TLD is not supported sample google.center; SHA-256 ac569c9d65e9be3602c92b1fefe10c9181fc9eeb81087517f40d27d60d652246. |
| 319 | .guru | [whois.nic.guru] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicGuru | Port-43 explicit TLD is not supported sample google.guru; SHA-256 2294c9033be5ba09c8f2c845037d4b46f34b2f522fd6c4b1c796059ddafe6b9a. |
| 323 | .red | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 333 | .https | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 335 | .bio | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 339 | .xxx | [whois.nic.xxx] | parser_present_unverified | verified_registered | Whois::Parsers::WhoisNicXxx | Port-43 registered sample google.xxx; SHA-256 23fa6362f7012d74fd96327a56b80f0b7b96be048779fd78a76640ae40f87a3d. |
| 341 | .wtf | [whois.nic.wtf] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicWtf | Port-43 explicit TLD is not supported sample google.wtf; SHA-256 9670870e7244c2fe7d4f6bfdecdd0f4d1a3aeb373cabb311e3ca417cadeea914. |
| 353 | .initplayback | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 357 | .city | [whois.nic.city] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicCity | Port-43 explicit TLD is not supported sample google.city; SHA-256 2a32a148815be8fa3f40ad7b1715b5376c163741431bfe0a8d5f4984c673265e. |
| 364 | .pet | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 367 | .money | [whois.nic.money] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicMoney | Port-43 explicit TLD is not supported sample google.money; SHA-256 6bb0ccace86e25b361fb02b8691b9acdd67debc82bbb40777ee942f2713e9924. |
| 375 | .test | — | excluded_special_use | excluded | classification-only | No implementation: source is special-use. |
| 379 | .llc | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 386 | .education | [whois.nic.education] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicEducation | Port-43 explicit TLD is not supported sample google.education; SHA-256 ea7be3b1ba7434da155acda06296fe04ee08dcf2c1ebeb6bec26f0489da4ef49. |
| 390 | .beer | [whois.nic.beer] | parser_missing | verified_registered | Whois::Parsers::WhoisNicBeer | Port-43 registered sample google.beer; SHA-256 bba322372b3f0ee4238355311362f844d1ffde5c0ce94ab863e2a3856ca1716d. |
| 395 | .house | [whois.nic.house] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicHouse | Port-43 explicit TLD is not supported sample google.house; SHA-256 a0387b7360b32670ba8d5610c50ed84118033ff16e9ca1885af2f4a8b5dc7906. |
| 396 | .expert | [whois.nic.expert] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicExpert | Port-43 explicit TLD is not supported sample google.expert; SHA-256 d8159b0da3d0036101f62f13707e2bdea6568ede32059f74b9694cf299d93079. |
| 397 | .cafe | [whois.nic.cafe] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicCafe | Port-43 explicit TLD is not supported sample google.cafe; SHA-256 dd5b258f597b5cf0114b1094799949ea62d654a69ed9b7b29f9a36884bf81515. |
| 401 | .jobs | [whois.nic.jobs] | parser_present_unverified | unavailable | Whois::Parsers::WhoisNicJobs | Port-43 current probe for google.jobs produced timeout or empty response; no parser claim is made. |
| 411 | .garden | [whois.nic.garden] | parser_missing | unknown | Blank | Port-43 sample google.garden returned Reserved Domain Name; reserved/negative evidence is not treated as availability and no parser was added. |
| 412 | .now | [whois.nic.now] | parser_missing | unavailable | Blank | Port-43 current probe for google.now produced timeout or empty response; no parser claim is made. |
| 414 | .blue | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 420 | .bond | [whois.nic.bond] | parser_missing | verified_registered | Whois::Parsers::WhoisNicBond | Port-43 registered sample google.bond; SHA-256 8e0847ae16018a205b16841fe9cd90a7e11a914c51d8e3a8837621079fe45459. |
| 421 | .family | [whois.nic.family] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicFamily | Port-43 explicit TLD is not supported sample google.family; SHA-256 245c39097bf77ea67b65b16ec2b5608bc6b1811220c45acaa3e4a7305c7c6b8d. |
| 422 | .foundation | [whois.nic.foundation] | parser_missing | verified_registered | Whois::Parsers::WhoisNicFoundation | Port-43 registered sample google.foundation; SHA-256 c8c224b9cdc69c23d858d4ca633c352cf9044c6475f4286fe1992496e7d70055. |
| 423 | .bike | [whois.nic.bike] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicBike | Port-43 explicit TLD is not supported sample google.bike; SHA-256 313d1d08286ccf7d252fa74bf53612f0942f1350b7d1edef67bd7c2987c0eaef. |
| 424 | .pizza | [whois.nic.pizza] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicPizza | Port-43 explicit TLD is not supported sample google.pizza; SHA-256 d7697aa95d478017dc14903f5a9af987258fc1d60a86a90d40d7026378525bfd. |
| 430 | .rip | [whois.nic.rip] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicRip | Port-43 explicit TLD is not supported sample google.rip; SHA-256 6faecca3abacf2b8aede69c517db511592576722768f4b6cca7e91b49a0eee52. |
| 431 | .autos | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 432 | .ooo | [whois.nic.ooo] | parser_missing | verified_registered | Whois::Parsers::WhoisNicOoo | Port-43 registered sample google.ooo; SHA-256 12822117efa14012d7c7e62a24a55b86d833180aa709f5348763111ccfa69a17. |
| 437 | .tips | [whois.nic.tips] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicTips | Port-43 explicit TLD is not supported sample google.tips; SHA-256 7ecba42b44ee96189f4baf267169f3e664f020fa56e97a6ea366c176822d1eea. |
| 438 | .careers | [whois.nic.careers] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicCareers | Port-43 explicit TLD is not supported sample google.careers; SHA-256 cc1f3fe89786129a23e4a43a18eb98fdebb148defd9f6279d011bccb489ae8e8. |
| 451 | .tube | — | adapter_none_excluded | excluded | classification-only | No implementation: server adapter is None. |
| 456 | .skin | [whois.nic.skin] | parser_missing | verified_registered | Whois::Parsers::WhoisNicSkin | Port-43 registered sample google.skin; SHA-256 98a37374af6b628703b9325abb57610688c5ba4a0233840d2925e38a9f1b8fd0. |
| 457 | .gq | [whois.dominio.gq] | parser_missing | verified_unavailable | Whois::Parsers::WhoisDominioGq | Port-43 response says the TLD has no WHOIS server; sample google.gq; SHA-256 edadc206502ecd1567a126faa067129479c4d06d0d377163f613f784294edc34. |
| 472 | .deals | [whois.nic.deals] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicDeals | Port-43 explicit TLD is not supported sample google.deals; SHA-256 061b2f8149869937de8452e4f497219c18dfd824f870bde412eab0842f9f1cba. |
| 473 | .london | [whois.nic.london] | parser_missing | verified_registered | Whois::Parsers::WhoisNicLondon | Port-43 registered sample google.london; SHA-256 b0bfbb4f77f55c63ce2cf6d35e44dc7e972d4a600ec97ffe4665b033f9b78a0d. |
| 477 | .kim | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 480 | .webcam | [whois.nic.webcam] | parser_missing | verified_registered | Whois::Parsers::WhoisNicWebcam | Port-43 registered sample google.webcam; SHA-256 498c65cf9fc9fadea1fd2c38a4f8eddab99f7935bfff64e1eeb6c70c4f319961. |
| 482 | .town | [whois.nic.town] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicTown | Port-43 explicit TLD is not supported sample google.town; SHA-256 e5cfdc2692fa7c6c33984c10c07539053900f278e01f5bb1e24533db1e1104e4. |
| 484 | .bank | [whois.nic.bank] | parser_missing | verified_available | Whois::Parsers::WhoisNicBank | Port-43 exact No Data Found sample google.bank; SHA-256 123a3978c63894944cd91bc81ea185d677c02495e21905740ce23087136e76b8. |
| 487 | .desi | [whois.nic.desi] | parser_missing | unavailable | Blank | Port-43 current probe for google.desi produced timeout or empty response; no parser claim is made. |
| 489 | .study | [whois.nic.study] | parser_missing | verified_registered | Whois::Parsers::WhoisNicStudy | Port-43 registered sample google.study; SHA-256 bddfbddd1bd2a0044a015994f6bede08a3681f10f89ca2cd6e7b4f95a034b7c0. |
| 501 | .pink | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 504 | .computer | [whois.nic.computer] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicComputer | Port-43 explicit TLD is not supported sample google.computer; SHA-256 1409fa6d0741513270dc812d51018b93fa6ba91f8a838596d887a26a77194b11. |
| 505 | .institute | [whois.nic.institute] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicInstitute | Port-43 explicit TLD is not supported sample google.institute; SHA-256 ee9f91d07ef26240f18eb801c868d8c95d227415ddbd8db313015063d592a4b8. |
| 508 | .hair | — | adapter_none_excluded | excluded | classification-only | No implementation: server adapter is None. |
| 512 | .vet | [whois.nic.vet] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicVet | Port-43 explicit TLD is not supported sample google.vet; SHA-256 eddd276d4a479ae7b5ffbc13b2ec80011cf60172cdec21238913e24a8f806df9. |
| 517 | .green | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 520 | .builders | [whois.nic.builders] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicBuilders | Port-43 explicit TLD is not supported sample google.builders; SHA-256 925d14c464980e2dfee80c0029fb624086834ca9e8d0d55355b249ebee7c9db2. |
| 521 | .sport | [whois.nic.sport] | parser_missing | verified_registered | Whois::Parsers::WhoisNicSport | Port-43 registered sample google.sport; SHA-256 c6ffc4626b8f860829db9054863a5292f37bea9379826c47bab7fccb5e26c1b4. |
| 522 | .fish | [whois.nic.fish] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicFish | Port-43 explicit TLD is not supported sample google.fish; SHA-256 fd1f47428b0e7c0e514624ed849203c1ffb871a87f56751d582645e7d4d19329. |
| 526 | .bradesco | [whois.nic.bradesco] | parser_missing | unknown | Blank | Port-43 sample google.bradesco returned Domain not found.; reserved/negative evidence is not treated as availability and no parser was added. |
| 527 | .pf | [whois.registry.pf] | parser_missing | unavailable | Blank | Port-43 current probe for google.pf produced timeout or empty response; no parser claim is made. |
| 531 | .coach | [whois.nic.coach] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicCoach | Port-43 explicit TLD is not supported sample google.coach; SHA-256 2a32a148815be8fa3f40ad7b1715b5376c163741431bfe0a8d5f4984c673265e. |
| 532 | .promo | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 535 | .training | [whois.nic.training] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicTraining | Port-43 explicit TLD is not supported sample google.training; SHA-256 10c0ad712496751cf27e20eb22e43b62a71b30c33a6fb0154cfa5b58f33c8f2e. |
| 546 | .lgbt | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 550 | .auction | [whois.nic.auction] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicAuction | Port-43 explicit TLD is not supported sample google.auction; SHA-256 712f3644573e02db00733724849b71dde8b0d43934c3d5ab9f5fdbd7de2a0f8c. |
| 552 | .yoga | [whois.nic.yoga] | parser_missing | verified_registered | Whois::Parsers::WhoisNicYoga | Port-43 registered sample google.yoga; SHA-256 38b7c58ed19820f2853a94f788dbd2dffa6c317da4b9dd9c1b402bcbda896867. |
| 556 | .loc | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 559 | .jetzt | [whois.nic.jetzt] | adapter_none_excluded | excluded | classification-only | No implementation: server adapter is None. |
| 573 | .black | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 577 | .makeup | [whois.nic.makeup] | parser_missing | verified_registered | Whois::Parsers::WhoisNicMakeup | Port-43 registered sample google.makeup; SHA-256 59b19179f5e33201464bb1d3ba3f25f6b48ad7636bdddbd1a5a75fd98a30083a. |
| 582 | .svc | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 583 | .dance | [whois.nic.dance] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicDance | Port-43 explicit TLD is not supported sample google.dance; SHA-256 ae38bf4bdad94080d666021d37afdee9811cbde225dda29f8ebf2452dc6d3786. |
| 594 | .limited | [whois.nic.limited] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicLimited | Port-43 explicit TLD is not supported sample google.limited; SHA-256 14978ed06c242afca68f9c4f49cfd7ab923c7da59844a7ea0afcf83275debde3. |
| 599 | .properties | [whois.nic.properties] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicProperties | Port-43 explicit TLD is not supported sample google.properties; SHA-256 fc203d01ce183ea02dfc2ef7cffbc7aada5fc3d294d55c0b17918ec61e5391fa. |
| 601 | .omada | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 625 | .http | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 627 | .mba | [whois.nic.mba] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicMba | Port-43 explicit TLD is not supported sample google.mba; SHA-256 84ae1920d51b977bd5f0b6eb951ca57635dafae77ae7192d284f672aa4b1461e. |
| 631 | .vote | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 642 | .realestate | [whois.nic.realestate] | parser_missing | unavailable | Blank | Port-43 current probe for google.realestate produced timeout or empty response; no parser claim is made. |
| 644 | .ski | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 646 | .ye | — | adapter_none_excluded | excluded | classification-only | No implementation: server adapter is None. |
| 653 | .holdings | [whois.nic.holdings] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicHoldings | Port-43 explicit TLD is not supported sample google.holdings; SHA-256 2294c9033be5ba09c8f2c845037d4b46f34b2f522fd6c4b1c796059ddafe6b9a. |
| 658 | .music | — | no_server_mapping | excluded | classification-only | No implementation: no locked WHOIS host mapping. |
| 663 | .poker | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 664 | .miami | [whois.nic.miami] | parser_missing | verified_registered | Whois::Parsers::WhoisNicMiami | Port-43 registered sample google.miami; SHA-256 539402ac1ccdba56328273919da3334e5ac7b16a4cc0cd2075f1c54829ffc2ef. |
| 668 | .taipei | [whois.nic.taipei] | parser_missing | verified_registered | Whois::Parsers::WhoisNicTaipei | Port-43 registered sample google.taipei; SHA-256 5f8294393fec25aedce77a4c7e4936d7c44d63543ecc3a10e980b8411b5f6d91. |
| 672 | .vlaanderen | [whois.nic.vlaanderen] | parser_missing | unavailable | Blank | Port-43 current probe for google.vlaanderen produced DNS/transport failure; no parser claim is made. |
| 674 | .schule | [whois.nic.schule] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicSchule | Port-43 explicit TLD is not supported sample google.schule; SHA-256 ef1224ef69ff9458e4311ce086b71497596782769cf3370085f2155020324274. |
| 679 | .salon | [whois.nic.salon] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicSalon | Port-43 explicit TLD is not supported sample google.salon; SHA-256 c819e6f6476546cc0707fc9476a5efa9aa2a37824ad49d1915df062c5dfa41cd. |
| 681 | .gateway | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 683 | .doctor | [whois.nic.doctor] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicDoctor | Port-43 explicit TLD is not supported sample google.doctor; SHA-256 43a170446339d162188a22bc5875975ebdf372a79961e1f7d0a5c29c08d0f38e. |
| 686 | .mr | [whois.nic.mr] | adapter_none_excluded | excluded | classification-only | No implementation: server adapter is None. |
| 703 | .lawyer | [whois.nic.lawyer] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicLawyer | Port-43 explicit TLD is not supported sample google.lawyer; SHA-256 029b11d654d95845f5c4158ebd2d5cdb23a54982f845c696a42552c7198ceaf3. |
| 704 | .js | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 706 | .equipment | [whois.nic.equipment] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicEquipment | Port-43 explicit TLD is not supported sample google.equipment; SHA-256 d8159b0da3d0036101f62f13707e2bdea6568ede32059f74b9694cf299d93079. |
| 713 | .archi | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 723 | .eth0 | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 740 | .actor | [whois.nic.actor] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicActor | Port-43 explicit TLD is not supported sample google.actor; SHA-256 dc64fadef9e41374063d123942b7909c88b960c5e40dd9b24f11791851ca3d11. |
| 742 | .reisen | [whois.nic.reisen] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicReisen | Port-43 explicit TLD is not supported sample google.reisen; SHA-256 c7ba48c26219d3d83dd9ad415a37a7b47586dc20b2ddf3e8c316e71c6b4df70d. |
| 743 | .png | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 765 | .intern | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 768 | .furniture | [whois.nic.furniture] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicFurniture | Port-43 explicit TLD is not supported sample google.furniture; SHA-256 cb3e29fe603b77e9b874cd2c98569b39b53396ae0feed0fbf24ed5cb954beab0. |
| 783 | .xn--6frz82g | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 787 | .canon | [whois.nic.canon] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicCanon | Port-43 WHOIS-retired notice sample google.canon; SHA-256 c3f431389949890809727895761aafaaa9fee3cc385721f7883d481e6435a93a. |
| 796 | .comm | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 797 | .florist | [whois.nic.florist] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicFlorist | Port-43 explicit TLD is not supported sample google.florist; SHA-256 e08471b050ba4f91d851fc123d094b5118286792efe80e8ed15183526dc11f59. |
| 804 | .apartments | [whois.nic.apartments] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicApartments | Port-43 explicit TLD is not supported sample google.apartments; SHA-256 dc64fadef9e41374063d123942b7909c88b960c5e40dd9b24f11791851ca3d11. |
| 810 | .bargains | [whois.nic.bargains] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicBargains | Port-43 explicit TLD is not supported sample google.bargains; SHA-256 40555c0bc4e77820ebb03bd8f71593e8f8f2dffca456b01bb51c733a5cd877ec. |
| 817 | .hp-print-mgmt | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 822 | .contractors | [whois.nic.contractors] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicContractors | Port-43 explicit TLD is not supported sample google.contractors; SHA-256 27d09d0888a7abc475eca5336275bce32a52418517f53823551d57ccf842cc1a. |
| 824 | .voto | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 828 | .giving | [whois.nic.giving] | parser_missing | verified_registered | Whois::Parsers::WhoisNicGiving | Port-43 registered sample google.giving; SHA-256 972f386270065a3a8fea59b897cb1af0621ae3d0e868d11b3a516cca6c49a532. |
| 834 | .lab | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 845 | .api | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 848 | .organic | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |
| 852 | .alsace | [whois-alsace.nic.fr] | parser_missing | unavailable | Blank | Port-43 current probe for google.alsace produced DNS/transport failure; no parser claim is made. |
| 855 | .nethttp | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 861 | .fast | [whois.nic.fast] | parser_missing | unavailable | Blank | Port-43 current probe for google.fast produced timeout or empty response; no parser claim is made. |
| 871 | .vnhttp | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 877 | .kn | [whois.nic.kn] | parser_missing | verified_registered | Whois::Parsers::WhoisNicKn | Port-43 registered sample google.kn; SHA-256 0bf69f88024e1d3420f4f3479c98d7e6bd1b1931b21513e3382b2db28c666b8b. |
| 882 | .abudhabi | [whois.nic.abudhabi] | parser_missing | unknown | Blank | Port-43 sample google.abudhabi returned Reserved Domain Name; reserved/negative evidence is not treated as availability and no parser was added. |
| 886 | .nhk | — | adapter_none_excluded | excluded | classification-only | No implementation: server adapter is None. |
| 896 | .dns | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 904 | .republican | [whois.nic.republican] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicRepublican | Port-43 explicit TLD is not supported sample google.republican; SHA-256 fe83b5c5d55800c8a777f022255f4aea95d3f6457b9e93ccd584d9d4a22f908a. |
| 906 | .commarket | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 913 | .pri | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 920 | .ithttp | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 923 | .creditcard | [whois.nic.creditcard] | parser_missing | verified_unavailable | Whois::Parsers::WhoisNicCreditcard | Port-43 explicit TLD is not supported sample google.creditcard; SHA-256 78e1be15dfc066193a7207fa11fcdb5d611809a0f0a4720c7f2c4eaaae8c8299. |
| 927 | .cboxh | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 929 | .gop | [whois.nic.gop] | parser_missing | unavailable | Blank | Port-43 current probe for google.gop produced DNS/transport failure; no parser claim is made. |
| 935 | .iphone | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 943 | .mib2p | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 951 | .no-data | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 957 | .select | [whois.nic.select] | parser_missing | verified_registered | Whois::Parsers::WhoisNicSelect | Port-43 registered sample google.select; SHA-256 2af89bbce702200cd5c130ba5daa2d84921c19bcaa39a4c8444d93f386fafec1. |
| 959 | .dll | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 967 | .comt | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 973 | .ntt | — | adapter_none_excluded | excluded | classification-only | No implementation: server adapter is None. |
| 979 | .xn--kput3i | [whois.nic.xn--kput3i] | parser_missing | unknown | Blank | Port-43 sample google.xn--kput3i returned Internationalized Domain Name: google.手机; reserved/negative evidence is not treated as availability and no parser was added. |
| 982 | .gbl | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 985 | .pay | [whois.nic.pay] | parser_missing | unavailable | Blank | Port-43 current probe for google.pay produced timeout or empty response; no parser claim is made. |
| 988 | .coms | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 994 | .eunull | — | excluded_undelegated | excluded | classification-only | No implementation: source is undelegated. |
| 996 | .shiksha | [whois.afilias.net] | parser_present_unverified | unknown | Whois::Parsers::WhoisAfiliasNet | Shared-host sample google.bet returned explicit unsupported notice (SHA-256 f74ad65a2639f4c00f578fa1f30cb7dc42c6bbd58929e08788a09887a0ab1d95); each TLD was not re-queried after rate limiting, so no per-TLD status is claimed. |


## Test evidence


Focused package specs:

    RBENV_VERSION=3.2.2 rbenv exec bundle exec rspec spec/whois/parsers/top1000_package_2_spec.rb
    8 examples, 0 failures


The focused suite covers registered ICANN evidence, the exact .bank availability marker, ambiguous no-object responses, explicit denials, empty responses, WHOIS retirement/no-WHOIS responses, and the shared Afilias denial contract.

Full RSpec:

    6653 examples, 0 failures

Scoped RuboCop for the changed Ruby files and package spec reported no offenses. The repository-wide RuboCop task still reports pre-existing offenses outside this package.
