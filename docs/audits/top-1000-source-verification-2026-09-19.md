# ICANN DNS Magnitude source verification

Date: 2026-09-19

## Result

The repository's pinned source manifest for ranks 1-300 is reproducible and
correct as a repository artifact. The canonical form is one UTF-8 line per
row, `source-rank:tld`, followed by a final newline. Its SHA-256 is:

```text
3f30997fd02e9481a316f2eaee541143b16cb445198cbf35956f5ae1c5950b62
```

The authoritative historical response is preserved by ICANN under its public
`historic` directory. The 2026-09-12 snapshot is therefore independently
recoverable and its ranks 301-1000 digest is recorded below. The live root page
has already rolled forward to 2026-09-13, so the dated historical URL must be
used for this manifest.

## Authoritative source and retrieval evidence

Source index: <https://magnitude.research.icann.org/>
Historical source: <https://magnitude.research.icann.org/historic/20260912.full.html>
Historical directory: <https://magnitude.research.icann.org/historic/>

The ICANN page says that it aggregates query names by top-level domain, limits
the table to the top 2,000 daily-ranked strings, and exposes `Daily Rank`; see
the source page's methodology and column descriptions. It labels the table's
values as “Top-Level Domain”, not registered domains. The source therefore
supports a top-1,000 **TLD-string** coverage audit, not a top-1,000 registered
domain audit.

Direct retrieval of the historical source on 2026-09-19 at 11:06:35 UTC
returned:

```text
HTTP/1.1 200 OK
Last-Modified: Fri, 18 Sep 2026 04:13:10 GMT
ETag: "cac4b-65bba1e440b89"
Content-Length: 830539
```

The downloaded HTML SHA-256 was:

```text
92e2ba73d59ad4c8876fb3ab98c99c66e625d310c179e04d2194acbd674a0a0c
```

The page heading was:

```text
DNS Statistics for Saturday, 12 September 2026
(generated on Friday, 18 September 2026)
```

The current root page was also retrieved and confirmed to have rolled to the
next snapshot, 2026-09-13 generated 2026-09-19. The historical directory
listing records `20260912.full.html` as an 811K file last modified on 2026-09-18.

## Repository ranks 1-300 verification

The nine existing audit reports contain exactly 300 rows, one for each source
rank 1 through 300, with 300 unique TLD labels and no duplicate rank. The
following command independently reproduced the pinned digest from those
reports:

```sh
perl -ne 'if(/^\|\s*(\d+)\s*\|\s*`\.([^`]+)`\s*\|/){print "$1:$2\n"}' \
  docs/audits/*.md | sort -n -t: -k1,1 > /tmp/magnitude-ranks-1-300-canonical.txt
sha256sum /tmp/magnitude-ranks-1-300-canonical.txt
```

Observed output:

```text
300 rows, 300 unique labels, ranks 1-300
3f30997fd02e9481a316f2eaee541143b16cb445198cbf35956f5ae1c5950b62
```

The pinned rows begin `1:com`, `2:net`, `3:org`, `4:arpa`, `5:uk` and end
`296:best`, `297:today`, `298:cfd`, `299:market`, `300:help`.

## Historical rank 301-1000 manifest

The historical 2026-09-12 HTML was parsed by the `Daily Rank` column. The
exact canonical digest for source ranks 301-1000 is:

```text
Rows: 700
Unique labels: 700
SHA-256 of `rank:tld\n` rows 301-1000:
3a1be524d77f9c9847d70db80929f9033cfdccdd20ba442c310e126ee2ab673c
```

The historical full ranks 1-1000 digest is:

```text
6f1411e1323ed09683480b47314188c71c19d62979d2d7cc2894669b4dd9e681
```

The first historical rows in the 301-1000 extraction are:

```text
301:blog
302:team
303:support
304:fox
305:cyou
306:null
307:agency
308:bid
309:bet
310:cx
```

The last historical rows are:

```text
991:citic
992:qtq
993:viajes
994:eunull
995:hotspot-50
996:shiksha
997:behnam
998:ns1
999:guitars
1000:redis
```

The historical first-300 extraction independently hashes to the repository's
pinned value above, confirming that the URL, parser, rank interpretation, and
canonicalization agree with the existing reports.

For comparison only, the live root page's current 2026-09-13 ranks 301-1000
hash to `daca871c3fc58013585bab5ed36ddae185e3870d43d7bdb84d13c949de668fc7`.
That digest is not part of the target manifest.

## Duplicate, special-use, undelegated, and encoding checks

The historical source-rank rows 1-300 have no duplicate labels. Historical
rows 301-1000 also have 700 unique labels. Through rank 1000, the historical
page exposes 844 delegated, 6 special-use, and 150 undelegated rows.

The historical page's special-use rows through rank 1000 are:

```text
11:local
126:invalid
168:example
363:onion
365:localhost
375:test
```

IANA's Special-Use Domain Names registry confirms `example`, `invalid`,
`local`, `localhost`, `onion`, and `test` as special-use names:
<https://www.iana.org/assignments/special-use-domain-names>.

The historical page's undelegated rows among ranks 1-300 are:

```text
27:internal
66:localdomain
67:azure-dns-info
106:lan
150:unifi
233:home
289:server
```

`arpa` is shown as delegated by ICANN but is infrastructure, not a normal
registrable public suffix. The source's `undelegated` classification is not
the same thing as IANA special-use status. Keep those dimensions separate in
the parser manifest.

The historical 301-1000 rows contain 28 A-label IDN strings, all represented in
ASCII Punycode, including `369:xn--p1ai`, `620:xn--p1acf`,
`691:xn--fiqs8s`, `758:xn--90ais`, `783:xn--6frz82g`, `786:xn--55qx5d`,
`801:xn--j1amh`, `805:xn--80asehdb`, `806:xn--h2brj9c`,
`807:xn--ses554g`, `809:xn--3ds443g`, `812:xn--80adxhks`,
`819:xn--3e0b707e`, `832:xn--io0a7i`, `838:xn--o3cw4h`,
`866:xn--mk1bu44c`, `885:xn--czru2d`, `887:xn--t60b56a`,
`894:xn--6qq986b3xl`, `897:xn--80aswg`, `903:xn--5tzm5g`,
`911:xn--tckwe`, `924:xn--q9jyb4c`, `931:xn--j6w193g`,
`949:xn--czr694b`, `961:xn--d1acj3b`, `979:xn--kput3i`, and
`986:xn--90ae`. Preserve source labels exactly and normalize only
at a typed IDNA boundary; do not Unicode-normalize the manifest before hashing.

Several undelegated labels are ordinary-looking internal names or malformed
application/configuration strings, for example `306:null`, `333:https`,
`478:comhttp`, `610:html`, `849:gvc884571451de`, `879:getcacheddhcpresultsforcurrentconfig`,
`983:pdfpro`, and `995:hotspot-50`. This confirms that DNS Magnitude rows
are observed query TLD strings, not registration candidates. Such rows should
remain source evidence and should not create WHOIS parser mappings unless a
separate delegation and authoritative WHOIS source is verified.

## Non-equivalent historical API check

The ICANN Name Collision Observatory API exposes historical magnitude data for
individual labels at <https://newgtldprogram-nco-api.icann.org/api/v1/observatory/dashboard/magnitude>.
Its `authoritative` data for 2026-09-12 does **not** reproduce the L-root page
used by the repository: for example, it returns `io` at rank 8 and `xyz` at
rank 7, while the repository's pinned 2026-09-12 L-root sequence is `io` rank
7 and `xyz` rank 8. Its `com` query volume also differs from the direct page.
It was therefore excluded from the source manifest and must not be used as a
silent historical substitute.

## Verification status

* Ranks 1-300: verified against the repository's pinned canonical digest.
* Ranks 301-1000 for 2026-09-12: verified from ICANN's historical HTML and
  digest recorded above.
* Current ICANN 2026-09-13 ranks 301-1000: checked only to confirm daily
  rollover; its digest is explicitly excluded from the target manifest.
* Parser implementation, README, CHANGELOG, and version files: unchanged by
  this verification.
