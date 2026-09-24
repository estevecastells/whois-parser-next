# ICANN DNS Magnitude snapshot manifest

`icann-dns-magnitude-20260912-ranks-1-1000.csv` is the repository-owned,
machine-readable manifest for source ranks 1 through 1,000 in the ICANN DNS
Magnitude historical snapshot:

- Source: <https://magnitude.research.icann.org/historic/20260912.full.html>
- Snapshot date: 2026-09-12
- Generated date stated by the source: 2026-09-18
- Retrieved: 2026-09-19

The source page contains more than the manifest range. The CSV preserves the
source rank and label exactly for ranks 1 through 1,000 and records the source
row classification as `delegated`, `special-use`, or `undelegated`. For
undelegated rows, the source identifies the classification on the table row
while its display cell is empty; the manifest records that source
classification without inferring a different status.

The canonical SHA-256 is calculated over UTF-8 lines in source-rank order,
using `source_rank:tld\n` for each CSV row and excluding the header:

```
6f1411e1323ed09683480b47314188c71c19d62979d2d7cc2894669b4dd9e681
```

The first 300 rows retain the previously pinned digest:

```
3f30997fd02e9481a316f2eaee541143b16cb445198cbf35956f5ae1c5950b62
```

The manifest has no unresolved rank or label ambiguity. The audit spec
verifies contiguity, uniqueness, classifications, and both digests.

The static 301-1000 WHOIS inventory and five-package ownership plan lives in
[`whois-parser-top1000-planning.csv`](whois-parser-top1000-planning.csv). Its
server columns come from the locked `whois` 6.0.3 definitions, and its parser
columns come from the current parser tree. See the accompanying
[`whois-parser-top1000-work-packages-2026-09-19.md`](../whois-parser-top1000-work-packages-2026-09-19.md)
for state definitions and implementation boundaries.
