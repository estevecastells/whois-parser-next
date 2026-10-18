# DomScan WHOIS response fixtures (2026-10-18)

These fixtures preserve only the technical fields needed to test `.ma` active
registration and `.sh` registered and absent response markers. Public queries
were made on 2026-10-18 UTC through the official WHOIS hosts listed by IANA:
[`whois.registre.ma`](https://www.iana.org/domains/root/db/ma.html) and
[`whois.nic.sh`](https://www.iana.org/domains/root/db/sh.html). Registre.ma
defines its `Active` status as registered and declared in DNS and WHOIS
([status definitions](https://www.registre.ma/language/en/domain-name/e-statuts)).

The `.ma` fixture retains the public technical fields for `registre.ma`:
domain name, update, creation and expiry dates, and active status. Its retained
source response was 1,346 characters with SHA-256
`6c016bc949c8d808141cc6c5978ec4deeddf2edeb7baa4ce13db3f2d1b495179`.
The `.sh` registered fixture retains 13 technical header lines from the
`nic.sh` response. Its 2,048-character retained preview has SHA-256
`082abb2b3cbb5bfdc10349e58d2cb3831298a68dae93ff7fa52a18eb2bd70d4f`; the
preview may be truncated. The `.sh` absence fixture retains the exact first
line `Domain not found.` from a 2,048-character preview with SHA-256
`36307369cb31a25a742a6f99bd837a3b1feb76012badb8221ec5f5341a8fad24`; this
preview may also be truncated. These hashes identify the retained upstream
captures, not the reduced fixture files, and the `.sh` hashes are not digests
of complete responses.

Contact details and full registry terms were omitted. The `.sh` response's
`Registry Domain ID: REDACTED` field was already redacted upstream; no
synthetic registered identity was added. Synthetic ambiguity and denial
examples in the parser spec are negative controls, not captured responses.
At the 0.4.2 checkpoint, its focused examples passed 40 cases and the full
suite passed 7,024 examples with 0 failures on Ruby 3.2.2 and 3.4.5; package
smoke passed on both versions. Those results do not establish broad or
traffic-weighted live coverage.

## Additional current formats (2026-10-18 UTC)

The `.ki`, `.bi`, and `.ci` subdirectories contain intentionally synthetic
CoCCA technical-shape controls using `example.<suffix>`. Registry terms
restrict redistribution of captured registration records, so these files are
not copies of live responses and do not claim exact record provenance. They
exercise single-domain identity, current EPP status links, standalone absence
markers, and ambiguity handling. IANA lists the hosts as
[`whois.nic.ki`](https://www.iana.org/domains/root/db/ki.html),
[`whois1.nic.bi`](https://www.iana.org/domains/root/db/bi.html), and
[`whois.nic.ci`](https://www.iana.org/domains/root/db/ci.html).

The `.ax` files are reduced public-response excerpts: the registered case
keeps three dotted technical fields for `nic.ax`, and the absent case keeps
the exact `Domain not found` marker. IANA lists [`whois.ax`](https://www.iana.org/domains/root/db/ax.html).
The `.ls` files retain only `domain`, `registered`, and `expire` fields for
`nic.ls`, plus the exact generated-query absence marker; IANA lists
[`whois.nic.ls`](https://www.iana.org/domains/root/db/ls.html). Personal
contact information and full response terms are omitted from these reduced
excerpts.

The 0.4.3 focused examples pass 84 cases. Its full suite passes 7,040 examples
with 0 failures on Ruby 3.2.2 and 3.4.5; package smoke passes on both and
loads every packaged parser. The 633-file gem includes the CoCCA helper and
`.ls` parser and has no native extensions. Supported-Ruby CI passed on Ruby
3.2, 3.3, 3.4, and 4.0.7 for implementation commit
`7b32576500609aecd8f69b9ae7941bdd41213647` (run 39172234679). The fixtures do
not establish broad or traffic-weighted live coverage.

## Additional current hosts (2026-10-18 UTC)

The `.gh` and `.do` directories contain minimal synthetic CoCCA response-shape
controls based on current registered and absent queries to the public hosts
listed by IANA: [`whois.nic.gh`](https://www.iana.org/domains/root/db/gh.html)
and [`whois.nic.do`](https://www.iana.org/domains/root/db/do.html). The `.vu`
directory contains matching synthetic shape controls for the GoDaddy WHOIS
host `whois.dnrs.vu`, listed by [IANA](https://www.iana.org/domains/root/db/vu.html).
The registered examples use `example.<suffix>` placeholders; the absent
examples retain only the response marker needed by the parser. Live response
originals and real contact details are not redistributed or included.

These fixtures exercise current registration and absence shapes with strict
domain-identity checks. They do not establish broad or traffic-weighted live
coverage. Validation of the 0.4.4 changes, including full-suite, package-smoke,
and supported-Ruby CI checks, is pending.
