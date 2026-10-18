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
The focused parser examples pass 40 cases. The full suite passes 7,024 examples
with 0 failures on Ruby 3.2.2 and 3.4.5, and the package smoke check passes on
both versions. These fixtures do not establish broad or traffic-weighted live
coverage.
