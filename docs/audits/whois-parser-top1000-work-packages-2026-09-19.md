# WHOIS parser top-1000 work packages

Date: 2026-09-19

## Scope and evidence boundary

This planning pass covers ICANN DNS Magnitude source ranks 301-1000 from the
repository-owned 2026-09-12 manifest. These are observed TLD strings, not a
list of registrable domains. The source rank, label, and source classification
are preserved exactly in
[`whois-parser-top1000-planning.csv`](data/whois-parser-top1000-planning.csv).

The server mapping columns are a static read of the locked `whois` 6.0.3 TLD
definitions in `Gemfile.lock`. The parser columns are a static read of the
current parser tree. No port-43 or web request was made, so
`parser_present_unverified` is an inventory state, not a claim that the
current response format is still safe. No parser implementation is included
in this planning change.

`Whois::Parsers::Blank` means that the current parser tree has no host-specific
class for the mapped host. `Unmapped` means the locked WHOIS definitions have
no entry for the source label. `None` and `Web` are kept distinct from
`Standard`: they do not provide a normal port-43 parser target for this work
package.

## Initial coverage states

| State | Meaning | Rows |
|---|---|---:|
| `parser_present_unverified` | A host-specific parser class exists, but this static pass did not validate current responses | 87 |
| `parser_missing` | A WHOIS host is mapped, but the parser resolves to `Blank` | 422 |
| `adapter_none_excluded` | The locked server definition uses the `None` adapter; do not invent port-43 support | 36 |
| `web_adapter_excluded` | The locked server definition is web-only; preserve the URL as metadata, but do not probe it in this pass | 3 |
| `no_server_mapping` | The delegated source label has no locked WHOIS server definition | 6 |
| `excluded_undelegated` | ICANN marks the source string undelegated; classification only | 143 |
| `excluded_special_use` | ICANN marks the source string special-use; classification only | 3 |

The seven states account for all 700 rows. An excluded row remains in a
package so the source sequence is complete, but it is not an implementation
target.

## Five implementation packages

The packages contain 140 rows each. Assignment is deterministic: shared
parser families are grouped first, then shared non-empty WHOIS hosts, and
remaining rows are assigned as single-row groups to the smallest package.
This makes the rank ranges intentionally non-contiguous while preventing a
shared host or parser family from being split.

| Package | Rows | Delegated | Existing parser, unverified | Parser missing | Classification/exclusion rows |
|---|---:|---:|---:|---:|---:|
| `package-1` | 140 | 117 | 38 | 65 | 37 |
| `package-2` | 140 | 109 | 23 | 78 | 39 |
| `package-3` | 140 | 108 | 0 | 102 | 38 |
| `package-4` | 140 | 110 | 17 | 84 | 39 |
| `package-5` | 140 | 110 | 9 | 93 | 38 |

The `resource_group` column records the unit that must stay together. A later
implementation pass can split each package into 25-rank audit reports while
retaining this ownership assignment.

## Shared ownership

The following shared WHOIS hosts are each owned by one package:

| Package | Shared hosts |
|---|---|
| `package-1` | `whois.afilias-srs.net`, `whois.uniregistry.net` |
| `package-2` | `whois.afilias.net` |
| `package-3` | `whois.nic.google`, `whois.teleinfo.cn` |
| `package-4` | `whois.gtlds.nic.br`, `whois.ngtld.cn`, `whois.publicinterestregistry.net` |
| `package-5` | `whois.aridnrs.net.au`, `whois.gtld.knet.cn`, `whois.mediaserv.net`, `whois.online.rs.corenic.net`, `whois.ryce-rsp.com` |

Shared parser families are also kept together: `BaseIcannCompliant` in
`package-1`, `BaseAfilias2` in `package-2`, `Base`/`BaseNicFr`/`WhoisCentralnicCom`
in `package-4`, and `BaseAfilias`/`BaseCocca2`/`BaseShared2` in `package-5`.
Single-row families are recorded in the CSV and remain owned by their package.

## Explicit classification-only buckets

- Special-use rows are ranks 363 (`onion`), 365 (`localhost`), and 375
  (`test`). They are not parser targets.
- The 143 undelegated rows remain source evidence only, including malformed or
  configuration-derived strings such as `null`, `https`, and `comhttp`.
- Web-only definitions are rank 575 (`bm`), rank 675 (`bb`), and rank 926
  (`gw`). Their locked definition URLs are recorded in `server_url`; they were
  not fetched.
- Delegated rows without a locked server mapping are `gay`, `music`, `kids`,
  `cpa`, `spa`, and `xn--czr694b`.
- `adapter_none_excluded` rows are retained as a separate state even when the
  definition includes a host. A host string alone is not permission to invent
  transport or parser behavior.

## Verification

`spec/whois/parsers/top1000_planning_spec.rb` proves that the CSV contains
every rank 301-1000 exactly once, has five 140-row packages, keeps each
non-empty WHOIS host in one package, keeps non-Blank parser families together,
and isolates special-use, undelegated, and web-only rows. It is intentionally
static and does not perform network probes.
