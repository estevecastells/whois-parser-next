# whois-parser-next

`whois-parser-next` is an independent, community-maintained successor to
[`weppos/whois-parser`](https://github.com/weppos/whois-parser).

The original project was created and maintained by Simone Carletti, known as
`weppos`, together with its contributors. We are grateful for that work and
for the foundation it provides. This project preserves the original MIT
license heritage, attribution, notices, and Git history while continuing
development under a new name.

This project is independent and is not affiliated with or endorsed by Simone
Carletti or `weppos`.

[![Tests](https://github.com/estevecastells/whois-parser-next/actions/workflows/tests.yml/badge.svg)](https://github.com/estevecastells/whois-parser-next/actions/workflows/tests.yml)

## Sponsored and supported by DomScan

`whois-parser-next` is sponsored and supported by
[DomScan](https://domscan.net/whois-api), which uses domain intelligence in production
and helps fund maintenance, testing, and registry-format research.

The project remains independent from DomScan and independent from the original
`weppos/whois-parser` maintainer. DomScan sponsorship does not imply
endorsement by Simone Carletti or `weppos`, and it does not give any sponsor
the right to influence parser results.

WHOIS formats drift. Parsers should keep up.

Project owner and lead maintainer:
[Esteve Castells](https://github.com/estevecastells). See
[MAINTAINERS.md](MAINTAINERS.md) and [GOVERNANCE.md](GOVERNANCE.md).

## Status

The project is under active development. The initial focus is reliable parsing
of current WHOIS responses, explicit unknown states, registry-specific
fixtures, and safe handling of malformed, rate-limited, retired, or changed
server responses.

The current source version is `0.3.1`. Check the [RubyGems project
page](https://rubygems.org/gems/whois-parser-next) for its publication status
and the latest published version.

## Compatibility

The compatibility target is the existing `whois-parser` loading path and
namespace:

```ruby
require "whois-parser"

Whois::Parser
```

Existing applications can retain `require "whois-parser"` and their
`Whois::Parser` integrations. To install version 0.3.1, pin it as follows:

```ruby
gem "whois-parser-next", "= 0.3.1", require: "whois-parser"
```

## Requirements

- Ruby 3.2 or newer

## Scope

The project parses and normalizes WHOIS responses. It does not guarantee domain
availability. Registry policies, server responses, rate limits, endpoint
changes, and the distinction between WHOIS and RDAP can all affect the result.

Unknown, malformed, unsupported, rate-limited, and ambiguous responses must
remain distinguishable from an authoritative availability result.

## Development

```shell
bundle install
bundle exec rspec
```

## Coverage evidence

The [2026-09-25 scorecard](docs/audits/top-1000-effective-coverage-scorecard-2026-09-25.md)
summarizes evidence for 1,000 observed TLD strings from the
[ICANN DNS Magnitude snapshot dated 2026-09-12](https://magnitude.research.icann.org/historic/20260912.full.html).
These strings are not 1,000 guaranteed working WHOIS registries or
domain-availability results. Its strict paired count is pinned to baseline
`f2c822c`, excludes the Top 100 whose summary labels do not expose row-level
evidence pairs, and does not claim an effective-coverage percentage. The
scorecard keeps verified parser evidence, explicit unavailable or unsupported
responses, unknown or unresolved endpoints, and classification-only rows
distinct. Later `.uz`/`.sa` paired evidence and `.pk`/`.ge` parsers are
follow-ups, not changes to the pinned scorecard counts. The `.pk` parser does
not make the default `whois` 6.0.3 Web adapter use port 43; `Whois::Client`
host configuration does not override that adapter. The `.ge` parser targets
IANA's `whois.nic.ge`, while the default `whois` route is
`whois.registration.ge`. Both require explicit fixed-host routing before an
application can count them as effective coverage.

Start with the [source verification report](docs/audits/top-1000-source-verification-2026-09-19.md),
the [Top 20 review](docs/audits/top-20-tlds-2026-09-19.md), and the [Top 100
audit](docs/audits/top-100-tlds-2026-09-19.md). The same directory contains
the contiguous reports for ranks 101 through 300, the [301-1000 work-package
plan](docs/audits/whois-parser-top1000-work-packages-2026-09-19.md), and the
five package audit reports. Each report preserves the evidence boundary and
does not turn unavailable, unsupported, unresolved, or classification-only
rows into availability claims.

## Join the work

We want this to be useful to people who maintain domain tools, registry
integrations, security services, and developer libraries. Small, focused
contributions are welcome. You do not need to be a long-time Ruby contributor
or a WHOIS expert to help.

Useful contributions include current registry fixtures, parser corrections,
tests, documentation, and careful reports of changed server behavior. If you
are unsure whether an observation is a bug, open an issue with the TLD, source,
date, sanitized response shape, and expected interpretation. We would rather
help shape an investigation than lose a useful report because it was not
perfectly packaged.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
The [public roadmap](ROADMAP.md) lists current priorities, non-goals, and the
evidence gate for any optional Rust work.
Maintainers should also follow [RELEASING.md](RELEASING.md), including the
package smoke test and trusted-publishing checks.

## License and attribution

This project continues work derived from the MIT-licensed
[`weppos/whois-parser`](https://github.com/weppos/whois-parser) project.

Original author: Simone Carletti (`weppos`)

Original project: <https://github.com/weppos/whois-parser>

See [LICENSE.txt](LICENSE.txt) and the retained attribution notices for the
applicable terms. New contributions remain available under the MIT license.
