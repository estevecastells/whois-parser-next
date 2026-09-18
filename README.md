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

The current development gem name is `whois-parser-next`. It has not yet been
published to RubyGems.

## Compatibility

The compatibility target is the existing `whois-parser` loading path and
namespace:

```ruby
require "whois-parser"

Whois::Parser
```

Existing applications can retain `require "whois-parser"` and their
`Whois::Parser` integrations while changing the dependency source:

```ruby
gem "whois-parser-next",
  github: "estevecastells/whois-parser-next",
  require: "whois-parser"
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

## License and attribution

This project continues work derived from the MIT-licensed
[`weppos/whois-parser`](https://github.com/weppos/whois-parser) project.

Original author: Simone Carletti (`weppos`)

Original project: <https://github.com/weppos/whois-parser>

See [LICENSE.txt](LICENSE.txt) and the retained attribution notices for the
applicable terms. New contributions remain available under the MIT license.
