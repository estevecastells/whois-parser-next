# Roadmap

This roadmap is a direction, not a promise of dates. Registry behavior changes
without notice, so correctness and current evidence take priority over a fixed
feature calendar.

## Current release

- Establish a safe, maintained successor with Ruby 3.2 through Ruby 4 support.
- Audit the first 300 rows of a dated, reproducible TLD-usage snapshot.
- Replace unsafe fallback classifications with explicit unknown or unavailable
  outcomes when a response lacks authoritative evidence.
- Keep the gem compatible with `require "whois-parser"` and `Whois::Parser`.
- Publish through short-lived RubyGems trusted-publishing credentials.

## Next priorities

1. Continue evidence-backed TLD coverage in reproducible, non-overlapping
   batches.
2. Add regression fixtures when registries change format, server, policy, or
   availability wording.
3. Reduce avoidable runtime dependencies without changing public behavior.
4. Improve contributor tooling for fixture privacy, server-mapping drift, and
   ambiguous-response safety.
5. Document parser confidence and provenance without pretending that a parsed
   WHOIS response is an availability guarantee.

## Performance and Rust

The Ruby parser is already small compared with the network request that
produces a WHOIS response. We will profile real workloads before adding native
code or attempting a rewrite.

If parsing becomes a measured bottleneck, the preferred experiment is a small,
optional Rust-backed parser for one high-volume server family behind the
existing Ruby API. It must pass the same fixtures and differential tests as the
Ruby implementation. A full rewrite is not planned without evidence that it
would improve user-visible performance enough to justify the maintenance,
packaging, and compatibility cost.

## Non-goals

- Guessing availability from an empty, blocked, throttled, or malformed reply.
- Hiding registry limitations or converting unknown evidence into certainty.
- Adding paid, private, or authenticated data sources to the parser.
- Breaking the established Ruby API merely to modernize internal style.
- Combining WHOIS transport, RDAP policy, billing, or product-specific routing
  into this parsing library.

## How to help

Good first contributions include a current sanitized fixture, a focused parser
regression, a server-mapping correction, or an adversarial unknown-response
test. Larger proposals should start in a public issue so contributors and
maintainers can agree on the evidence, compatibility boundary, and test plan
before implementation.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the rules and
[GOVERNANCE.md](GOVERNANCE.md) for how decisions are made.
