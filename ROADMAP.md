# Roadmap

This roadmap is a direction, not a promise of dates. Registry behavior changes
without notice, so correctness and current evidence take priority over a fixed
feature calendar.

## Current release

- Published `whois-parser-next` 0.2.0 to RubyGems, retaining the established
  `require "whois-parser"` and `Whois::Parser` compatibility.
- Completed the audit of 1,000 observed TLD strings from the ICANN DNS Magnitude
  snapshot dated 2026-09-12. These rows are ranked TLD strings, not 1,000
  confirmed working WHOIS registries or domain-availability results.
- Kept verified parser evidence, unavailable or unsupported responses,
  unresolved endpoints, and classification-only rows distinct.

## Next priorities

1. Refresh the existing 1,000-row cohort only against a new, dated source
   snapshot, keeping each snapshot's ranks and labels separate.
2. Close parser evidence gaps for mapped official WHOIS hosts with bounded
   probes and sanitized fixtures for exact response behavior. DNS failures,
   timeouts, unsupported replies, and ambiguous responses remain unresolved or
   unavailable.
3. Add or change parser behavior only when current response evidence is backed
   by a regression spec; do not infer one host's behavior for unmapped or
   unverified TLDs.
4. Scope any expansion beyond rank 1,000 from a separately documented dataset
   before treating it as parser-coverage work.
5. Reduce avoidable runtime dependencies and improve contributor tooling for
   fixture privacy, server-mapping drift, and response-safety checks.

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
