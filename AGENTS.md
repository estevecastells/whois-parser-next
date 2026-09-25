# Agent guide for whois-parser-next

This is an independent, community-maintained Ruby WHOIS parser sponsored by
DomScan. Keep the original project's attribution and MIT notices intact. Read
`CONTRIBUTING.md` before changing behavior, `SECURITY.md` for vulnerability
reports, and `RELEASING.md` before any release. Those documents contain the
full procedures; this guide records the working invariants.

## Scope and compatibility

- Put reusable WHOIS response parsing here, not in a downstream application's
  local patch. Applications still own transport, endpoint routing, RDAP policy,
  and product-specific decisions.
- Preserve `require "whois-parser"`, the `Whois::Parser` API, and Ruby 3.2+
  compatibility. Discuss breaking changes before implementing them.
- Do not add Rust or other native code without an explicit maintainer decision
  backed by a reproducible, user-relevant benchmark.
- Never turn an empty, blocked, throttled, denied, malformed, or ambiguous reply
  into `registered` or `available`. Unknown and unavailable are distinct from
  authoritative registration and absence.

## Evidence and fixtures

- Verify the current official WHOIS host and response semantics before adding a
  parser or marker. Use bounded, paced probes; stop on denial or rate limits.
  Do not work around registry access restrictions.
- Add exact, current registered and likely-unregistered response fixtures when
  permitted, plus tests for errors and unknown states. Redact personal data
  without losing parser-relevant structure. Never commit credentials, private
  responses, or registry material whose terms prohibit redistribution.
- A parser file, a host mapping, an RDAP result, or a single positive response
  does not prove effective WHOIS coverage. Keep dated observations and the
  pinned audit baseline separate. Read the current
  `docs/audits/top-1000-effective-coverage-scorecard-2026-09-25.md` and
  `docs/audits/data/README.md` before changing the top-1,000 ledger or CSV.

## Work and verification

- Preserve unrelated local changes. Keep changes focused and use a separate
  worktree when the checkout contains other work. Do not commit, push, tag,
  publish, or change downstream production unless the user asks.
- Place parser code under `lib/whois/parsers/` and matching regressions under
  `spec/whois/parsers/` where practical. Run focused specs, then the full
  `bundle exec rspec` suite for behavior changes. Run `./script/package-smoke`
  before a release and check the supported-Ruby CI matrix.
- Keep audit links and generated data consistent. Regenerate a ledger with its
  checked-in builder and run its audit spec when changing evidence; do not
  hand-edit a generated CSV. Keep `README.md` and `CHANGELOG.md` claims limited
  to verified outcomes.
