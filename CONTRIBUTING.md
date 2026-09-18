# Contributing to whois-parser-next

Thank you for helping maintain `whois-parser-next`. The project is sponsored
and supported by [DomScan](https://domscan.net/whois-api), but it is an independent
community project. Contributions are welcome from everyone who treats
maintainers, users, and other contributors with respect.

WHOIS behavior changes over time. Reliable evidence and focused pull requests
help us keep the parser useful.

## Getting started

Fork and clone the repository, then install its dependencies:

```shell
git clone git@github.com:your-username/whois-parser-next.git
cd whois-parser-next
bundle install
```

Create a focused branch, add fixtures and tests with your change, then run:

```shell
bundle exec rspec
```

Open a pull request against
[`estevecastells/whois-parser-next`](https://github.com/estevecastells/whois-parser-next/compare/).

## Pull request rules

Please follow these rules for every behavior change:

1. Keep one focused registry or server-family change per pull request.
2. Add exact, current raw-response fixtures for registered and
   likely-unregistered cases where applicable.
3. Never include personal registrant data in fixtures. If a current response
   contains personal data, provide a minimally redacted fixture that preserves
   the parser-relevant structure and document the redaction.
4. Never interpret rate limits, blocks, timeouts, malformed responses, or
   ambiguous responses as either available or absent. Unknown must remain
   unknown.
5. Add tests for every behavior change, including successful parsing, expected
   absence, errors, and important unknown states.
6. Document the date of live verification and the source or server used.
7. Do not add paid, private, authenticated, or otherwise inaccessible source
   dependencies.
8. Preserve the existing loading path and public API where possible. Discuss
   proposed breaking changes in an issue before opening the implementation PR.
9. Run the full test suite before requesting review and report the result in the
   pull request.
10. Keep changes understandable and avoid unrelated cleanup in a focused pull
    request.

A parser result is not an availability guarantee. Registry policy, rate limits,
server changes, and the distinction between WHOIS and RDAP all matter.

## Fixtures and privacy

Fixtures should represent current server behavior, not invented examples. Do
not commit names, email addresses, telephone numbers, postal addresses, or
other personal registrant information. Preserve the fields and response
structure needed to reproduce the behavior while removing personal data.

Never commit credentials, private endpoints, paid-service responses, or data
that you are not allowed to redistribute.

## Licensing

Contributions are made under the MIT license. This project does not require a
Contributor License Agreement. By submitting a contribution, you confirm that
you have the right to submit it under those terms.

## Review

Maintainers may request narrower scope, stronger evidence, additional fixtures,
or clearer handling of unknown results. Review is about correctness, evidence,
privacy, compatibility, and maintainability.

Please follow the project's [Code of Conduct](CODE_OF_CONDUCT.md).
