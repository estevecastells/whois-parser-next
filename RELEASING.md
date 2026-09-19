# Releasing whois-parser-next

Releases are made from a reviewed commit on `main` and published to RubyGems
through GitHub's trusted-publishing flow. Maintainers must not add a long-lived
RubyGems API key to the repository or its Actions secrets.

## Before tagging

1. Confirm the version in `lib/whois/parser/version.rb` and prepare a dated
   changelog entry.
2. Run the complete test suite with `bundle exec rspec`.
3. Run `./script/package-smoke` and inspect the built gem's file list.
4. Confirm the GitHub Actions matrix passes on every supported Ruby version.
5. Confirm the RubyGems trusted publisher names this repository,
   `.github/workflows/release.yml`, and the `release` environment.
6. Review the diff from the previous release for fixtures containing personal
   data, credentials, or unneeded registry response content.

## Publish

Create and push the annotated release tag only after the checks above pass:

```shell
git tag -a v0.1.0 -m "whois-parser-next 0.1.0"
git push origin v0.1.0
```

The release workflow repeats the full suite and package smoke test before it
requests a short-lived RubyGems publishing credential through OIDC.

## Verify

After the workflow succeeds:

1. Confirm the version and metadata on RubyGems.
2. Install the released gem into an empty gem home.
3. Verify `require "whois-parser"` and `Whois::Parser`.
4. Parse at least one registered and one available fixture.
5. Publish release notes that describe only tested behavior.

If a release is wrong, stop downstream upgrades and document the issue before
yanking. A yank does not remove code already downloaded by users, so follow it
with a corrected release and a clear changelog entry.
