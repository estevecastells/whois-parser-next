# Guatemala registry web WHOIS evidence (2026-10-19)

**Production validation passed (2026-10-19 UTC).** The application-facing
route was verified on active production build
`cdc6fc3a59ec0a12d2f6c8e0ac6ebf226d5c4705` with parser 0.4.7; deployment
workflow [39193322142](https://github.com/estevecastells/domscan/actions/runs/39193322142)
completed successfully. The public web WHOIS controls and relay classifications
are summarized below.

## Source and provenance

The [official .gt registry](https://www.gt/sitio/) identifies the Universidad
del Valle de Guatemala (UVG) as the administrator of `.gt`. The public
[WHOIS result page](https://www.gt/sitio/whois.php?dn={domain}) accepts a
domain through the `dn` query parameter and returns an HTML result. The
registry's [registration policy](https://www.gt/sitio/registration_policy.php?lang=en)
describes the public WHOIS fields and says searches are limited to individual
domain names rather than lists of registered names. IANA's [`.gt` root-zone
entry](https://www.iana.org/domains/root/db/gt.html) lists no WHOIS server or
RDAP base URL. This evidence supports the published web lookup only; it makes
no TCP/43 or RDAP claim.

## Bounded observations

On 2026-10-19 UTC, bounded GET requests to
`https://www.gt/sitio/whois.php?dn={domain}` returned HTTP 200 with the
following registry results:

- `google.gt` and `google.com.gt` returned one result heading whose text was
  `{domain}. ACTIVO`.
- Generated eight-letter negative names under `.gt` and `.com.gt` returned an
  `alert alert-danger` block containing
  `<strong>{domain}.</strong> no est&aacute; registrado .`.

Measured responses were 2.02 seconds for a negative `.gt` lookup, 2.52 seconds
for registered `google.com.gt`, and 1.96 seconds for a negative `.com.gt`
lookup. No actual negative-name values are included in this report.

The returned page contained a global reCAPTCHA script, but the observed result
markup contained the requested WHOIS result and no CAPTCHA widget or
`data-sitekey`. The result was read as returned; no CAPTCHA was solved or
bypassed.

## Parser and test evidence policy

The `.gt` parser scans HTML tokens in one forward pass and reads only result
headings and qualifying alert blocks. It ignores script and style contents,
comments, and unrelated page text. Registration requires one valid result
heading ending in `ACTIVO`; absence requires one alert containing the exact
domain and absence marker. Duplicate, contradictory, malformed, incomplete, or
non-matching result blocks remain unknown. Challenge, denial, and throttle
responses are not classified as absence. The relay must also require the
parsed domain to match the submitted query.

Only status and domain identity are parsed. Contact blocks and dates are not
normalized or inferred. Parser regressions use minimal synthetic inline HTML
with generated example names; no captured registry response, registrant
contact, or date is included in the repository.

The observed source latency informed a bounded route budget; it is not a
reliability guarantee. On the active production build, registered and absent
v1/v2 controls for both `.gt` and `.com.gt` returned HTTP 200 from the official
WHOIS source and were classified correctly. All eight checks completed between
03:18:08 and 03:18:49 UTC on 2026-10-19. This validates paired capability for
these controls, not continuous availability or historical accuracy. The
[remaining-extension audit](domscan-whois-remaining-extensions-2026-10-19.md)
records the aggregate coverage result and the other namespaces still outside
the paired numerator.
