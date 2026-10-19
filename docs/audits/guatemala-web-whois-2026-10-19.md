# Guatemala registry web WHOIS evidence (2026-10-19)

**Production validation pending.** This report documents the public registry
source and the observed response shapes. It does not establish that an
application deployment or application-facing route has been validated.

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
reliability guarantee. Application-level production validation remains
pending.
