# `.cam` current WHOIS evidence follow-up for rank 315

Date: 2026-09-25

## Scope and source

The pinned ICANN DNS Magnitude snapshot ranks `.cam` at 315. The current
[IANA delegation record](https://www.iana.org/domains/root/db/cam.html) lists
`whois.nic.cam` as its WHOIS server and `https://rdap.centralnic.com/cam/` as
its RDAP server. The locked `whois` 6.0.3 client selects a standard WHOIS
adapter at `whois.nic.cam` for `google.cam`.

## Bounded evidence and terms

On 2026-09-25, one bounded TCP port-43 query to the IANA-listed WHOIS host for
`google.cam` parsed as `:registered`. After at least two seconds, one
syntactically valid generated-name query for `codex-r301450-20260925.cam`
parsed as `:available` from the registry's authoritative missing-name result.
The sanitized, parser-relevant response hashes are:

| Query shape | Parser outcome | Sanitized response SHA-256 |
| --- | --- | --- |
| Registered domain `google.cam` | `:registered` | `82308de3daf2eeef6841f7320354078c977e34499b6410708db10e3229f5d764` |
| Generated name `codex-r301450-20260925.cam` | `:available` | `8d411c487ce19878d933e3a2b5add8f0ecb00a805eb3475857d393ace95a87dd` |

The limits were a four-second connection timeout, seven-second response
deadline, 64 KiB response cap, and at least two seconds between requests.
Contact data and registry footer text were not retained. CentralNic's
[published WHOIS/RDAP terms](https://whois.centralnicregistry.com/rdap) prohibit
storing or reproducing service data; no affirmative `.cam`-specific permission
was found, so response text and fixtures are deliberately omitted. The test
suite only asserts the IANA-listed default route here; its existing generic
package-3 fixtures cover the shared parser markers. This row-specific pair
is a point-in-time observation, not an independently reproducible parser
fixture: hashes cannot replay the response or independently validate parsing.
It supplements the package-3 collection-level evidence while keeping the
pinned baseline row state unchanged. It does not establish DomScan deployment
or broad effective coverage.
