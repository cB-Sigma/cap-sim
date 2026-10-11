# Provenance

## How the code was written

Written in Go for SigmaM2M, a oneM2M platform, as the test peer of its CAP
integration and of the cap module. No code was ported or copied from
another implementation. The simulator began in SigmaM2M's CAP
integration, moved into the cap module on 2026-10-06 (where `NewFeedAt`,
`NewReceiverAt` and the `capsim` command were added), and moved into this
module on 2026-10-11 so that the library does not depend on it. The
package's own tests (sim/sim_test.go) were added then; before that it was
exercised through the command's tests and SigmaM2M's integration tests.

The feed forms follow what CAP publishers serve: Atom entries that embed
the alert, Atom entries that link to it, and RSS 2.0 items that link to
it (the form used by some national alerting feeds, such as India's
SACHET). The receiver follows the usual way of delivering CAP by HTTP
POST with a bearer token.

v0.2.0 (2026-10-11) added the EDXL-DE feed form, If-Modified-Since,
signing feeds (`SetSigner`) and checking receivers (`SetVerifier`,
`SetProfiles`, `Refused`), all through the cap module's own functions,
and the `-format edxl` and `-profile` flags of the command.

## Sources

| Area (files) | Followed |
|---|---|
| Alerts, signatures, profiles (through the cap module) | OASIS CAP 1.2 and the documents listed in the cap module's PROVENANCE.md, facts only |
| Feeds (sim/sim.go) | RFC 4287 (Atom), RSS 2.0, OASIS EDXL-DE 1.0 (element names) |
| HTTP caching (sim/sim.go) | RFC 9110 and RFC 9111: ETag, If-None-Match, Last-Modified, If-Modified-Since, 304 |

No text of these documents is reproduced.

v0.3.0 (2026-10-12) added more.go and v030_test.go, written for this
module, from RFC 5005 (feed paging), RFC 5280 (certificate revocation
lists, CRL distribution points), RFC 6960 (OCSP; requests and responses
through golang.org/x/crypto/ocsp) and EDXL-DE 2.0 (through cap's
`WriteEDXLDE2`), used as facts.

## Test data

The demo alert (SIM-0001 from capsim@example.test over "Demo district"),
the identifiers, senders, areas and tokens in the tests are made up; keys
and certificates are generated at run time.
