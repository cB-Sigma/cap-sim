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

## Sources

| Area (files) | Followed |
|---|---|
| Alerts (through the cap module) | OASIS CAP 1.2, facts only |
| Feeds (sim/sim.go) | RFC 4287 (Atom), RSS 2.0 |
| HTTP caching (sim/sim.go) | RFC 9110 and RFC 9111: ETag, If-None-Match, Last-Modified, 304 |

No text of these documents is reproduced.

## Test data

The demo alert (SIM-0001 from capsim@example.test over "Demo district"),
the identifiers, senders, areas and tokens in the tests are made up.
