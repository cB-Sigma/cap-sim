# cap-sim

A simulated Common Alerting Protocol (CAP) feed server and receiver, as a Go package and a command.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/cap-sim.svg)](https://pkg.go.dev/github.com/cB-Sigma/cap-sim) [![test](https://github.com/cB-Sigma/cap-sim/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/cap-sim/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

It lets a CAP reader or publisher be tried without a real alerting
authority. It is built on [cap](https://github.com/cB-Sigma/cap).

## What is simulated

| Part | Behaviour |
|---|---|
| Feed server | serves `/feed` as Atom with embedded alerts (`AtomEmbedded`), Atom linking to the documents (`AtomLinked`), RSS 2.0 linking to them (`RSSLinked`), an EDXL-DE 1.0 or 2.0 envelope embedding them (`EDXLEmbedded`, `EDXL2Embedded`) or the newest alert alone (`BareAlert`); the documents at `/docs/<n>.xml`, and in JSON at `/docs/<n>.json`; over HTTPS with `NewFeedTLS`; Atom paged by `PageSize` with RFC 5005 next links; Update and Cancel chains (`Update`, `Cancel`); newest first; `ETag` and `Last-Modified`, 304 for a matching `If-None-Match` or an `If-Modified-Since` not older than the last change; signs the alerts it is given with `SetSigner`; can be set down (503); counts feed requests, 304 answers and document GETs |
| Receiver | accepts CAP documents by `POST /cap` (over HTTPS with `NewReceiverTLS`) with `Content-Type: application/cap+xml`; optional bearer token (401 without it); with `SetVerifier`, refuses unsigned (when required) or tampered alerts (403) and keeps the verified alert; refuses malformed (400) and invalid (422) alerts, invalid under `SetProfiles` too; `Refused` says why; can fail the next n posts or stay down (503); keeps the valid alerts and their raw bodies |

| Certificate authority | `NewCA` issues signing certificates that name its CRL and OCSP responder, serves both, and revokes on request (`Revoke`), so revocation checks can be tried end to end |

Not simulated: the NAAD System's TCP stream (capnet's tests serve a
local one) and IPAWS-OPEN.

## Install

```
go get github.com/cB-Sigma/cap-sim@latest
go install github.com/cB-Sigma/cap-sim/cmd/capsim@latest
```

Requires Go 1.27.1 or later.

## Command

```
capsim feed|receiver [-listen addr] [-format atom|atom-linked|rss|edxl|edxl2|bare] [-token t] [-profile CAP-CP|IPAWS|India]
```

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `127.0.0.1:8098` | address to listen on |
| `-format` | `atom` | feed: `atom` (embedded alerts), `atom-linked`, `rss`, `edxl` (an EDXL-DE 1.0 envelope), `edxl2` (EDXL-DE 2.0) or `bare` (the alert alone) |
| `-token` | none | receiver: bearer token required |
| `-profile` | none | receiver: also refuse alerts with errors under this profile |

The feed holds one demo alert. The receiver prints each valid alert it
receives. Both run until interrupted. Output observed:

```
$ capsim feed -listen 127.0.0.1:18098 -format rss
capsim feed at http://127.0.0.1:18098/feed

$ curl -s http://127.0.0.1:18098/feed
<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Simulated CAP feed</title><item><title>alert 0</title><link>/docs/0.xml</link><guid>SIM-0001</guid><pubDate>Sun, 11 Oct 2026 08:53:39 +0000</pubDate></item></channel></rss>
```

```
$ capsim receiver -listen 127.0.0.1:18099 -token demo-token
capsim receiver at http://127.0.0.1:18099/cap
received Alert SIM-0001 from capsim@example.test
```

The last line followed a POST of the feed's document:

```
curl -X POST -H "Content-Type: application/cap+xml" -H "Authorization: Bearer demo-token" \
  --data-binary @alert.xml http://127.0.0.1:18099/cap
```

## In Go tests

```go
import (
	"github.com/cB-Sigma/cap"
	"github.com/cB-Sigma/cap-sim/sim"
)

feed := sim.NewFeed(sim.AtomEmbedded) // on a loopback port
defer feed.Close()
feed.Add(alert)                       // a *cap.Alert
resp, err := http.Get(feed.URL())
// ... cap.ParseFeed(body) returns the entry with the alert embedded

rc := sim.NewReceiver("demo-token")
defer rc.Close()
// POST a CAP document to rc.URL() with the bearer token, then:
msgs := rc.Messages() // the valid alerts received, in order
```

This mirrors the runnable `Example` in sim/sim_test.go. `NewFeedAt` and
`NewReceiverAt` listen on a given address; `Feed.SetDown`,
`Receiver.FailNext` and `Receiver.SetDown` inject failures;
`Feed.SetSigner`, `Receiver.SetVerifier` and `Receiver.SetProfiles` try
signatures and profiles end to end (`TestSignedFeedAndCheckingReceiver`).

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/cap-sim

| Package | What it does |
|---|---|
| `sim` | `Feed` (`NewFeed`, `NewFeedAt`, `Add`, `AddRaw`, `SetSigner`, `SetDown`, `Stats`) and `Receiver` (`NewReceiver`, `NewReceiverAt`, `Messages`, `Raw`, `Refused`, `SetVerifier`, `SetProfiles`, `FailNext`, `SetDown`) |
| `cmd/capsim` | the command above |

## Testing

```
go test -race ./...
```

## Demo values

Every alert, sender, identifier, area, address and token in this module
(such as `SIM-0001`, `capsim@example.test` and `demo-token`) is a made-up
demo value. There are no real keys or credentials.

## Related repositories

- [cap](https://github.com/cB-Sigma/cap): the CAP 1.2 library this
  simulator is built on.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam. Not affiliated with or endorsed by OASIS; see NOTICE.
