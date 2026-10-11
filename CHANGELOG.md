# Changelog

## v0.3.1 (2026-10-12)

- The repository no longer carries a compiled `capsim` binary, published by mistake in v0.3.0. No code changed.

## v0.3.0 (2026-10-12)

Needs github.com/cB-Sigma/cap v0.3.0. Added, all backwards compatible:

- Feed formats `EDXL2Embedded` (an EDXL-DE 2.0 envelope) and `BareAlert`
  (the newest alert alone); `capsim feed -format edxl2|bare`.
- Documents in JSON with CAP element names at `/docs/<n>.json`.
- HTTPS: `NewFeedTLS`, `NewReceiverTLS` and `Client` on both.
- Paging: `Feed.PageSize` pages an Atom feed with RFC 5005 rel="next"
  links (read by `capnet.Poller` with `MaxPages`).
- Update and Cancel chains: `Feed.Update`, `Feed.Cancel`.
- `CA`: a simulated certificate authority that issues signing
  certificates naming its CRL and OCSP responder, serves both, and
  revokes on request (`NewCA`, `Issue`, `Revoke`, `RootPEM`).

## v0.2.0 (2026-10-11)

Needs github.com/cB-Sigma/cap v0.2.0. Added, all backwards compatible:

- `EDXLEmbedded`: the feed as an EDXL-DE 1.0 envelope with one content
  object per alert; `capsim feed -format edxl`.
- `If-Modified-Since` is answered with 304 when the feed has not changed
  since.
- `Feed.SetSigner`: alerts added afterwards are signed.
- `Receiver.SetVerifier`: signatures are checked (403 for an unsigned
  alert where required, or one that does not verify); the verified
  alert is kept.
- `Receiver.SetProfiles` and `capsim receiver -profile`: alerts with
  profile errors are refused with 422.
- `Receiver.Refused`: why each refused post was refused.

## v0.1.0 (2026-10-11)

The feed server and receiver, moved from the cap module (see
PROVENANCE.md).
