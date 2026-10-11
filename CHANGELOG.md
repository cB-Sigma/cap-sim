# Changelog

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
