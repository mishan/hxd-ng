# The server banner

The image a server shows above its client's windows: a strip of the
operator's own decoration, often with somewhere to click. One banner,
configured once in `[banner]` (README), shown on both wires.

## 1. What a banner is

Either an image this server holds — a JPEG, GIF or PNG file of at most
1 MiB, recognized by its magic bytes and re-read on SIGHUP — or a URL
where the image is, for the client to fetch itself. A held banner may
also carry a URL, which is then where a click on it goes.

## 2. The legacy wire

As mhxd serves it (`rcv.c`): after a 1.5+ client's AGREEMENTAGREE,
`HTLS_HDR_BANNER` carries the banner's type (`JPEG`, `GIFf`, `PNGf`, or
`URL ` for a banner fetched from its URL) and the URL, when there is
one. A held banner is fetched with `HTLC_HDR_DOWNLOAD_BANNER`, answered
with an HTXF reference redeemed for the raw bytes, once per login. The
deviations from mhxd are commented in `hxd-session/src/banner.rs` and
`session.rs`.

## 3. The ng wire

### 3.1 Capability

`banner` in `caps`, whenever the server has one, with a login block:

```jsonc
// A banner held here:
"banner": { "url": "/banner", "type": "image/jpeg",
            "link": "https://hl.example/" }    // absent without a URL
// A banner somewhere else:
"banner": { "url": "https://hl.example/banner.jpg" }
```

| Field | Rule |
|---|---|
| `url` | Always where the image is: `"/banner"` for a banner held here, fetched from this server's ng port with the session's bearer (§3.2), or an absolute `http://` or `https://` URL, fetched as it is, without the bearer. A client MUST NOT send the bearer for any other value. |
| `type` | For a banner held here, its media type at login. The response's `Content-Type` is the one to believe: a SIGHUP may change the file under the same path. |
| `link` | Where a click on the banner goes. Absent means nowhere. It is the operator's to write and may be any URL — a classic banner often links to a `hotline://` — so a client MUST check its scheme as it would a link in chat, and SHOULD open it outside itself. |

### 3.2 `GET /banner`

```
GET /banner
  Authorization: Bearer <session>.<token>

  200  Content-Type: image/jpeg
       Cache-Control: private, no-cache
       ETag: "<digest>"
       <the file's bytes>
```

As often as a client likes, unlike the legacy download: a page that
reloads fetches it again. The ETag is a digest of the bytes, so a
revalidation after a SIGHUP that changed nothing is a 304. It is
compared weakly, as RFC 9110 asks of `If-None-Match`, so `*` and a tag
a proxy weakened both match.

Refusals carry the ng error body, `{ "error": { "code", "text" } }`:

| Status | Code | When |
|---|---|---|
| 401 | `not_logged_in` | No bearer, or one that is not a live session's. |
| 404 | `no_such_banner` | No banner held here: none at all, or one fetched from its URL. |

The banner is the server's own decoration, shown to every session, so
the fetch needs no access bit; the bearer is required only so that it
is not a public web resource, as for `/media`.
