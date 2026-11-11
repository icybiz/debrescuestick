# Public image-service API

This is the **existing** DebRescueStick image API used by the specialized image
service. It is separate from EORLS website editing: create and maintain the EORLS
website through its normal customer UI. The old standalone HTML frontend is no
longer the public EORLS page.

Public origin: `https://eorls.com`. Endpoint paths below include the complete
`/debrescuestick` prefix; they are not internal EORLS editing endpoints.
Implementation references: [server.py](server.py), [store.py](store.py) and
[keys.py](keys.py). No credentials, live job links or private server files are
needed to use this description. Examples below use placeholders, not live jobs.

## Important integration limits

- Start is **not idempotent**. There is no request-key parameter, supported
  `Idempotency-Key` header, public job search or lookup by fingerprint.
- If the start response is lost after acceptance, the client cannot recover the
  job ID from another endpoint. Do not silently retry an indeterminate POST or
  claim exactly-once submission. A future recovery extension needs a separate
  implementation and qualification; it is not provided by this document.
- No public cancellation, job listing or deletion endpoint exists.
- Rate control uses the client address observed by the public edge. A server-side
  adapter may therefore share one rate-limit identity across visitors. There is
  no public authenticated per-visitor identity override in this contract.
- Status has no percentage, ETA or queue position. It exposes states only.

An EORLS adapter should persist the returned job ID before acknowledging a
successful start to its visitor. It must still handle a lost or indeterminate
start separately. Native EORLS public work links do not by themselves add
idempotency to this backend.

## Availability and corresponding sources

`GET /debrescuestick/api/status` returns HTTP 200 with an object:

```json
{
  "available": true,
  "sources_url": "/debrescuestick/sources/<base-sha256>/"
}
```

`available` is a boolean. The service accepts new jobs only while the current
base has matching qualification metadata and the worker heartbeat is fresh.
`sources_url` is optional: it is present when a qualified base is known, even if
worker availability is currently false. With no qualified base the response can
be only `{"available": false}`.

The source directory is public and independent of a personal job expiry. It
contains the exact corresponding Debian package sources for that base. Keep the
URL returned by the service rather than guessing a base hash.

## Start a request

`POST /debrescuestick/api/jobs`

Send `Content-Type: application/json` and a fixed `Content-Length`. The complete
UTF-8 JSON body must be between 1 and 20,000 bytes. Chunked request bodies are not
supported. The input object has one required property:

```json
{"public_key": "ssh-ed25519 <base64-public-key-data> optional comment"}
```

Only a public OpenSSH key is accepted. The parser accepts Ed25519, RSA with at
least 2,048 bits, NIST P-256/P-384/P-521 ECDSA and supported OpenSSH security-key
variants. The input string is at most 16,384 characters; decoded data is at most
8,192 bytes. Only one key line is allowed. Private keys and `authorized_keys`
options are rejected; a trailing comment is discarded during normalization.
No visitor account, password, email address or authorization token is required.

For the public service, an `Origin` header must either be absent or equal to
`https://eorls.com`. Other origins are rejected. This is not a general cross-origin
browser API; a normal server-side HTTP client can omit `Origin`. Do not send
forwarded-client headers to claim a different visitor identity.

HTTP **202 Accepted** returns the public job record:

```json
{
  "id": "<job-id>",
  "fingerprint": "SHA256:<public-key-fingerprint>",
  "created": 1700000000,
  "expires": 1700007200,
  "state": "queued",
  "bytes": null,
  "sha256": null,
  "error": null
}
```

The timestamps above are illustrative Unix seconds, not a usable request.
The actual `id` is 48 lowercase hexadecimal characters generated from 24 random
bytes. It is both the status and download capability: treat it as a secret,
keep it out of analytics/referrers/logs and do not publish it. The record never
returns the submitted public-key line; `fingerprint` is its OpenSSH SHA256
fingerprint. Do not use the fingerprint as a substitute for the secret job ID.

Additional JSON properties are not a recovery mechanism. In particular, sending
a made-up request ID does not cause the service to deduplicate requests.

## Read job state

`GET /debrescuestick/api/jobs/<job-id>` returns HTTP 200 with the same record shape.
The states are:

| State | Meaning |
| --- | --- |
| `queued` | Accepted and waiting for the single worker. |
| `personalizing` | The worker is preparing the individual key partition. |
| `compressing` | The worker is preparing the archive result. |
| `ready` | `bytes` and `sha256` identify the downloadable ZIP. |
| `failed` | Preparation failed; `error` contains a human-readable message. |

Poll with a bounded interval, for example two seconds, and stop when the job is
ready, failed, expired or missing. There is no server-push or long-poll endpoint.
A failed job is still a normal HTTP 200 job response; handle its `state`.
Human-readable error text is not a stable machine error code.

The default lifetime is **7,200 seconds from acceptance**, including queue time.
It is not extended when the job becomes ready or when it is polled/downloaded.
After expiry, status and download access return HTTP 404. There is no public
`expired` job state to poll successfully after the deadline.

The default queue admits at most **three unexpired jobs other than failed
jobs**, including ready jobs. A client address can create at most one request
per 60 seconds. Only one job is processed at a time. A full queue and a client
cooldown both return HTTP 429, without a guaranteed `Retry-After` value.

## Download, checksum and resume

After `state == "ready"`, use:

- `GET /debrescuestick/download/<job-id>` for the ZIP;
- `HEAD /debrescuestick/download/<job-id>` for its headers without the body.

`bytes` is the complete ZIP byte length and `sha256` is the SHA256 of that ZIP,
not of the IMG inside it. They are non-null only for a completed result. The
usual download name is `DebRescueStick-amd64.img.zip`. The ZIP contains one whole
personalized IMG; the compressed system prefix is shared internally, but no
special client-side assembly is needed.

A full successful download returns HTTP 200 with:

```text
Content-Type: application/zip
Content-Length: <complete ZIP byte length>
Content-Disposition: attachment; filename="DebRescueStick-amd64.img.zip"
Accept-Ranges: bytes
ETag: "<ZIP sha256>"
```

Single byte ranges are supported: `Range: bytes=START-END`, `bytes=START-` and
`bytes=-SUFFIX_LENGTH`. A satisfiable range returns HTTP 206 and
`Content-Range: bytes START-END/TOTAL`. Multi-range, malformed and unsatisfiable
requests return HTTP 416 with `Content-Range: bytes */TOTAL` and an empty body.
`HEAD` uses the same size/range validation as GET.

`If-Range` and conditional-cache behavior are **not implemented**. Do not rely on
them to bind a resumed download. Keep the same job ID and expected ZIP identity,
validate range responses and verify the completed full length and SHA256.

Each streaming response is bounded to about 300 seconds and also stops at job
expiry. Network errors or expiry can leave an incomplete body despite a declared
content length. Resume with a new range request only while the same job is still
available. A finished download is valid only after full-length and checksum
verification. The current uncompressed AMD64 IMG length is 8,598,323,200 bytes;
compressed ZIP sizes vary and must come from the job record.

## Errors and HTTP behavior

Application errors are JSON objects containing an `error` string. In particular:

| HTTP status | Situation |
| --- | --- |
| 400 | Invalid JSON/request size, missing or invalid public key. |
| 403 | A supplied Origin does not match the service origin. |
| 415 | POST content type is not `application/json`. |
| 429 | Client cooldown or queue capacity reached; no job was created. |
| 503 | Image preparation unavailable; no job was created. |
| 404 | Unknown/missing/expired job, not-yet-ready download or unavailable file. |
| 416 | Invalid/unsatisfiable download range; empty body as described above. |

The HTTP listener also caps concurrent requests. Its overload response can be
HTTP 503 with an **empty body** and `Retry-After: 10`; do not assume every error
is JSON. Socket timeouts or broken connections can likewise produce no complete
JSON response. HEAD is supported only for download paths; other HEAD requests
return HTTP 405.

JSON and download responses use `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`. Keep personal job capabilities separate from public
source links. Log only redacted operation/state information and never private
SSH keys, submitted key material or complete personal status/download URLs.
