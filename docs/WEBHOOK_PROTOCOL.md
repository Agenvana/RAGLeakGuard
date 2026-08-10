# Authenticated webhook protocol

This document defines the implemented RAGLeakGuard monitor webhook version 1. It is a privacy-minimal notification that an exposure change occurred, not a finding report, durable-delivery protocol, or proof of downstream processing. The monitor-state key remains governed separately by the [monitor key and state contract](MONITOR_STATE.md).

## Sender configuration and dedicated secret

The two monitor options are a required pair:

```text
--webhook HTTPS_URL --webhook-secret-file PATH
```

`--webhook` without `--webhook-secret-file` exits 5. A secret file without a webhook exits 2. Validation occurs after source/path, locale, and detection-runtime validation but before monitor-key/state loading and before connector access. There is no unsigned mode, fallback key, literal secret option, environment fallback, derived key, monitor-key reuse, embedded default, or silent generation.

Create a new secret without overwriting any path:

```bash
ragleakguard generate-webhook-secret --output /etc/ragleakguard/webhook-secret.json
```

The JSON root has this complete allowlist; duplicate, unknown, or missing members fail:

| Field | Exact contract |
|---|---|
| `version` | Integer `1`; a Boolean is not an integer here. |
| `purpose` | `ragleakguard.webhook-signing` |
| `construction` | `RLG-WEBHOOK-HMAC-SHA256-v1` |
| `key_id` | Random non-secret 128 bits encoded as 32 lowercase hexadecimal characters. It selects a receiver-side secret during rotation and must not encode an installation, tenant, store, or customer identity. |
| `secret` | Exactly 256 CSPRNG bits in strict canonical Base64. |

Generation uses the OS CSPRNG, exclusive no-overwrite creation, file `fsync`, and POSIX mode `0600`. Loading is capped at 4096 bytes and rejects missing/unreadable paths, non-regular files, symlinks, broad POSIX permissions, invalid UTF-8, invalid or duplicate JSON, schema/type mismatches, malformed/noncanonical Base64, wrong-length material, and wrong purpose/construction/version/key ID. Failures are static and do not print paths, key IDs, secret bytes, URLs, or exception text.

Portable Python does not prove a restrictive Windows DACL. On Windows, the operator must use Windows ACL tooling such as `icacls` or `Set-Acl` to restrict the file to the sender identity and authorized administrators. This implementation does not claim to enforce or audit that DACL.

### Lifecycle

- **Provisioning and sharing:** generate at a controlled sender host and deliver the `(key_id, secret)` to the verifying receiver through a separately controlled confidential channel. Do not send it in the webhook, command line, environment dumps, logs, tickets, or repository.
- **Backup and recovery:** back up sender and receiver mappings through separately access-controlled, tested recovery procedures. Secret loss requires restoration or explicit new-secret provisioning; it must not cause unsigned delivery.
- **Rotation:** generate a new file, provision its new `(key_id, secret)` at the receiver, point the sender to the new file, retain the old receiver mapping through the freshness/replay window after the last possible old send, then retire it. Do not replace secret bytes in place.
- **Compromise:** provision a new file and receiver mapping, cut over, retire the compromised mapping as soon as incident handling permits, and investigate sender/receiver logs and downstream effects. A compromised shared secret permits forgery.
- **Identifiers:** never reuse a retired key ID, including with different secret bytes. Key IDs are non-secret selectors, not installation IDs.

## Exact event body

The UTF-8 body is exactly these 60 bytes, with no BOM, insignificant whitespace, or trailing newline:

```json
{"event":"ragleakguard.monitor.exposure-change","version":1}
```

The sender serializes the two-field object with `ensure_ascii=True`, `sort_keys=True`, and separators `(',', ':')`, then asserts the exact bytes and size. That immutable byte object is signed and passed unchanged to the transport; it is not reserialized.

The body intentionally carries no timestamp, source/store/state/key path, collection/tenant, record ID/token, finding value/type/count/total/span, document text, exception, monitor key, signing secret, URL, or installation identifier.

## HTTP/1.1 request

The request line is `POST`, one ASCII space, the exact validated origin-form request target, and ` HTTP/1.1`. The complete application header allowlist is:

| Header | Exact value or format |
|---|---|
| `Host` | Normalized lowercase ASCII authority; an optional non-default port is included. |
| `Content-Length` | `60` |
| `Content-Type` | `application/json` |
| `User-Agent` | `RAGLeakGuard-Webhook/1` |
| `X-RAGLeakGuard-Webhook-Version` | `1` |
| `X-RAGLeakGuard-Key-Id` | 32 lowercase hexadecimal characters |
| `X-RAGLeakGuard-Timestamp` | UTC Unix time in whole decimal seconds, with no sign or leading zeroes |
| `X-RAGLeakGuard-Nonce` | Fresh 128 CSPRNG bits encoded as 32 lowercase hexadecimal characters |
| `X-RAGLeakGuard-Signature` | `v1=` plus the full 64-lowercase-hex HMAC-SHA-256 digest |

No HTTP library defaults are used. The raw client adds no authorization, proxy authorization, cookie, referrer, accept, accept-encoding, connection, runtime-identifying user agent, source metadata, or other header. TLS records and TCP/IP framing are outside this HTTP-header allowlist.

## Signature construction

Use the 32 secret bytes directly as the HMAC-SHA-256 key. Each field is framed as:

```text
uint32_be(label_length) || label_ascii || uint64_be(value_length) || value_bytes
```

Concatenate frames in exactly this order:

```text
construction     = ASCII("RLG-WEBHOOK-HMAC-SHA256-v1")
method           = ASCII("POST")
authority        = exact ASCII Host header value
request-target   = exact ASCII origin-form path and optional query sent
content-length   = exact ASCII Content-Length value
content-type     = exact ASCII Content-Type value
user-agent       = exact ASCII User-Agent value
webhook-version  = exact ASCII X-RAGLeakGuard-Webhook-Version value
key-id           = exact ASCII X-RAGLeakGuard-Key-Id value
timestamp        = exact ASCII X-RAGLeakGuard-Timestamp value
nonce            = exact ASCII X-RAGLeakGuard-Nonce value
body             = exact 60 transmitted bytes
```

Compute the full 32-byte HMAC-SHA-256, encode all 64 digest hex characters in lowercase, and prefix `v1=`.

### Published test vector

```text
secret bytes     = 00 01 02 ... 1f
secret Base64    = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
key_id           = 00112233445566778899aabbccddeeff
method           = POST
URL              = https://receiver.example.test/hooks/rlg?channel=security
authority        = receiver.example.test
request-target   = /hooks/rlg?channel=security
timestamp        = 1786320000
nonce            = 0123456789abcdeffedcba9876543210
body             = {"event":"ragleakguard.monitor.exposure-change","version":1}
signature        = v1=6405d41258cc777845c57c39ec86528bb19a1b8f30c589c8fe870274f397ae3c
```

The test suite reproduces this value and verifies it through the independent receiver path.

## Receiver algorithm

A receiver must retain the raw method, authority, origin-form request target, header occurrences/values, and body bytes. Framework normalization must not hide duplicate headers or alter the target before verification.

Language-neutral verification order:

1. Require method `POST`, exact 60-byte body/schema, exact header-name allowlist, exact fixed header values, normalized Host, origin-form request target, supported version, lowercase formats, and a Content-Length that equals the received body length.
2. Reject duplicate headers. Select exactly one 32-byte secret by `X-RAGLeakGuard-Key-Id`; reject unknown or retired IDs.
3. Reconstruct the frames above from the received values and compute the expected full HMAC-SHA-256.
4. Compare the received and computed signatures with a constant-time digest comparison. Do not perform freshness or replay-cache acceptance before authentication succeeds.
5. Parse the authenticated timestamp and require `abs(receiver_now - timestamp) <= 300` seconds. Both boundary seconds are accepted.
6. Atomically reject an already accepted `(key_id, nonce)` and retain a new entry until at least `timestamp + 300` seconds. A future-skewed accepted timestamp can therefore require retention for up to 600 seconds after receipt.
7. Only after all checks pass, treat the request as the single `ragleakguard.monitor.exposure-change` event.

The Python helper `verify_webhook_request` implements this order and accepts an atomic cache object with `accept(key_id, nonce, timestamp, receiver_now)`. `WebhookReplayCache` is a thread-safe process-local reference implementation. Production receiver topology determines whether a shared/durable cache is needed.

Wrong secrets, unknown IDs, malformed/non-lowercase signatures, unsupported versions, duplicate/extra/missing headers, body/method/Host/request-target/header tampering, stale/future timestamps outside the inclusive window, and authenticated duplicate nonces are rejected rather than treated as events.

## URL and transport policy

- URL input is ASCII and at most 2048 bytes. Only `https` with a non-empty normalized host and optional port `1..65535` is accepted. Empty path becomes `/`.
- User information, embedded credentials, fragments, whitespace/control characters, backslashes, invalid percent escapes, malformed hosts/authorities/ports, non-ASCII input, and unsupported schemes fail before source access. Exact validated percent-encoded path/query spelling is preserved; it is not decoded or re-encoded.
- The URL, path/query, Host, key ID, signature, response data, and underlying failures are never printed or interpolated into errors/reprs.
- Python's default TLS context provides certificate-chain and hostname verification. There is no disable switch and no HTTP or localhost exception.
- Exactly one synchronous POST is transmitted. Redirect handling is absent by construction. Every `3xx`, including same-origin, cross-origin, and HTTPS-to-HTTP locations, fails without another request.
- One 10-second monotonic deadline begins before DNS and is carried through address connection attempts, TLS handshake, request-head/body writes, and response-header completion. DNS runs behind a bounded daemon-thread handoff because portable Python exposes no timeout for the platform resolver; the caller exits on the shared deadline, although a stuck OS resolver call may remain in that daemon thread until the platform returns.
- The client reads one TLS byte at a time only through `\r\n\r\n`, so it does not consume response-body bytes even when the peer has already sent them. It closes without parsing, persisting, or printing a body.
- Only `200..299` succeeds. `1xx`, `3xx`, `4xx`, `5xx`, malformed/oversized headers, EOF, deadline expiry, and DNS/socket/TLS/write/read failures become one static exit-5 delivery failure. `Webhook alert delivered.` is printed only after accepted response headers.

## Monitor ordering and failure semantics

1. Validate source/path pairing, locale, and detection runtime.
2. If either webhook option is present, validate the pair, HTTPS URL, and dedicated secret before source access.
3. Load the monitor key, bind the source scope, and authenticate/validate state before source access.
4. Read, detect, build the current snapshot, and calculate the delta.
5. Initialization creates the baseline and sends nothing.
6. No-change and resolved-only runs replace the checkpoint and send nothing.
7. A new/changed exposure without a webhook replaces the checkpoint, reports the change, and exits 1.
8. A new/changed exposure with a webhook constructs the fixed body, samples timestamp/nonce, builds the allowlist, and signs before checkpoint replacement. Preparation failure exits 5 with the prior checkpoint preserved and no request.
9. Checkpoint failure exits 4 with no request and preserves the prior checkpoint in tested failure paths.
10. The sender transmits the already prepared request once. Accepted `2xx` prints the delivery line and exits 1 for the exposure. Transport/response failure advances no further state, prints only the static delivery failure, and exits 5.

Step 10 deliberately follows checkpoint replacement. If transport fails, the checkpoint is already advanced and a later run will ordinarily not reconstruct the alert.

## Compatibility and explicit exclusions

- Existing unsigned `--webhook` jobs break deliberately and fail closed. Receivers must implement this protocol before cutover.
- The fixed version-1 event replaces the prior unversioned payload containing store metadata, totals, record tokens, and type/count details.
- Direct Slack and Discord incoming webhooks are not compatible. Zapier, n8n, or another integration is not directly supported unless a receiver/gateway first implements and tests this verifier.
- Exit 5 is new for webhook configuration, secret loading/generation, preparation/signing, transport, redirect, and response failures. Exit 1 with a configured webhook means an exposure plus accepted `2xx` response headers.
- Monitor state remains version 2. No pending-delivery or webhook data is persisted.
- Importable webhook helper call shapes changed incompatibly. Python modules do not have a separately versioned stable SDK contract.
- This package intentionally excludes durable outbox/pending delivery, retries, backoff, jitter, idempotency keys or guarantees, dead-letter handling, crash recovery, multi-destination routing, and exactly-once/at-least-once delivery claims.

## Residual risks and non-claims

- HMAC provides shared-secret authenticity/integrity, not confidentiality and not replay prevention by itself. TLS supplies in-transit confidentiality/authentication under the configured CA trust.
- Receiver verification, clock correctness, key mapping, atomic cache behavior, restart/multi-node cache topology, logging, and downstream adapters are external dependencies. A restart or nodes without shared cache can admit replay inside the window.
- Sender-clock correctness affects the signed timestamp. Nonces have a non-zero collision probability; receivers still reject duplicate pairs.
- A compromised sender, receiver, shared secret, Python runtime, dependency, CA store, or endpoint can disclose or forge material within its access.
- The checkpoint-before-transport window can lose an alert. A send or response failure cannot prove that the receiver did not accept a complete request, and crashes around sending remain ambiguous until separately implemented durable delivery work.
- `2xx` proves only that response headers satisfied this client contract, not that a receiver stored, forwarded, notified, or acted on the event.
- This protocol does not prove detector/connector completeness, production safety, compliance, breach prevention, receiver trustworthiness, or alert reliability. Review the broader [security policy](../SECURITY.md) and [threat model](THREAT_MODEL.md).
