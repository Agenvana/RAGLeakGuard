# Authenticated durable webhook protocol v2

This document defines the implemented RAGLeakGuard monitor webhook protocol version 2. It is a deliberately incompatible privacy-minimal delivery protocol for one exposure-change event and one destination. It is not a finding report, a hosted receiver, an exactly-once guarantee, unconditional at-least-once delivery, or proof of downstream processing or human notification. The authenticated outbox is governed by the [monitor key and state contract](MONITOR_STATE.md).

## Configuration and v1 cutover

The sender options are a required pair:

```text
--webhook HTTPS_URL --webhook-secret-file PATH
```

`--webhook` without its secret exits 5. A secret without `--webhook` exits 2. URL and secret validation occur before monitor-key/state loading. Direct Chroma new scans are disabled, so no connector access follows. There is no unsigned mode, fallback key, literal secret option, environment fallback, monitor-key reuse, automatic generation, downgrade, dual-send, or receiver compatibility mode.

Protocol v2 requires a new secret file and new key ID:

```bash
ragleakguard generate-webhook-secret \
  --output /etc/ragleakguard/webhook-secret-v2.json
```

The strict JSON root is:

| Field | Exact contract |
|---|---|
| `version` | Integer `2`; booleans rejected. |
| `purpose` | `ragleakguard.webhook-signing.v2`. |
| `construction` | `RLG-WEBHOOK-HMAC-SHA256-v2`. |
| `key_id` | Random non-secret 128 bits as 32 lowercase hex characters. |
| `secret` | Exactly 256 CSPRNG bits in strict canonical Base64. |

Generation uses exclusive no-overwrite creation, file `fsync`, and POSIX mode `0600`. Loading is capped at 4096 bytes and rejects non-regular paths, symlinks, broad POSIX permissions, malformed/duplicate/unknown JSON, noncanonical Base64, wrong lengths, and wrong version/purpose/construction. Failures are static and omit paths, key IDs, secret material, URLs, and exceptions. Portable Python cannot prove a restrictive Windows DACL; operators must configure it separately.

### Required cutover sequence

1. Keep the v1 file unchanged for rollback evidence; never overwrite it.
2. Generate a distinct v2 file with a new random key ID. Never reuse a retired key ID.
3. Provision the new `(key_id, secret)` through a confidential channel to the receiver's protocol-v2 key mapping on every node.
4. Deploy a receiver that enforces the exact v2 verifier, shared nonce policy, and durable delivery-ID store.
5. Point the sender at the new file only after receiver readiness is verified with synthetic traffic.
6. Retire v1 receiver behavior separately. The RAGLeakGuard v2 sender never falls back to it.

Legacy v1 secret files and receivers fail closed. A v1 file cannot masquerade as v2 by renaming it. Rotation within v2 also uses a new file/new key ID: provision receiver first, cut the sender over, retain the old mapping through the last possible freshness/retry window, then retire it. Secret backup, recovery, compromise response, and receiver mapping remain operator responsibilities.

## Exact event body

The UTF-8 body is exactly these 60 bytes, with no BOM, whitespace variance, or trailing newline:

```json
{"event":"ragleakguard.monitor.exposure-change","version":2}
```

Serialization uses `ensure_ascii=True`, `sort_keys=True`, and separators `(',', ':')`, then asserts the exact bytes and length. The same immutable byte object is signed and transmitted.

The body carries no timestamp, delivery ID, source/store/state/key path, collection/tenant, record ID/token, finding value/type/count/total/span, document text, exception, monitor key, webhook secret, URL, response, or installation identifier.

## Exact HTTP/1.1 request

The request line is `POST`, one ASCII space, the exact validated origin-form target, and ` HTTP/1.1`. The complete application header allowlist and order are:

| Header | Exact value or format |
|---|---|
| `Host` | Normalized lowercase ASCII authority; non-default port included. |
| `Content-Length` | `60`. |
| `Content-Type` | `application/json`. |
| `User-Agent` | `RAGLeakGuard-Webhook/2`. |
| `X-RAGLeakGuard-Webhook-Version` | `2`. |
| `X-RAGLeakGuard-Key-Id` | 32 lowercase hex characters. |
| `X-RAGLeakGuard-Delivery-Id` | The persisted 32-lowercase-hex 128-bit delivery ID. |
| `X-RAGLeakGuard-Timestamp` | Fresh UTC Unix time in whole decimal seconds, no sign/leading zeroes. |
| `X-RAGLeakGuard-Nonce` | Fresh 128 CSPRNG bits as 32 lowercase hex characters. |
| `X-RAGLeakGuard-Signature` | `v2=` plus the full 64-lowercase-hex HMAC-SHA-256 digest. |

No HTTP-library defaults are used. The sender adds no authorization, proxy authorization, cookie, referrer, accept, compression, connection, runtime-identifying user agent, source metadata, or other header.

Every actual attempt reuses only `X-RAGLeakGuard-Delivery-Id`. It resamples timestamp and nonce, rebuilds the request, and recomputes the signature. Attempt bytes are never persisted or replayed verbatim.

## Signature construction

Use the 32 secret bytes directly as the HMAC-SHA-256 key. Frame every field as:

```text
uint32_be(label_length) || label_ascii || uint64_be(value_length) || value_bytes
```

Concatenate frames in exactly this order:

```text
construction     = ASCII("RLG-WEBHOOK-HMAC-SHA256-v2")
method           = ASCII("POST")
authority        = exact ASCII Host header value
request-target   = exact ASCII origin-form path and optional query
content-length   = exact ASCII Content-Length value
content-type     = exact ASCII Content-Type value
user-agent       = exact ASCII User-Agent value
webhook-version  = exact ASCII X-RAGLeakGuard-Webhook-Version value
key-id           = exact ASCII X-RAGLeakGuard-Key-Id value
delivery-id      = exact ASCII X-RAGLeakGuard-Delivery-Id value
timestamp        = exact ASCII X-RAGLeakGuard-Timestamp value
nonce            = exact ASCII X-RAGLeakGuard-Nonce value
body             = exact 60 transmitted bytes
```

Compute full HMAC-SHA-256, encode all 64 digest hex characters lowercase, and prefix `v2=`. The construction identifier, header values, delivery ID, and signature prefix deliberately domain-separate v2 from v1.

### Published protocol-v2 test vector

```text
secret bytes     = 00 01 02 ... 1f
secret Base64    = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
key_id           = 00112233445566778899aabbccddeeff
delivery_id      = ffeeddccbbaa99887766554433221100
method           = POST
URL              = https://receiver.example.test/hooks/rlg?channel=security
authority        = receiver.example.test
request-target   = /hooks/rlg?channel=security
content-length   = 60
content-type     = application/json
user-agent       = RAGLeakGuard-Webhook/2
webhook-version  = 2
timestamp        = 1786320000
nonce            = 0123456789abcdeffedcba9876543210
body             = {"event":"ragleakguard.monitor.exposure-change","version":2}
signature        = v2=fd7ce5c478368ffeb37c38d04d9ae5cb18e2a45b507e870ab9f48829ce13a438
```

The tests independently frame every field, reproduce the signature, verify it, and reject tampering with every signed field.

## Receiver verification and durable deduplication

A receiver must retain the raw method, authority, origin-form target, header occurrences/values, and body. Framework normalization must not hide duplicates or rewrite the target before verification.

Required order:

1. Enforce exact method, 60-byte body/schema, header-name allowlist, fixed header values, normalized Host, origin-form target, protocol version, lowercase formats, and matching content length.
2. Reject duplicate headers and select exactly one v2 secret by key ID.
3. Reconstruct all frames and compute the expected full v2 HMAC.
4. Compare signatures in constant time. No freshness, nonce, delivery-store, or downstream action occurs before authentication succeeds.
5. Parse the authenticated timestamp and require `abs(receiver_now - timestamp) <= 300` seconds.
6. Atomically reject a previously accepted `(key_id, nonce)` and retain a new entry through at least `timestamp + 300`. A future-skewed request can therefore require retention for up to 600 seconds after receipt.
7. Consult a durable, atomic delivery-ID store shared by every receiver node.
8. Process a previously unseen authenticated `(key_id, delivery_id)` once under that store's documented transaction/claim semantics.
9. For an already accepted delivery ID with a fresh authenticated nonce, skip downstream processing and return the same documented successful `2xx` class (for example `204`).

The Python helper `verify_webhook_request` accepts:

- a nonce cache with `accept(key_id, nonce, timestamp, receiver_now) -> bool`;
- a delivery store with `process_once(key_id, delivery_id, processor) -> bool`, returning `True` only when it ran the processor and durably accepted the new ID, or `False` for an already accepted duplicate; and
- a zero-argument event processor.

It returns `WebhookVerificationResult(duplicate=False)` for a newly processed delivery and `WebhookVerificationResult(duplicate=True)` for authenticated duplicate-success behavior. `WebhookReplayCache` and `WebhookMemoryDeliveryStore` are thread-safe process-local reference implementations for tests; neither is production-durable. Production topology requires a durable, atomic delivery-ID store and an appropriate shared nonce mechanism across all nodes.

The delivery-store interface reduces duplicate downstream work but does not establish exactly-once processing. Retention expiry, storage loss, multi-node inconsistency, and a crash or non-atomic boundary between downstream processing and deduplication commit can permit duplicate effects. Receiver implementations must document their transaction ordering and recovery behavior.

## URL and transport policy

- Input is bounded to 2048 ASCII bytes and exact HTTPS. Credentials, fragments, controls/whitespace, backslashes, malformed hosts/ports/percent escapes, and non-ASCII input fail before source access.
- Exact validated percent-encoded path/query spelling is preserved. URL, authority, query, key/delivery IDs, signature, response data, and failures are never printed.
- Default TLS certificate-chain and hostname verification cannot be disabled. There is no HTTP or localhost exception.
- One synchronous POST is permitted per invocation. Redirect handling is absent; every `3xx` fails without a second request.
- One 10-second monotonic deadline covers DNS, address connection attempts, TLS handshake, request writes, and response headers. The bounded daemon-thread DNS handoff can leave a stuck OS resolver thread until the platform returns.
- The client reads one byte at a time only through `\r\n\r\n`, then closes without consuming, persisting, or printing response-body bytes.
- Only `200..299` succeeds. Informational, redirect, error, malformed/oversized, EOF, timeout, DNS, socket, TLS, write, and read failures become static delivery failure.

## Sender state machine and exits

1. Validate source/path and locale syntax, webhook pair/URL/v2 secret, monitor key, and authenticated state. Disabled new-scan paths do not initialize detection or access a connector.
2. If a v3 pending alert exists, the pending alert blocks source access and newer scans.
3. Missing v2 webhook configuration, safe-retry precondition failure, or not-yet-due backoff leaves state unchanged and exits 5 without a request.
4. A due retry prepares a fresh request with the persisted delivery ID and makes at most one attempt.
5. Failed delivery atomically advances bounded attempt/backoff metadata. Successful update exits 5; update failure preserves prior authenticated pending state in tested paths and exits 4.
6. Accepted `2xx` permits atomic clear. Clear success prints `Webhook response accepted; pending alert cleared. No downstream processing is claimed.` and exits without scanning. Clear failure prints static ambiguous delivery and exits 4; later delivery can duplicate.
7. With no pending alert, the current CLI exits 6 before initialization, no-change, resolved-only,
   local-exposure, or new-alert behavior. It preserves authenticated state and sends nothing.
8. The WP6 new-alert ordering remains implemented in library code but is unreachable from the
   disabled current CLI new-scan path. It is not evidence that scanning or new-alert creation is
   available.

Exit 1 is not emitted by the disabled current CLI new-scan path. A recovered pending alert accepted
and cleared at invocation start exits 0 because no scan occurred. Exit 6 marks the disabled new-scan
boundary. Exit 5 covers pending/backoff/configuration/preparation/delivery failures. Exit 4 covers
state/retry-metadata and accepted-but-not-cleared ambiguity.

## Compatibility, exclusions, and residual risks

- Protocol/secret v1 remains historical documentation context only and is not accepted by this durable sender/verifier. There is no silent downgrade or compatibility masquerading.
- Protocol-v2 and state-v3 helper call shapes are incompatible. Importable Python modules have no separately versioned stable SDK guarantee.
- One pending alert and one destination are supported. There is no queue, fan-out, multi-destination routing, direct Slack/Discord adapter, hosted receiver, database, Control Plane, tenancy, RBAC/SSO, billing, vault/KMS, or fleet management.
- There is no dead-letter inspection, acknowledgement, replay, purge, or maximum-attempt discard. A permanently pending alert blocks scans indefinitely.
- A send/response/clear crash is ambiguous and can duplicate delivery. Durable receiver deduplication reduces but cannot eliminate that risk.
- HMAC supplies authenticity/integrity, not confidentiality. TLS, receiver clocks, key mapping, cache/store behavior, logging, downstream systems, CA/runtime integrity, and shared-secret protection are external dependencies.
- A `2xx` proves only that sender response-header requirements were met. It proves neither event storage nor downstream processing, notification, or human action.
- Alerts lost under version 1 or the former version-2 checkpoint-before-send ordering cannot be reconstructed.
- No source-scanning connector is currently available. This protocol does not prove detector/connector completeness, production safety, compliance, breach prevention, erasure, receiver trustworthiness, or delivery under every host/network/filesystem failure.
