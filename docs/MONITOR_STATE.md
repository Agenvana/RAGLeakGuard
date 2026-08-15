# Monitor key, state, and durable outbox contract

This document describes the implemented version-3 local monitor checkpoint and its one-entry authenticated webhook outbox. Direct/live Chroma and monitor new scans are disabled. The separate exact-1.5.9 operator-snapshot CLI requires the operator to create a complete, quiescent/full-filesystem snapshot; monitor does not use it. A completed pending-alert recovery transition is not proof of detector or connector completeness, production safety, compliance, webhook delivery under every failure, downstream processing, or human notification.

## Operator workflow

Every monitor run requires an explicit operator-provided monitor key. There is no default key, public-metadata derivation, fallback key, unkeyed mode, Control Plane, vault, or KMS integration.

Generate a new key without overwriting any path:

```bash
ragleakguard generate-monitor-key --output /etc/ragleakguard/monitor-key.json
```

On POSIX, the generator creates mode `0600`, and the loader rejects group- or other-accessible files. Portable Python cannot prove a restrictive Windows DACL; use Windows ACL tooling to restrict the key file to the scheduled-task identity and authorized administrators. Missing, non-regular, unreadable, oversized, malformed, weak, wrong-purpose, wrong-construction, and incompatible files produce a static exit-4 failure.

New monitor baselines and new scans cannot currently be created. A syntactically valid `--initialize`
request validates the monitor key and confirms that the selected state path is absent, then exits 6
without creating state. An existing authenticated state with no pending alert also exits 6 without
replacement. Existing operator-selected state paths do not need renaming.

An existing authenticated pending alert may still be recovered by invoking `monitor` with the exact
original source/path spelling, monitor key, state, protocol-v2 webhook URL, and protocol-v2 secret.
This is a recovery operation only, not a scan quickstart. Legacy v1 secret files fail closed. See the
[webhook protocol](WEBHOOK_PROTOCOL.md) for the mandatory new-file/new-key-ID cutover.

## Monitor key and finding construction

The strict monitor-key allowlist remains `version`, `purpose`, `construction`, `key_id`, and `key`:

| Field | Required value |
|---|---|
| `version` | Exact integer `1`; booleans rejected. |
| `purpose` | `ragleakguard.monitor`. |
| `construction` | `RLG-MONITOR-HMAC-SHA256-v1`. |
| `key_id` | Random non-secret 128-bit identifier as 32 lowercase hexadecimal characters. |
| `key` | Exactly 256 CSPRNG bits in strict canonical Base64. |

The master key remains process-local. Independently labelled HMAC-SHA-256 subkeys cover finding tokens, aggregate fingerprints, record correlation, store-scope binding, and persisted-state authentication. The persisted schema changes to version 3; the cryptographic state construction deliberately remains `RLG-MONITOR-HMAC-SHA256-v1`.

Finding identity remains the exact uppercase detector type plus exact detected text, encoded as strict UTF-8 without Unicode normalization. Position and score are excluded. Typed length framing is:

```text
uint32_be(label_length) || label || uint64_be(value_length) || value
```

Sorted repeated finding tokens define an order-independent multiset while retaining duplicate multiplicity. Tokens, fingerprints, scope/record values, and state authenticators retain the full 256-bit HMAC output. The specific-pair idealized collision probability is `2^-256`; the birthday approximation for `q` independent outputs is `q(q-1) / 2^257`. These are assumptions and non-zero residual risks, not impossibility claims.

Key backup, recovery, rotation, retirement, compromise response, and non-overlapping scheduled execution remain operator responsibilities. Do not replace a key file in place or reuse a retired key ID. Deliberate rotation requires a new key, new state path, and explicit initialization; it loses cross-key comparison history.

## Version-3 state schema

The root has exactly these members; unknown and duplicate members are rejected:

| Field | Contract |
|---|---|
| `version` | Exact integer `3`; booleans rejected. |
| `construction` | Exact `RLG-MONITOR-HMAC-SHA256-v1`. |
| `key_id` | 32 lowercase hex characters matching the loaded key. |
| `scope_token` | Full 64-hex keyed store-scope token. |
| `totals` | Exact bounded `records` and `findings` integers consistent with `records`. |
| `records` | Object keyed only by full 64-hex record tokens. |
| `pending_alert` | `null` or the one strict object below. |
| `authentication` | Full 64-hex authenticator over every other root field. |

Each record value contains exactly `finding_count` (`0..1,000,000`) and a 64-lowercase-hex `fingerprint`. State permits at most 1,000,000 records, at most 1,000,000 findings per record, at most `10^12` findings in total, and at most 64 MiB of UTF-8 JSON. Zero/non-zero counts must be consistent with the keyed empty fingerprint. Totals must exactly match the record map.

### One pending alert

The only non-null `pending_alert` shape is:

| Field | Exact contract |
|---|---|
| `event` | `ragleakguard.monitor.exposure-change`. |
| `webhook_version` | Exact integer `2`; booleans rejected. |
| `delivery_id` | One CSPRNG 128-bit value as 32 lowercase hex characters. |
| `attempts` | Completed failed attempts durably recorded, integer `0..2^63-1`. |
| `next_attempt_at` | Earliest retry as a whole UTC Unix second, integer `0..253402300799`. |

The outbox does not persist a URL or authority, webhook secret, webhook key ID, timestamp header, nonce, signature, prepared request bytes, source/store/state/key path, scope or record data beyond the existing checkpoint, finding value/type/count/span, document data, response data, exception, or adapter metadata. The state authenticator covers the complete canonical body, including every pending-alert member.

Serialization uses sorted keys, `ensure_ascii=True`, separators `(',', ':')` for the authenticated body, and a final human-readable JSON encoding. Loading validates schema, bounds, key/scope binding, totals, digest formats, and authentication before source access, diffing, writing, success output, request preparation, or delivery.

## Atomic persistence and pending-first ordering

State creation and replacement use a permission-restricted same-directory temporary file, complete write, flush, file `fsync`, and an atomic namespace operation. Initialization uses atomic no-overwrite installation. Tested temporary-write, `fsync`, and replacement failures clean temporary artifacts when possible and preserve the prior checkpoint byte-for-byte. Power-loss durability and namespace semantics beyond those operations depend on the host filesystem and storage stack.

For a new or changed exposure with a configured webhook:

1. Generate the delivery ID and due-now pending metadata.
2. Serialize and authenticate the new checkpoint and pending alert together.
3. Atomically replace the state before sampling an attempt timestamp/nonce, signing, or accessing the network.
4. Make at most one delivery attempt in that invocation.

No request is prepared or sent unless step 3 succeeds. An interruption after step 3 leaves a recoverable pending alert.

At the beginning of later runs, authenticated pending state blocks all source access and newer scans. The current protocol-v2 URL and secret must pass preflight. A not-yet-due alert exits 5 with static output and unchanged state. A due alert reuses only the delivery ID; timestamp, nonce, signature, and request object are constructed anew.

Only accepted `2xx` response headers permit an atomic replacement with `pending_alert: null`. No success line is emitted until that clear succeeds. If receiver acceptance is followed by a clear failure, the same pending delivery remains or is recoverable, exit 4 reports static ambiguous delivery, and a later retry may duplicate the request. The next invocation after a successful clear performs the next scan.

Transport, TLS, redirect, deadline, malformed-response, or non-`2xx` failure advances the pending metadata in an authenticated atomic replacement and exits 5. If that retry-metadata write fails, the previous authenticated pending state remains in tested paths and the command exits 4. No failure silently clears the outbox.

## Backoff contract

After completed failed attempt number `n` (starting at 1):

```text
envelope(n) = min(3600, 30 * 2^(n - 1))
delay(n)    = 1 + CSPRNG_randbelow(envelope(n))
next        = current_UTC_unix_second + delay(n)
```

The exponent calculation is capped before shifting, so adversarial counters cannot cause unbounded integer work. The injected jitter seam must return an exact integer in `0..envelope-1`; production uses `secrets.randbelow`. Delay is always at least one second and at most 3600 seconds. Deterministic tests cover both jitter endpoints, exponential growth, the cap, malformed jitter, extreme counters, clock rollback, and future timestamps.

Clock rollback leaves an alert not due until the recorded UTC second, rather than creating a tight retry loop. A clock too near the maximum timestamp or an exhausted bounded counter fails closed before network access with the alert unchanged. There is no maximum-attempt or age-based discard. A permanently pending alert remains visible through static failures and blocks monitoring indefinitely; dead-letter inspection, replay, acknowledgement, and purge are not implemented.

## Migration and compatibility

| Condition | Behavior |
|---|---|
| State absent without `--initialize` | Exit 4 before source access. |
| State absent with `--initialize` | Exit 6 without creating state because a new Chroma baseline would require a disabled scan. |
| Valid authenticated version 2 | Load as having no pending alert; preserve bytes until the next otherwise-valid state transition writes version 3. |
| Failure during v2-to-v3 transition | Preserve the authenticated v2 bytes in tested temporary/replace failure paths; no migration success claim. |
| Version 1 | Static exit 4; preserve bytes because finding-value history cannot be reconstructed. |
| Invalid, unauthenticated, wrong-key, wrong-scope, malformed, or unsupported state | Static exit 4 before source access; preserve bytes. |

Migration does not reconstruct an alert lost under the old checkpoint-before-send ordering. Existing paths need not be renamed. Importable state/webhook helper call shapes changed incompatibly; RAGLeakGuard has no separately versioned stable Python SDK guarantee.

Exit behavior is:

- `0`: a previously pending alert was accepted and durably cleared without a scan;
- `4`: monitor key/state, retry-metadata, or ambiguous clear failure;
- `5`: webhook configuration, pending backoff, safe-retry precondition, preparation, transport, redirect, or response failure.
- `6`: authenticated state has no pending alert and a disabled Chroma new scan would otherwise begin, or an explicitly requested new baseline would require such a scan.

## Residual risks and non-claims

- ChromaDB 1.5.0 and 1.5.9 exhibited durable mutation; other versions have not established an
  acceptable read-only boundary. The bounded operator-snapshot connector activates exact 1.5.9 on
  its finite matrix, but is not used by monitor. RAGLeakGuard does not prove snapshot provenance,
  quiescence, completeness, or atomic consistency. Direct/live access and monitor new scans remain
  disabled.
- Exact path spelling binds scope. Key compromise, insecure backup, rollback to an older valid state, overlapping writers, local runtime compromise, Windows DACL configuration, and host filesystem behavior remain external risks.
- One pending alert and one destination are supported. Receiver outage intentionally blocks all newer scans, potentially forever.
- A crash during or after network transmission can be ambiguous. A clear failure can cause duplicate delivery.
- The [receiver contract](WEBHOOK_PROTOCOL.md) requires durable atomic delivery-ID deduplication, but retention expiry, storage loss, multi-node inconsistency, and a crash or non-atomic boundary between downstream processing and the dedup commit can permit duplicates.
- A `2xx` proves only that response headers met the sender contract. It does not prove storage, forwarding, notification, downstream processing, or human action.
- This implementation makes no exactly-once, unconditional at-least-once, historical-alert recovery, production-safety, compliance, breach-prevention, certified-erasure, connector-completeness, or universal filesystem/platform guarantee.
