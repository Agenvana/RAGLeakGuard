"""Privacy-safe monitor state and authenticated durable webhook alerts.

Version-3 state contains purpose-bound keyed checkpoint data plus one optional,
privacy-minimal pending alert under the existing authenticated-state
construction. Webhook protocol v2 uses a separate operator secret, a stable
delivery ID, a fixed 60-byte body, an exact HTTP/1.1 header allowlist, and one
monotonic-deadline HTTPS request per invocation.
"""
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import math
import os
import queue
import re
import secrets
import socket
import ssl
import stat
import tempfile
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


STATE_VERSION = 3
MIGRATABLE_STATE_VERSION = 2
KEY_FILE_VERSION = 1
KEY_PURPOSE = "ragleakguard.monitor"
CONSTRUCTION_ID = "RLG-MONITOR-HMAC-SHA256-v1"

DIGEST_BYTES = 32
DIGEST_HEX_LENGTH = DIGEST_BYTES * 2
KEY_ID_HEX_LENGTH = 32
KEY_FILE_BYTES = 32
MAX_KEY_FILE_BYTES = 4096
MAX_STATE_FILE_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 1_000_000
MAX_FINDINGS_PER_RECORD = 1_000_000
MAX_TOTAL_FINDINGS = MAX_RECORDS * MAX_FINDINGS_PER_RECORD

PENDING_ALERT_EVENT = "ragleakguard.monitor.exposure-change"
PENDING_ALERT_WEBHOOK_VERSION = 2
MAX_PENDING_ALERT_ATTEMPTS = (1 << 63) - 1
MAX_UNIX_TIME = 253_402_300_799
WEBHOOK_RETRY_BASE_SECONDS = 30
WEBHOOK_RETRY_MAX_SECONDS = 3_600

WEBHOOK_SECRET_FILE_VERSION = 2
WEBHOOK_SECRET_PURPOSE = "ragleakguard.webhook-signing.v2"
WEBHOOK_CONSTRUCTION_ID = "RLG-WEBHOOK-HMAC-SHA256-v2"
WEBHOOK_SECRET_BYTES = 32
MAX_WEBHOOK_SECRET_FILE_BYTES = 4096
MAX_WEBHOOK_URL_BYTES = 2048
MAX_WEBHOOK_RESPONSE_HEADER_BYTES = 64 * 1024
WEBHOOK_DEADLINE_SECONDS = 10.0
WEBHOOK_FRESHNESS_SECONDS = 300
WEBHOOK_METHOD = "POST"
WEBHOOK_CONTENT_TYPE = "application/json"
WEBHOOK_USER_AGENT = "RAGLeakGuard-Webhook/2"
WEBHOOK_VERSION = "2"
WEBHOOK_BODY_BYTES = (
    b'{"event":"ragleakguard.monitor.exposure-change","version":2}'
)
WEBHOOK_HEADER_ORDER = (
    "Host",
    "Content-Length",
    "Content-Type",
    "User-Agent",
    "X-RAGLeakGuard-Webhook-Version",
    "X-RAGLeakGuard-Key-Id",
    "X-RAGLeakGuard-Delivery-Id",
    "X-RAGLeakGuard-Timestamp",
    "X-RAGLeakGuard-Nonce",
    "X-RAGLeakGuard-Signature",
)
WEBHOOK_HEADER_ALLOWLIST = frozenset(WEBHOOK_HEADER_ORDER)

_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[0-9a-f]{32}$")
_ENTITY_TYPE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_DELIVERY_ID = re.compile(r"^[0-9a-f]{32}$")
_WEBHOOK_SIGNATURE = re.compile(r"^v2=[0-9a-f]{64}$")
_WEBHOOK_TIMESTAMP = re.compile(r"^(?:0|[1-9][0-9]*)$")
_HTTP_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_VALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")

_PURPOSE_FINDING = b"finding-token"
_PURPOSE_AGGREGATE = b"aggregate-finding-fingerprint"
_PURPOSE_RECORD = b"record-correlation-token"
_PURPOSE_SCOPE = b"store-scope-binding"
_PURPOSE_STATE_AUTH = b"persisted-state-authentication"

DetectFn = Callable[..., List[Dict[str, Any]]]
TokenDigestFn = Callable[[bytes], bytes]


class MonitorError(Exception):
    """Base class for privacy-safe monitor failures."""


class MonitorKeyError(MonitorError):
    """The explicitly configured monitor key is unavailable or invalid."""


class MonitorKeyMismatchError(MonitorError):
    """The key, construction, or store scope does not match persisted state."""


class MonitorStateError(MonitorError):
    """Persisted monitor state is malformed, corrupt, or unauthenticated."""


class LegacyMonitorStateError(MonitorStateError):
    """Version-1 state cannot be losslessly converted to finding-level history."""


class UnsupportedMonitorStateError(MonitorStateError):
    """The monitor state version is not supported."""


class MonitorFingerprintError(MonitorError):
    """A record or finding cannot be canonicalized or fingerprinted safely."""


class MonitorCollisionError(MonitorFingerprintError):
    """Distinct in-run identities produced the same injected/finding token."""


class MonitorWriteError(MonitorError):
    """A checkpoint could not be written atomically."""


class MonitorInitializationError(MonitorError):
    """Explicit initialization could not safely create a new checkpoint."""


class MonitorBaselineRequiredError(MonitorError):
    """No checkpoint exists and explicit initialization was not authorized."""


class WebhookError(MonitorError):
    """Base class for privacy-safe webhook failures."""


class WebhookConfigurationError(WebhookError):
    """The webhook URL or option configuration is invalid."""


class WebhookSecretError(WebhookError):
    """The dedicated webhook secret could not be generated or loaded."""


class WebhookPreparationError(WebhookError):
    """The fixed alert could not be constructed and signed."""


class WebhookTransportError(WebhookError):
    """The one permitted HTTPS request did not complete successfully."""


class WebhookVerificationError(WebhookError):
    """A received webhook request did not satisfy the version-2 contract."""


class WebhookRetryError(WebhookError):
    """A pending alert cannot safely make or schedule its next attempt."""


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey("Duplicate JSON member.")
        result[key] = value
    return result


def _load_json_strict(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        RecursionError,
    ):
        raise MonitorStateError("Monitor state is invalid.") from None


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise MonitorStateError("Monitor state cannot be canonicalized.") from None


def _frame(label: bytes, value: bytes) -> bytes:
    """Typed, length-prefixed binary framing used by every construction."""
    if not isinstance(label, bytes) or not isinstance(value, bytes):
        raise MonitorFingerprintError("Monitor input cannot be framed.")
    return (
        len(label).to_bytes(4, "big")
        + label
        + len(value).to_bytes(8, "big")
        + value
    )


def _utf8(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise MonitorFingerprintError("Monitor identity input is malformed.")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        raise MonitorFingerprintError("Monitor identity input is malformed.") from None


def _is_exact_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class MonitorKey:
    """Validated operator key; repr deliberately excludes secret material."""

    key_id: str
    _material: bytes = field(repr=False)


@dataclass(frozen=True)
class WebhookSecret:
    """Validated dedicated signing secret; repr excludes all identifying data."""

    key_id: str = field(repr=False)
    _material: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.key_id, str)
            or not _KEY_ID.fullmatch(self.key_id)
            or not isinstance(self._material, bytes)
            or len(self._material) != WEBHOOK_SECRET_BYTES
        ):
            raise WebhookSecretError("Webhook signing secret is invalid.")

    def __repr__(self) -> str:
        return "WebhookSecret(<redacted>)"


@dataclass(frozen=True)
class WebhookTarget:
    """Validated HTTPS destination; repr hides endpoint and authority data."""

    host: str = field(repr=False)
    port: int = field(repr=False)
    authority: str = field(repr=False)
    request_target: str = field(repr=False)

    def __repr__(self) -> str:
        return "WebhookTarget(<redacted>)"


@dataclass(frozen=True)
class PreparedWebhook:
    """Immutable signed request components ready for exactly one transport call."""

    target: WebhookTarget = field(repr=False)
    body: bytes = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)

    def __repr__(self) -> str:
        return "PreparedWebhook(<redacted>)"


@dataclass(frozen=True)
class WebhookVerificationResult:
    """Authenticated receiver result suitable for a successful HTTP response."""

    duplicate: bool

    def __post_init__(self) -> None:
        if not isinstance(self.duplicate, bool):
            raise WebhookVerificationError("Webhook request verification failed.")


class MonitorCrypto:
    """Purpose-separated HMAC-SHA-256 construction for one monitor key."""

    def __init__(self, key: MonitorKey):
        if not isinstance(key, MonitorKey) or len(key._material) != KEY_FILE_BYTES:
            raise MonitorKeyError("Monitor key is invalid.")
        self.key_id = key.key_id
        self._finding_key = self._derive(key._material, _PURPOSE_FINDING)
        self._aggregate_key = self._derive(key._material, _PURPOSE_AGGREGATE)
        self._record_key = self._derive(key._material, _PURPOSE_RECORD)
        self._scope_key = self._derive(key._material, _PURPOSE_SCOPE)
        self._state_auth_key = self._derive(key._material, _PURPOSE_STATE_AUTH)

    def __repr__(self) -> str:
        return "MonitorCrypto(key_id=<non-secret>)"

    @staticmethod
    def _derive(master_key: bytes, purpose: bytes) -> bytes:
        message = (
            _frame(b"construction", CONSTRUCTION_ID.encode("ascii"))
            + _frame(b"operation", b"derive-monitor-subkey")
            + _frame(b"purpose", purpose)
        )
        return hmac.new(master_key, message, hashlib.sha256).digest()

    @staticmethod
    def _mac(key: bytes, purpose: bytes, payload: bytes) -> bytes:
        message = (
            _frame(b"construction", CONSTRUCTION_ID.encode("ascii"))
            + _frame(b"purpose", purpose)
            + _frame(b"payload", payload)
        )
        return hmac.new(key, message, hashlib.sha256).digest()

    def finding_token(self, canonical_finding: bytes) -> bytes:
        return self._mac(self._finding_key, _PURPOSE_FINDING, canonical_finding)

    def aggregate_fingerprint(self, tokens: Sequence[bytes]) -> str:
        ordered = sorted(tokens)
        payload = bytearray(
            _frame(b"finding-count", len(ordered).to_bytes(8, "big"))
        )
        for token in ordered:
            if not isinstance(token, bytes) or len(token) != DIGEST_BYTES:
                raise MonitorFingerprintError("Finding token is invalid.")
            payload.extend(_frame(b"finding-token", token))
        return self._mac(
            self._aggregate_key, _PURPOSE_AGGREGATE, bytes(payload)
        ).hex()

    def scope_token(self, source: str, store_path: str) -> str:
        payload = _frame(b"source", _utf8(source)) + _frame(
            b"store-path", _utf8(store_path)
        )
        return self._mac(self._scope_key, _PURPOSE_SCOPE, payload).hex()

    def record_token(self, scope_token: bytes, collection: str, record_id: str) -> str:
        if not isinstance(scope_token, bytes) or len(scope_token) != DIGEST_BYTES:
            raise MonitorFingerprintError("Store scope token is invalid.")
        payload = (
            _frame(b"store-scope", scope_token)
            + _frame(b"collection", _utf8(collection))
            + _frame(b"record-id", _utf8(record_id))
        )
        return self._mac(self._record_key, _PURPOSE_RECORD, payload).hex()

    def authenticate_state(self, canonical_body: bytes) -> str:
        return self._mac(
            self._state_auth_key,
            _PURPOSE_STATE_AUTH,
            canonical_body,
        ).hex()


def generate_key_file(path: str) -> str:
    """Create a new 256-bit monitor key file without ever overwriting a path."""
    if not isinstance(path, str) or not path:
        raise MonitorKeyError("Monitor key path is invalid.")
    key_id = secrets.token_hex(KEY_ID_HEX_LENGTH // 2)
    key_material = secrets.token_bytes(KEY_FILE_BYTES)
    document = {
        "construction": CONSTRUCTION_ID,
        "key": base64.b64encode(key_material).decode("ascii"),
        "key_id": key_id,
        "purpose": KEY_PURPOSE,
        "version": KEY_FILE_VERSION,
    }
    encoded = (
        json.dumps(document, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = None
    created = False
    try:
        fd = os.open(path, flags, 0o600)
        created = True
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(path, 0o600)
    except (OSError, ValueError):
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if created:
            try:
                os.unlink(path)
            except OSError:
                pass
        raise MonitorKeyError("Monitor key could not be generated.") from None
    return key_id


def _read_regular_file(path: str, maximum: int, *, private: bool) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = None
    try:
        path_stat = os.lstat(path)
        if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
            raise OSError("not a regular non-symlink file")
        fd = os.open(path, flags)
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("not a regular file")
        if (path_stat.st_dev, path_stat.st_ino) != (file_stat.st_dev, file_stat.st_ino):
            raise OSError("file changed during open")
        if private and os.name != "nt" and file_stat.st_mode & 0o077:
            raise OSError("permissions are too broad")
        with os.fdopen(fd, "rb") as handle:
            fd = None
            raw = handle.read(maximum + 1)
        if len(raw) > maximum:
            raise OSError("file is too large")
        return raw
    except OSError:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if private:
            raise MonitorKeyError("Monitor key could not be loaded.") from None
        raise MonitorStateError("Monitor state could not be loaded.") from None


def load_key_file(path: str) -> MonitorKey:
    """Load a strict, monitor-purpose key file without exposing parse failures."""
    if not isinstance(path, str) or not path:
        raise MonitorKeyError("Monitor key path is invalid.")
    raw = _read_regular_file(path, MAX_KEY_FILE_BYTES, private=True)
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
        if not isinstance(document, dict) or set(document) != {
            "construction",
            "key",
            "key_id",
            "purpose",
            "version",
        }:
            raise ValueError
        if (
            not _is_exact_int(document["version"])
            or document["version"] != KEY_FILE_VERSION
            or document["purpose"] != KEY_PURPOSE
            or document["construction"] != CONSTRUCTION_ID
            or not isinstance(document["key_id"], str)
            or not _KEY_ID.fullmatch(document["key_id"])
            or not isinstance(document["key"], str)
        ):
            raise ValueError
        material = base64.b64decode(document["key"].encode("ascii"), validate=True)
        if len(material) != KEY_FILE_BYTES:
            raise ValueError
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        UnicodeEncodeError,
        binascii.Error,
        ValueError,
        TypeError,
        RecursionError,
    ):
        raise MonitorKeyError("Monitor key is malformed or incompatible.") from None
    return MonitorKey(key_id=document["key_id"], _material=material)


def canonicalize_finding(finding: Dict[str, Any]) -> bytes:
    """Encode exact finding type/value identity; position and score are ignored."""
    if not isinstance(finding, dict) or "type" not in finding or "text" not in finding:
        raise MonitorFingerprintError("Finding identity is incomplete.")
    finding_type = finding["type"]
    if not isinstance(finding_type, str) or not _ENTITY_TYPE.fullmatch(finding_type):
        raise MonitorFingerprintError("Finding type is malformed.")
    value = _utf8(finding["text"])
    return _frame(b"finding-type", finding_type.encode("ascii")) + _frame(
        b"detected-value", value
    )


def fingerprint(
    findings: List[Dict[str, Any]],
    crypto: MonitorCrypto,
) -> str:
    """Full-length keyed multiset fingerprint of exact finding type/value pairs."""
    return _fingerprint_with_token_digest(findings, crypto, crypto.finding_token)


def _fingerprint_with_token_digest(
    findings: List[Dict[str, Any]],
    crypto: MonitorCrypto,
    token_digest: TokenDigestFn,
) -> str:
    """Private forced-collision seam; production always calls ``fingerprint``."""
    if not isinstance(crypto, MonitorCrypto):
        raise MonitorKeyError("A monitor key is required for fingerprinting.")
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS_PER_RECORD:
        raise MonitorFingerprintError("Finding collection is malformed or too large.")
    tokens: List[bytes] = []
    identities_by_token: Dict[bytes, bytes] = {}
    for finding in findings:
        identity = canonicalize_finding(finding)
        try:
            token = token_digest(identity)
        except MonitorError:
            raise
        except Exception:
            raise MonitorFingerprintError("Finding token construction failed.") from None
        if not isinstance(token, bytes) or len(token) != DIGEST_BYTES:
            raise MonitorFingerprintError("Finding token construction failed.")
        prior = identities_by_token.get(token)
        if prior is not None and prior != identity:
            raise MonitorCollisionError("Distinct findings produced one finding token.")
        identities_by_token[token] = identity
        tokens.append(token)
    return crypto.aggregate_fingerprint(tokens)


def _type_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        finding_type = finding.get("type") if isinstance(finding, dict) else None
        if not isinstance(finding_type, str) or not _ENTITY_TYPE.fullmatch(finding_type):
            raise MonitorFingerprintError("Finding type is malformed.")
        counts[finding_type] = counts.get(finding_type, 0) + 1
    return {key: counts[key] for key in sorted(counts)}


def build_snapshot(
    items: Iterable[Dict[str, Any]],
    detect_fn: DetectFn,
    crypto: MonitorCrypto,
    scope_token: str,
    locale: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """Scan items into ephemeral token-keyed records; no raw identity is retained."""
    if not isinstance(scope_token, str) or not _HEX_DIGEST.fullmatch(scope_token):
        raise MonitorFingerprintError("Store scope token is invalid.")
    scope_bytes = bytes.fromhex(scope_token)
    records: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if len(records) >= MAX_RECORDS or not isinstance(item, dict):
            raise MonitorFingerprintError("Record collection is malformed or too large.")
        if not all(name in item for name in ("collection", "id", "text")):
            raise MonitorFingerprintError("Record identity is incomplete.")
        collection = item["collection"]
        record_id = item["id"]
        text = item["text"]
        if not isinstance(text, str):
            raise MonitorFingerprintError("Record text is malformed.")
        record_token = crypto.record_token(scope_bytes, collection, record_id)
        if record_token in records:
            raise MonitorCollisionError("Duplicate or colliding record identity detected.")
        found = detect_fn(text, locale=locale)
        record_fingerprint = fingerprint(found, crypto)
        records[record_token] = {
            "fingerprint": record_fingerprint,
            "finding_count": len(found),
            "type_counts": _type_counts(found),
        }
    return records


def diff(
    previous: Dict[str, Dict[str, Any]],
    current: Dict[str, Dict[str, Any]],
) -> Dict[str, List[str]]:
    """Classify tokenized records as new, changed, or resolved."""
    new: List[str] = []
    changed: List[str] = []
    resolved: List[str] = []
    for token, record in current.items():
        old = previous.get(token)
        if old is None:
            if record["finding_count"] > 0:
                new.append(token)
        elif record["fingerprint"] != old["fingerprint"]:
            if old["finding_count"] == 0 and record["finding_count"] > 0:
                new.append(token)
            elif record["finding_count"] == 0:
                resolved.append(token)
            else:
                changed.append(token)
    for token, old in previous.items():
        if token not in current and old["finding_count"] > 0:
            resolved.append(token)
    return {
        "new": sorted(new),
        "changed": sorted(changed),
        "resolved": sorted(resolved),
    }


def _validate_digest(value: Any) -> bool:
    return isinstance(value, str) and _HEX_DIGEST.fullmatch(value) is not None


def _validate_pending_alert(value: Any) -> Optional[Dict[str, Any]]:
    """Validate and copy the exact privacy-minimal one-entry outbox value."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "attempts",
        "delivery_id",
        "event",
        "next_attempt_at",
        "webhook_version",
    }:
        raise MonitorStateError("Monitor pending alert is invalid.")
    if (
        value["event"] != PENDING_ALERT_EVENT
        or not _is_exact_int(value["webhook_version"])
        or value["webhook_version"] != PENDING_ALERT_WEBHOOK_VERSION
        or not isinstance(value["delivery_id"], str)
        or _DELIVERY_ID.fullmatch(value["delivery_id"]) is None
        or not _is_exact_int(value["attempts"])
        or not 0 <= value["attempts"] <= MAX_PENDING_ALERT_ATTEMPTS
        or not _is_exact_int(value["next_attempt_at"])
        or not 0 <= value["next_attempt_at"] <= MAX_UNIX_TIME
    ):
        raise MonitorStateError("Monitor pending alert is invalid.")
    return {name: value[name] for name in sorted(value)}


def _validate_state(
    document: Any,
    crypto: MonitorCrypto,
    expected_scope_token: str,
) -> Dict[str, Any]:
    if not isinstance(document, dict):
        raise MonitorStateError("Monitor state root is invalid.")
    version = document.get("version")
    if version == 1 and _is_exact_int(version):
        raise LegacyMonitorStateError("Version-1 monitor state is incompatible.")
    if not _is_exact_int(version) or version not in {
        MIGRATABLE_STATE_VERSION,
        STATE_VERSION,
    }:
        raise UnsupportedMonitorStateError("Monitor state version is unsupported.")
    expected_fields = {
        "authentication",
        "construction",
        "key_id",
        "records",
        "scope_token",
        "totals",
        "version",
    }
    if version == STATE_VERSION:
        expected_fields.add("pending_alert")
    if set(document) != expected_fields:
        raise MonitorStateError("Monitor state fields are invalid.")
    if document["construction"] != CONSTRUCTION_ID:
        raise MonitorKeyMismatchError("Monitor construction does not match state.")
    key_id = document["key_id"]
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise MonitorStateError("Monitor state key identifier is invalid.")
    if not hmac.compare_digest(key_id, crypto.key_id):
        raise MonitorKeyMismatchError("Monitor key does not match state.")
    scope_token = document["scope_token"]
    if not _validate_digest(scope_token):
        raise MonitorStateError("Monitor state scope is invalid.")
    if not _validate_digest(expected_scope_token) or not hmac.compare_digest(
        scope_token, expected_scope_token
    ):
        raise MonitorKeyMismatchError("Monitor store scope does not match state.")

    records = document["records"]
    totals = document["totals"]
    if not isinstance(records, dict) or len(records) > MAX_RECORDS:
        raise MonitorStateError("Monitor state records are invalid.")
    if not isinstance(totals, dict) or set(totals) != {"findings", "records"}:
        raise MonitorStateError("Monitor state totals are invalid.")
    if (
        not _is_exact_int(totals["records"])
        or not 0 <= totals["records"] <= MAX_RECORDS
        or not _is_exact_int(totals["findings"])
        or not 0 <= totals["findings"] <= MAX_TOTAL_FINDINGS
    ):
        raise MonitorStateError("Monitor state totals are invalid.")

    empty_fingerprint = crypto.aggregate_fingerprint([])
    finding_total = 0
    for token, record in records.items():
        if not isinstance(token, str) or not _HEX_DIGEST.fullmatch(token):
            raise MonitorStateError("Monitor record token is invalid.")
        if not isinstance(record, dict) or set(record) != {
            "finding_count",
            "fingerprint",
        }:
            raise MonitorStateError("Monitor record fields are invalid.")
        finding_count = record["finding_count"]
        record_fingerprint = record["fingerprint"]
        if (
            not _is_exact_int(finding_count)
            or not 0 <= finding_count <= MAX_FINDINGS_PER_RECORD
            or not _validate_digest(record_fingerprint)
            or (finding_count == 0 and record_fingerprint != empty_fingerprint)
            or (finding_count > 0 and record_fingerprint == empty_fingerprint)
        ):
            raise MonitorStateError("Monitor record value is inconsistent.")
        finding_total += finding_count

    if totals["records"] != len(records) or totals["findings"] != finding_total:
        raise MonitorStateError("Monitor state totals are inconsistent.")

    if version == STATE_VERSION:
        _validate_pending_alert(document["pending_alert"])

    authentication = document["authentication"]
    if not _validate_digest(authentication):
        raise MonitorStateError("Monitor state authentication is invalid.")
    body = {key: value for key, value in document.items() if key != "authentication"}
    expected_authentication = crypto.authenticate_state(_canonical_json(body))
    if not hmac.compare_digest(authentication, expected_authentication):
        raise MonitorStateError("Monitor state authentication failed.")
    return document


def _build_state_document(
    records: Dict[str, Dict[str, Any]],
    crypto: MonitorCrypto,
    scope_token: str,
    pending_alert: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    persisted_records: Dict[str, Dict[str, Any]] = {}
    finding_total = 0
    if not isinstance(records, dict) or len(records) > MAX_RECORDS:
        raise MonitorStateError("Monitor snapshot records are invalid.")
    for token, record in records.items():
        if not isinstance(token, str) or not _HEX_DIGEST.fullmatch(token):
            raise MonitorStateError("Monitor snapshot token is invalid.")
        if not isinstance(record, dict):
            raise MonitorStateError("Monitor snapshot record is invalid.")
        record_fingerprint = record.get("fingerprint")
        finding_count = record.get("finding_count")
        if (
            not _validate_digest(record_fingerprint)
            or not _is_exact_int(finding_count)
            or not 0 <= finding_count <= MAX_FINDINGS_PER_RECORD
        ):
            raise MonitorStateError("Monitor snapshot record is invalid.")
        persisted_records[token] = {
            "finding_count": finding_count,
            "fingerprint": record_fingerprint,
        }
        finding_total += finding_count
    body = {
        "construction": CONSTRUCTION_ID,
        "key_id": crypto.key_id,
        "pending_alert": _validate_pending_alert(pending_alert),
        "records": persisted_records,
        "scope_token": scope_token,
        "totals": {"findings": finding_total, "records": len(persisted_records)},
        "version": STATE_VERSION,
    }
    document = dict(body)
    document["authentication"] = crypto.authenticate_state(_canonical_json(body))
    return _validate_state(document, crypto, scope_token)


def serialize_state(
    records: Dict[str, Dict[str, Any]],
    crypto: MonitorCrypto,
    scope_token: str,
    pending_alert: Optional[Dict[str, Any]] = None,
) -> bytes:
    """Return the strict authenticated version-3 state serialization."""
    document = _build_state_document(
        records,
        crypto,
        scope_token,
        pending_alert,
    )
    encoded = (
        json.dumps(document, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_STATE_FILE_BYTES:
        raise MonitorStateError("Monitor state is too large.")
    return encoded


def load_state(
    path: str,
    crypto: MonitorCrypto,
    scope_token: str,
) -> Optional[Dict[str, Any]]:
    """Load and fully validate state, or return ``None`` only when absent."""
    if not isinstance(path, str) or not path:
        raise MonitorStateError("Monitor state path is invalid.")
    if not os.path.lexists(path):
        return None
    raw = _read_regular_file(path, MAX_STATE_FILE_BYTES, private=False)
    return _validate_state(_load_json_strict(raw), crypto, scope_token)


def _write_state_bytes(handle, encoded: bytes) -> None:
    """Small failure-injection seam for temporary-file write tests."""
    handle.write(encoded)


def _write_state_temp(directory: str, encoded: bytes) -> str:
    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=directory,
            prefix=".rlg-monitor-",
            suffix=".tmp",
        )
        if os.name != "nt":
            os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            _write_state_bytes(handle, encoded)
            handle.flush()
            os.fsync(handle.fileno())
        return tmp_path
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise MonitorWriteError("Monitor temporary checkpoint write failed.") from None


def _replace_state(tmp_path: str, path: str) -> None:
    """Failure-injection seam for atomic replacement tests."""
    os.replace(tmp_path, path)


def _install_new_state(tmp_path: str, path: str) -> None:
    """Atomically create a target without overwriting an existing path."""
    os.link(tmp_path, path)


def save_state(
    path: str,
    records: Dict[str, Dict[str, Any]],
    crypto: MonitorCrypto,
    scope_token: str,
    *,
    pending_alert: Optional[Dict[str, Any]] = None,
    initialize: bool = False,
) -> None:
    """Same-directory atomic checkpoint update or explicit no-overwrite init."""
    if not isinstance(path, str) or not path:
        raise MonitorWriteError("Monitor state path is invalid.")
    if initialize and os.path.lexists(path):
        raise MonitorInitializationError("Monitor state already exists.")
    encoded = serialize_state(records, crypto, scope_token, pending_alert)
    directory = os.path.dirname(os.path.abspath(path))
    tmp_path = _write_state_temp(directory, encoded)
    installed = False
    try:
        if initialize:
            try:
                _install_new_state(tmp_path, path)
            except FileExistsError:
                raise MonitorInitializationError("Monitor state already exists.") from None
            installed = True
        else:
            _replace_state(tmp_path, path)
            tmp_path = ""
    except MonitorInitializationError:
        raise
    except Exception:
        raise MonitorWriteError("Monitor checkpoint replacement failed.") from None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                if not installed:
                    pass


def _sample_unix_time(clock: Callable[[], Any]) -> int:
    sampled = clock()
    if isinstance(sampled, bool) or not isinstance(sampled, (int, float)):
        raise ValueError
    if not math.isfinite(sampled) or not 0 <= sampled <= MAX_UNIX_TIME:
        raise ValueError
    return int(sampled)


def new_pending_alert(
    *,
    clock: Optional[Callable[[], Any]] = None,
    delivery_id_source: Optional[Callable[[int], bytes]] = None,
) -> Dict[str, Any]:
    """Construct one due-now outbox entry without preparing a network request."""
    try:
        clock = time.time if clock is None else clock
        delivery_id_source = (
            secrets.token_bytes
            if delivery_id_source is None
            else delivery_id_source
        )
        delivery_bytes = delivery_id_source(16)
        if not isinstance(delivery_bytes, bytes) or len(delivery_bytes) != 16:
            raise ValueError
        now = _sample_unix_time(clock)
        if now > MAX_UNIX_TIME - WEBHOOK_RETRY_MAX_SECONDS:
            raise ValueError
        pending = {
            "attempts": 0,
            "delivery_id": delivery_bytes.hex(),
            "event": PENDING_ALERT_EVENT,
            "next_attempt_at": now,
            "webhook_version": PENDING_ALERT_WEBHOOK_VERSION,
        }
        validated = _validate_pending_alert(pending)
        if validated is None:
            raise ValueError
        return validated
    except Exception:
        raise WebhookPreparationError("Webhook alert preparation failed.") from None


def pending_alert_is_due(
    pending_alert: Dict[str, Any],
    *,
    clock: Optional[Callable[[], Any]] = None,
) -> bool:
    """Return whether one pending alert may attempt now without overflow risk."""
    try:
        pending = _validate_pending_alert(pending_alert)
        if pending is None or pending["attempts"] >= MAX_PENDING_ALERT_ATTEMPTS:
            raise ValueError
        clock = time.time if clock is None else clock
        now = _sample_unix_time(clock)
        if now > MAX_UNIX_TIME - WEBHOOK_RETRY_MAX_SECONDS:
            raise ValueError
        return now >= pending["next_attempt_at"]
    except Exception:
        raise WebhookRetryError("Webhook retry cannot proceed safely.") from None


def retry_backoff_seconds(
    completed_attempts: int,
    *,
    jitter_source: Optional[Callable[[int], int]] = None,
) -> int:
    """Return full-jitter delay ``1..min(3600, 30*2**(n-1))`` seconds."""
    try:
        if (
            not _is_exact_int(completed_attempts)
            or not 1 <= completed_attempts <= MAX_PENDING_ALERT_ATTEMPTS
        ):
            raise ValueError
        growth_steps = min(
            completed_attempts - 1,
            WEBHOOK_RETRY_MAX_SECONDS.bit_length(),
        )
        envelope = min(
            WEBHOOK_RETRY_MAX_SECONDS,
            WEBHOOK_RETRY_BASE_SECONDS * (1 << growth_steps),
        )
        jitter_source = secrets.randbelow if jitter_source is None else jitter_source
        jitter = jitter_source(envelope)
        if not _is_exact_int(jitter) or not 0 <= jitter < envelope:
            raise ValueError
        return 1 + jitter
    except Exception:
        raise WebhookRetryError("Webhook retry cannot proceed safely.") from None


def advance_pending_alert(
    pending_alert: Dict[str, Any],
    *,
    clock: Optional[Callable[[], Any]] = None,
    jitter_source: Optional[Callable[[int], int]] = None,
) -> Dict[str, Any]:
    """Record one completed failed attempt and its bounded next-attempt time."""
    try:
        pending = _validate_pending_alert(pending_alert)
        if pending is None or pending["attempts"] >= MAX_PENDING_ALERT_ATTEMPTS:
            raise ValueError
        attempts = pending["attempts"] + 1
        clock = time.time if clock is None else clock
        now = _sample_unix_time(clock)
        if now > MAX_UNIX_TIME - WEBHOOK_RETRY_MAX_SECONDS:
            raise ValueError
        delay = retry_backoff_seconds(
            attempts,
            jitter_source=jitter_source,
        )
        updated = dict(pending)
        updated["attempts"] = attempts
        updated["next_attempt_at"] = now + delay
        validated = _validate_pending_alert(updated)
        if validated is None:
            raise ValueError
        return validated
    except WebhookRetryError:
        raise
    except Exception:
        raise WebhookRetryError("Webhook retry cannot proceed safely.") from None


def generate_webhook_secret_file(path: str) -> str:
    """Create a dedicated 256-bit webhook secret without overwriting a path."""
    if not isinstance(path, str) or not path:
        raise WebhookSecretError("Webhook signing secret path is invalid.")
    fd = None
    created = False
    try:
        secret = WebhookSecret(
            secrets.token_hex(KEY_ID_HEX_LENGTH // 2),
            secrets.token_bytes(WEBHOOK_SECRET_BYTES),
        )
        document = {
            "construction": WEBHOOK_CONSTRUCTION_ID,
            "key_id": secret.key_id,
            "purpose": WEBHOOK_SECRET_PURPOSE,
            "secret": base64.b64encode(secret._material).decode("ascii"),
            "version": WEBHOOK_SECRET_FILE_VERSION,
        }
        encoded = (
            json.dumps(document, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
        ).encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        created = True
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(path, 0o600)
        return secret.key_id
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if created:
            try:
                os.unlink(path)
            except OSError:
                pass
        raise WebhookSecretError(
            "Webhook signing secret could not be generated."
        ) from None


def load_webhook_secret_file(path: str) -> WebhookSecret:
    """Strictly load a purpose-bound webhook signing secret."""
    if not isinstance(path, str) or not path:
        raise WebhookSecretError("Webhook signing secret path is invalid.")
    try:
        raw = _read_regular_file(
            path, MAX_WEBHOOK_SECRET_FILE_BYTES, private=True
        )
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
        if not isinstance(document, dict) or set(document) != {
            "construction",
            "key_id",
            "purpose",
            "secret",
            "version",
        }:
            raise ValueError
        if (
            not _is_exact_int(document["version"])
            or document["version"] != WEBHOOK_SECRET_FILE_VERSION
            or document["purpose"] != WEBHOOK_SECRET_PURPOSE
            or document["construction"] != WEBHOOK_CONSTRUCTION_ID
            or not isinstance(document["key_id"], str)
            or not _KEY_ID.fullmatch(document["key_id"])
            or not isinstance(document["secret"], str)
        ):
            raise ValueError
        encoded_secret = document["secret"].encode("ascii")
        material = base64.b64decode(encoded_secret, validate=True)
        if (
            len(material) != WEBHOOK_SECRET_BYTES
            or base64.b64encode(material) != encoded_secret
        ):
            raise ValueError
        return WebhookSecret(document["key_id"], material)
    except (
        MonitorKeyError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        UnicodeEncodeError,
        binascii.Error,
        ValueError,
        TypeError,
        RecursionError,
        WebhookSecretError,
    ):
        raise WebhookSecretError(
            "Webhook signing secret is unavailable or invalid."
        ) from None


def _validate_percent_escapes(value: str) -> None:
    if _VALID_PERCENT_ESCAPE.search(value):
        raise WebhookConfigurationError("Webhook URL is invalid.")


def _normalize_host(host: str) -> Tuple[str, str]:
    if not isinstance(host, str) or not host:
        raise WebhookConfigurationError("Webhook URL is invalid.")
    lowered = host.lower()
    if "%" in lowered:
        raise WebhookConfigurationError("Webhook URL is invalid.")
    if ":" in lowered:
        try:
            normalized = ipaddress.IPv6Address(lowered).compressed
        except ValueError:
            raise WebhookConfigurationError("Webhook URL is invalid.") from None
        return normalized, "[{}]".format(normalized)
    if len(lowered) > 253:
        raise WebhookConfigurationError("Webhook URL is invalid.")
    labels_value = lowered[:-1] if lowered.endswith(".") else lowered
    labels = labels_value.split(".")
    if not labels or any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise WebhookConfigurationError("Webhook URL is invalid.")
    return lowered, lowered


def validate_webhook_url(url: str) -> WebhookTarget:
    """Validate and normalize one HTTPS URL without exposing it in errors."""
    try:
        if not isinstance(url, str):
            raise ValueError
        encoded = url.encode("ascii")
        if not encoded or len(encoded) > MAX_WEBHOOK_URL_BYTES:
            raise ValueError
        if any(byte <= 0x20 or byte == 0x7F for byte in encoded):
            raise ValueError
        if "\\" in url or "#" in url:
            raise ValueError
        _validate_percent_escapes(url)
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            raise ValueError
        if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
            raise ValueError
        if parsed.netloc.endswith(":"):
            raise ValueError
        if parsed.netloc.startswith("["):
            if re.fullmatch(
                r"\[[0-9A-Fa-f:.]+\](?::[0-9]+)?", parsed.netloc
            ) is None:
                raise ValueError
        elif re.fullmatch(
            r"[A-Za-z0-9.-]+(?::[0-9]+)?", parsed.netloc
        ) is None:
            raise ValueError
        host = parsed.hostname
        port = parsed.port
        normalized_host, host_header = _normalize_host(host)
        if port is None:
            port = 443
        if not _is_exact_int(port) or not 1 <= port <= 65535:
            raise ValueError
        authority = host_header if port == 443 else "{}:{}".format(host_header, port)
        prefix_length = len(parsed.scheme) + 3 + len(parsed.netloc)
        suffix = url[prefix_length:]
        if suffix == "":
            request_target = "/"
        elif suffix.startswith("?"):
            request_target = "/" + suffix
        elif suffix.startswith("/"):
            request_target = suffix
        else:
            raise ValueError
        _validate_request_target(request_target)
        return WebhookTarget(
            host=normalized_host,
            port=port,
            authority=authority,
            request_target=request_target,
        )
    except (UnicodeEncodeError, ValueError, WebhookConfigurationError):
        raise WebhookConfigurationError("Webhook URL is invalid.") from None


def _validate_request_target(request_target: str) -> None:
    try:
        encoded = request_target.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        raise WebhookConfigurationError("Webhook request target is invalid.") from None
    if (
        not encoded
        or len(encoded) > MAX_WEBHOOK_URL_BYTES
        or not request_target.startswith("/")
        or "#" in request_target
        or "\\" in request_target
        or any(byte <= 0x20 or byte == 0x7F for byte in encoded)
    ):
        raise WebhookConfigurationError("Webhook request target is invalid.")
    _validate_percent_escapes(request_target)


def _validate_received_target(authority: str, request_target: str) -> None:
    try:
        validated = validate_webhook_url(
            "https://{}{}".format(authority, request_target)
        )
    except (TypeError, WebhookConfigurationError):
        raise WebhookVerificationError("Webhook request verification failed.") from None
    if (
        validated.authority != authority
        or validated.request_target != request_target
    ):
        raise WebhookVerificationError("Webhook request verification failed.")


def _target_is_consistent(target: Any) -> bool:
    if not isinstance(target, WebhookTarget):
        return False
    try:
        reconstructed = validate_webhook_url(
            "https://{}{}".format(target.authority, target.request_target)
        )
    except WebhookConfigurationError:
        return False
    return reconstructed == target


def build_webhook_body() -> bytes:
    """Return the one canonical immutable 60-byte version-2 event body."""
    try:
        encoded = json.dumps(
            {
                "event": PENDING_ALERT_EVENT,
                "version": PENDING_ALERT_WEBHOOK_VERSION,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise WebhookPreparationError("Webhook alert preparation failed.") from None
    if encoded != WEBHOOK_BODY_BYTES or len(encoded) != 60:
        raise WebhookPreparationError("Webhook alert preparation failed.")
    return WEBHOOK_BODY_BYTES


def _webhook_frame(label: str, value: bytes) -> bytes:
    try:
        label_bytes = label.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        raise WebhookPreparationError("Webhook alert preparation failed.") from None
    if not isinstance(value, bytes):
        raise WebhookPreparationError("Webhook alert preparation failed.")
    return (
        len(label_bytes).to_bytes(4, "big")
        + label_bytes
        + len(value).to_bytes(8, "big")
        + value
    )


def _header_ascii(headers: Mapping[str, str], name: str) -> bytes:
    try:
        value = headers[name]
        if not isinstance(value, str):
            raise ValueError
        return value.encode("ascii")
    except (KeyError, UnicodeEncodeError, ValueError):
        raise WebhookPreparationError("Webhook alert preparation failed.") from None


def build_webhook_signing_bytes(
    method: str,
    authority: str,
    request_target: str,
    headers: Mapping[str, str],
    body: bytes,
) -> bytes:
    """Frame the exact version-2 signed fields in their public order."""
    try:
        if method != WEBHOOK_METHOD or not isinstance(headers, Mapping):
            raise ValueError
        method_bytes = method.encode("ascii")
        authority_bytes = authority.encode("ascii")
        target_bytes = request_target.encode("ascii")
        if headers.get("Host") != authority:
            raise ValueError
        values = (
            ("construction", WEBHOOK_CONSTRUCTION_ID.encode("ascii")),
            ("method", method_bytes),
            ("authority", authority_bytes),
            ("request-target", target_bytes),
            ("content-length", _header_ascii(headers, "Content-Length")),
            ("content-type", _header_ascii(headers, "Content-Type")),
            ("user-agent", _header_ascii(headers, "User-Agent")),
            (
                "webhook-version",
                _header_ascii(headers, "X-RAGLeakGuard-Webhook-Version"),
            ),
            ("key-id", _header_ascii(headers, "X-RAGLeakGuard-Key-Id")),
            (
                "delivery-id",
                _header_ascii(headers, "X-RAGLeakGuard-Delivery-Id"),
            ),
            ("timestamp", _header_ascii(headers, "X-RAGLeakGuard-Timestamp")),
            ("nonce", _header_ascii(headers, "X-RAGLeakGuard-Nonce")),
            ("body", body),
        )
        return b"".join(_webhook_frame(label, value) for label, value in values)
    except (AttributeError, UnicodeEncodeError, ValueError, WebhookPreparationError):
        raise WebhookPreparationError("Webhook alert preparation failed.") from None


def _sign_webhook(
    secret: WebhookSecret,
    target: WebhookTarget,
    headers: Mapping[str, str],
    body: bytes,
) -> str:
    if not isinstance(secret, WebhookSecret) or not isinstance(target, WebhookTarget):
        raise WebhookPreparationError("Webhook alert preparation failed.")
    signing_bytes = build_webhook_signing_bytes(
        WEBHOOK_METHOD,
        target.authority,
        target.request_target,
        headers,
        body,
    )
    return "v2=" + hmac.new(
        secret._material, signing_bytes, hashlib.sha256
    ).hexdigest()


def prepare_webhook_request(
    alert_trigger: bool,
    target: WebhookTarget,
    secret: WebhookSecret,
    delivery_id: str,
    *,
    clock: Optional[Callable[[], Any]] = None,
    nonce_source: Optional[Callable[[int], bytes]] = None,
) -> PreparedWebhook:
    """Build and sign one fresh attempt for an already-durable alert."""
    try:
        if alert_trigger is not True:
            raise ValueError
        if (
            not _target_is_consistent(target)
            or not isinstance(secret, WebhookSecret)
            or not isinstance(delivery_id, str)
            or _DELIVERY_ID.fullmatch(delivery_id) is None
        ):
            raise ValueError
        clock = time.time if clock is None else clock
        nonce_source = secrets.token_bytes if nonce_source is None else nonce_source
        timestamp = str(_sample_unix_time(clock))
        if not _WEBHOOK_TIMESTAMP.fullmatch(timestamp):
            raise ValueError
        nonce_bytes = nonce_source(16)
        if not isinstance(nonce_bytes, bytes) or len(nonce_bytes) != 16:
            raise ValueError
        nonce = nonce_bytes.hex()
        body = build_webhook_body()
        unsigned_headers = {
            "Host": target.authority,
            "Content-Length": str(len(body)),
            "Content-Type": WEBHOOK_CONTENT_TYPE,
            "User-Agent": WEBHOOK_USER_AGENT,
            "X-RAGLeakGuard-Webhook-Version": WEBHOOK_VERSION,
            "X-RAGLeakGuard-Key-Id": secret.key_id,
            "X-RAGLeakGuard-Delivery-Id": delivery_id,
            "X-RAGLeakGuard-Timestamp": timestamp,
            "X-RAGLeakGuard-Nonce": nonce,
        }
        signature = _sign_webhook(secret, target, unsigned_headers, body)
        headers = dict(unsigned_headers)
        headers["X-RAGLeakGuard-Signature"] = signature
        if tuple(headers) != WEBHOOK_HEADER_ORDER or set(headers) != WEBHOOK_HEADER_ALLOWLIST:
            raise ValueError
        return PreparedWebhook(
            target=target,
            body=body,
            headers=MappingProxyType(headers),
        )
    except Exception:
        raise WebhookPreparationError("Webhook alert preparation failed.") from None


def _received_headers(
    headers: Iterable[Tuple[str, str]],
) -> Dict[str, str]:
    try:
        pairs = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
        result: Dict[str, str] = {}
        for pair in pairs:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ValueError
            name, value = pair
            if (
                not isinstance(name, str)
                or not isinstance(value, str)
                or name in result
            ):
                raise ValueError
            name.encode("ascii")
            value_bytes = value.encode("ascii")
            if any(byte < 0x20 or byte == 0x7F for byte in value_bytes):
                raise ValueError
            result[name] = value
        if set(result) != WEBHOOK_HEADER_ALLOWLIST:
            raise ValueError
        return result
    except (TypeError, ValueError, UnicodeEncodeError):
        raise WebhookVerificationError(
            "Webhook request verification failed."
        ) from None


class WebhookReplayCache:
    """Process-local atomic nonce cache for the receiver helper."""

    def __init__(self) -> None:
        self._entries: Dict[Tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "WebhookReplayCache(<redacted>)"

    def accept(self, key_id: str, nonce: str, timestamp: int, now: int) -> bool:
        with self._lock:
            expired = [
                key for key, expires_at in self._entries.items() if expires_at < now
            ]
            for key in expired:
                del self._entries[key]
            replay_key = (key_id, nonce)
            if replay_key in self._entries:
                return False
            self._entries[replay_key] = timestamp + WEBHOOK_FRESHNESS_SECONDS
            return True


class WebhookMemoryDeliveryStore:
    """Process-local reference implementation of the atomic delivery interface.

    Production receivers need a durable implementation shared by all nodes.
    """

    def __init__(self) -> None:
        self._accepted = set()
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "WebhookMemoryDeliveryStore(<redacted>)"

    def process_once(
        self,
        key_id: str,
        delivery_id: str,
        processor: Callable[[], Any],
    ) -> bool:
        """Atomically run ``processor`` for a new ID; return false for duplicate."""
        with self._lock:
            delivery_key = (key_id, delivery_id)
            if delivery_key in self._accepted:
                return False
            processor()
            self._accepted.add(delivery_key)
            return True


def verify_webhook_request(
    *,
    method: str,
    authority: str,
    request_target: str,
    headers: Iterable[Tuple[str, str]],
    body: bytes,
    secrets_by_key_id: Mapping[str, Any],
    receiver_now: int,
    replay_cache: Any,
    delivery_store: Any,
    process_event: Callable[[], Any],
) -> WebhookVerificationResult:
    """Verify v2, then process or acknowledge one authenticated delivery ID."""
    try:
        received = _received_headers(headers)
        if method != WEBHOOK_METHOD or received["Host"] != authority:
            raise ValueError
        _validate_received_target(authority, request_target)
        if body != WEBHOOK_BODY_BYTES or len(body) != 60:
            raise ValueError
        if (
            received["Content-Length"] != "60"
            or received["Content-Type"] != WEBHOOK_CONTENT_TYPE
            or received["User-Agent"] != WEBHOOK_USER_AGENT
            or received["X-RAGLeakGuard-Webhook-Version"] != WEBHOOK_VERSION
        ):
            raise ValueError
        key_id = received["X-RAGLeakGuard-Key-Id"]
        delivery_id = received["X-RAGLeakGuard-Delivery-Id"]
        timestamp_text = received["X-RAGLeakGuard-Timestamp"]
        nonce = received["X-RAGLeakGuard-Nonce"]
        signature = received["X-RAGLeakGuard-Signature"]
        if (
            not _KEY_ID.fullmatch(key_id)
            or not _DELIVERY_ID.fullmatch(delivery_id)
            or not _WEBHOOK_TIMESTAMP.fullmatch(timestamp_text)
            or not _KEY_ID.fullmatch(nonce)
            or not _WEBHOOK_SIGNATURE.fullmatch(signature)
        ):
            raise ValueError
        if not isinstance(secrets_by_key_id, Mapping) or key_id not in secrets_by_key_id:
            raise ValueError
        selected = secrets_by_key_id[key_id]
        if isinstance(selected, WebhookSecret):
            if selected.key_id != key_id:
                raise ValueError
            material = selected._material
        else:
            material = selected
        if not isinstance(material, bytes) or len(material) != WEBHOOK_SECRET_BYTES:
            raise ValueError
        signing_bytes = build_webhook_signing_bytes(
            method, authority, request_target, received, body
        )
        expected = "v2=" + hmac.new(material, signing_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError

        timestamp = int(timestamp_text)
        if not _is_exact_int(receiver_now) or receiver_now < 0:
            raise ValueError
        if abs(receiver_now - timestamp) > WEBHOOK_FRESHNESS_SECONDS:
            raise ValueError
        accept_nonce = getattr(replay_cache, "accept", None)
        if not callable(accept_nonce):
            raise ValueError
        if not accept_nonce(key_id, nonce, timestamp, receiver_now):
            raise ValueError
        process_once = getattr(delivery_store, "process_once", None)
        if not callable(process_once) or not callable(process_event):
            raise ValueError
        processed = process_once(key_id, delivery_id, process_event)
        if not isinstance(processed, bool):
            raise ValueError
        return WebhookVerificationResult(duplicate=not processed)
    except Exception:
        raise WebhookVerificationError(
            "Webhook request verification failed."
        ) from None


def _remaining(deadline: float, monotonic: Callable[[], float]) -> float:
    try:
        remaining = deadline - monotonic()
    except Exception:
        raise WebhookTransportError("Webhook delivery failed.") from None
    if remaining <= 0:
        raise WebhookTransportError("Webhook delivery failed.")
    return remaining


def _resolve_addresses(
    host: str,
    port: int,
    deadline: float,
    monotonic: Callable[[], float],
) -> List[Tuple[Any, ...]]:
    """Bound blocking platform DNS by handing it to a daemon resolver thread."""
    results: queue.Queue = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            addresses = socket.getaddrinfo(
                host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except Exception:
            results.put((False, None))
        else:
            results.put((True, addresses))

    thread = threading.Thread(
        target=resolve,
        name="rlg-webhook-dns",
        daemon=True,
    )
    thread.start()
    try:
        ok, addresses = results.get(timeout=_remaining(deadline, monotonic))
    except queue.Empty:
        raise WebhookTransportError("Webhook delivery failed.") from None
    if not ok or not addresses:
        raise WebhookTransportError("Webhook delivery failed.")
    return addresses


def _connect_address(
    addresses: Sequence[Tuple[Any, ...]],
    deadline: float,
    monotonic: Callable[[], float],
) -> socket.socket:
    for family, socktype, proto, _canonical_name, address in addresses:
        raw = None
        try:
            raw = socket.socket(family, socktype, proto)
            raw.settimeout(_remaining(deadline, monotonic))
            raw.connect(address)
            return raw
        except Exception:
            if raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass
    raise WebhookTransportError("Webhook delivery failed.")


def _validate_prepared_request(prepared: PreparedWebhook) -> None:
    if (
        not isinstance(prepared, PreparedWebhook)
        or not _target_is_consistent(prepared.target)
        or prepared.body is not WEBHOOK_BODY_BYTES
        or len(prepared.body) != 60
        or not isinstance(prepared.headers, Mapping)
        or tuple(prepared.headers) != WEBHOOK_HEADER_ORDER
        or set(prepared.headers) != WEBHOOK_HEADER_ALLOWLIST
        or prepared.headers["Host"] != prepared.target.authority
        or prepared.headers["Content-Length"] != "60"
        or prepared.headers["Content-Type"] != WEBHOOK_CONTENT_TYPE
        or prepared.headers["User-Agent"] != WEBHOOK_USER_AGENT
        or prepared.headers["X-RAGLeakGuard-Webhook-Version"] != WEBHOOK_VERSION
        or not _KEY_ID.fullmatch(prepared.headers["X-RAGLeakGuard-Key-Id"])
        or not _DELIVERY_ID.fullmatch(
            prepared.headers["X-RAGLeakGuard-Delivery-Id"]
        )
        or not _WEBHOOK_TIMESTAMP.fullmatch(
            prepared.headers["X-RAGLeakGuard-Timestamp"]
        )
        or not _KEY_ID.fullmatch(prepared.headers["X-RAGLeakGuard-Nonce"])
        or not _WEBHOOK_SIGNATURE.fullmatch(
            prepared.headers["X-RAGLeakGuard-Signature"]
        )
    ):
        raise WebhookTransportError("Webhook delivery failed.")


def _request_head(prepared: PreparedWebhook) -> bytes:
    try:
        lines = [
            "{} {} HTTP/1.1".format(
                WEBHOOK_METHOD, prepared.target.request_target
            )
        ]
        lines.extend(
            "{}: {}".format(name, prepared.headers[name])
            for name in WEBHOOK_HEADER_ORDER
        )
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    except Exception:
        raise WebhookTransportError("Webhook delivery failed.") from None


def _read_response_headers(
    tls_socket: ssl.SSLSocket,
    deadline: float,
    monotonic: Callable[[], float],
) -> bytes:
    response = bytearray()
    while not response.endswith(b"\r\n\r\n"):
        if len(response) >= MAX_WEBHOOK_RESPONSE_HEADER_BYTES:
            raise WebhookTransportError("Webhook delivery failed.")
        tls_socket.settimeout(_remaining(deadline, monotonic))
        chunk = tls_socket.recv(1)
        if not chunk:
            raise WebhookTransportError("Webhook delivery failed.")
        response.extend(chunk)
    return bytes(response)


def _response_status(raw_headers: bytes) -> int:
    try:
        if not raw_headers.endswith(b"\r\n\r\n"):
            raise ValueError
        lines = raw_headers[:-4].split(b"\r\n")
        status_line = lines[0].decode("ascii")
        match = re.fullmatch(r"HTTP/1\.1 ([0-9]{3})(?: [\x20-\x7e]*)?", status_line)
        if match is None:
            raise ValueError
        for raw_line in lines[1:]:
            line = raw_line.decode("ascii")
            if line.startswith((" ", "\t")) or ":" not in line:
                raise ValueError
            name, value = line.split(":", 1)
            if not _HTTP_TOKEN.fullmatch(name):
                raise ValueError
            value_bytes = value.encode("ascii")
            if any(
                byte not in (0x09,) and not 0x20 <= byte <= 0x7E
                for byte in value_bytes
            ):
                raise ValueError
        return int(match.group(1))
    except (IndexError, UnicodeDecodeError, ValueError):
        raise WebhookTransportError("Webhook delivery failed.") from None


def post_webhook(prepared: PreparedWebhook) -> int:
    """Send one HTTPS POST under one DNS-to-response-headers deadline."""
    raw_socket = None
    tls_socket = None
    monotonic = time.monotonic
    try:
        _validate_prepared_request(prepared)
        request_head = _request_head(prepared)
        started = monotonic()
        deadline = started + WEBHOOK_DEADLINE_SECONDS
        addresses = _resolve_addresses(
            prepared.target.host,
            prepared.target.port,
            deadline,
            monotonic,
        )
        raw_socket = _connect_address(addresses, deadline, monotonic)
        context = ssl.create_default_context()
        tls_socket = context.wrap_socket(
            raw_socket,
            server_hostname=prepared.target.host,
            do_handshake_on_connect=False,
        )
        tls_socket.settimeout(_remaining(deadline, monotonic))
        tls_socket.do_handshake()
        tls_socket.settimeout(_remaining(deadline, monotonic))
        tls_socket.sendall(request_head)
        tls_socket.settimeout(_remaining(deadline, monotonic))
        tls_socket.sendall(prepared.body)
        status = _response_status(
            _read_response_headers(tls_socket, deadline, monotonic)
        )
        if not 200 <= status <= 299:
            raise WebhookTransportError("Webhook delivery failed.")
        return status
    except WebhookTransportError:
        raise
    except Exception:
        raise WebhookTransportError("Webhook delivery failed.") from None
    finally:
        if tls_socket is not None:
            try:
                tls_socket.close()
            except OSError:
                pass
        if raw_socket is not None:
            try:
                raw_socket.close()
            except OSError:
                pass
