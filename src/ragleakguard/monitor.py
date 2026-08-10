"""Privacy-safe keyed monitoring state and the existing webhook transport.

Version-2 state contains only purpose-bound keyed tokens, finding counts,
validation totals, public construction/key identifiers, and an authenticator.
Raw store metadata and detector values stay process-local. Webhook minimisation,
signing, and delivery policy are separate work packages and are not changed here.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence


STATE_VERSION = 2
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

_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[0-9a-f]{32}$")
_ENTITY_TYPE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")

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
        fd = os.open(path, flags)
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("not a regular file")
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
    if not _is_exact_int(version) or version != STATE_VERSION:
        raise UnsupportedMonitorStateError("Monitor state version is unsupported.")
    if set(document) != {
        "authentication",
        "construction",
        "key_id",
        "records",
        "scope_token",
        "totals",
        "version",
    }:
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
) -> bytes:
    """Return the strict authenticated v2 state serialization."""
    document = _build_state_document(records, crypto, scope_token)
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
    initialize: bool = False,
) -> None:
    """Same-directory atomic checkpoint update or explicit no-overwrite init."""
    if not isinstance(path, str) or not path:
        raise MonitorWriteError("Monitor state path is invalid.")
    if initialize and os.path.lexists(path):
        raise MonitorInitializationError("Monitor state already exists.")
    encoded = serialize_state(records, crypto, scope_token)
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


def build_webhook_payload(
    delta: Dict[str, List[str]],
    current: Dict[str, Dict[str, Any]],
    source: str,
    store_path: str,
) -> Dict[str, Any]:
    """Existing alert contract, now keyed by non-reversible record tokens.

    Source/path minimisation and payload signing remain explicitly out of scope.
    """

    def _summarize(tokens: List[str]) -> List[Dict[str, Any]]:
        return [
            {
                "record": token,
                "findings": current.get(token, {}).get("finding_count", 0),
                "types": current.get(token, {}).get("type_counts", {}),
            }
            for token in tokens
        ]

    totals = {
        "records": len(current),
        "records_with_findings": sum(
            1 for record in current.values() if record["finding_count"] > 0
        ),
        "findings": sum(record["finding_count"] for record in current.values()),
    }
    return {
        "event": "ragleakguard.monitor",
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "store": {"source": source, "path": store_path},
        "totals": totals,
        "new": _summarize(delta["new"]),
        "changed": _summarize(delta["changed"]),
        "resolved": [{"record": token} for token in delta["resolved"]],
    }


def post_webhook(url: str, payload: Dict[str, Any], timeout: int = 10) -> int:
    """POST the existing alert JSON and return its HTTP status."""
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        return response.status
