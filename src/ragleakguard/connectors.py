"""Public connector boundaries.

Direct/live Chroma access remains disabled.  WP7D exposes only one aggregate result
after a separately created operator snapshot has been copied, scanned, and cleaned.
"""
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterator, Mapping, Optional

from ragleakguard import _chroma_snapshot, _snapshot
from ragleakguard.detect import (
    MissingDetectionModelError,
    UnsupportedLocaleError,
    normalize_locale,
    validate_detection_runtime,
)


CHROMA_DISABLED_MESSAGE = (
    "Local Chroma scanning is disabled because executable endpoint evidence proved "
    "that ChromaDB 1.5.0 and 1.5.9 may modify durable store files during client "
    "construction or reads, while other versions have not established an acceptable "
    "read-only boundary. No report, monitor state, or webhook was created or replaced."
)
CHROMA_SNAPSHOT_INVALID_MESSAGE = "Snapshot-backed Chroma scan request is invalid."
CHROMA_SNAPSHOT_UNAVAILABLE_MESSAGE = (
    "Snapshot-backed Chroma scanning is unavailable for this dependency or runtime."
)
CHROMA_SNAPSHOT_FAILURE_MESSAGE = (
    "Snapshot-backed Chroma scanning failed closed; no completion result was produced."
)
_SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ENTITY_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class ChromaConnectorUnavailableError(RuntimeError):
    """Static public failure for the unavailable direct local Chroma connector."""

    def __init__(self) -> None:
        super().__init__(CHROMA_DISABLED_MESSAGE)


class InvalidChromaSnapshotRequest(ValueError):
    """Static failure for acknowledgement or pseudonymous-ID validation."""

    def __init__(self) -> None:
        super().__init__(CHROMA_SNAPSHOT_INVALID_MESSAGE)


class ChromaSnapshotUnavailableError(RuntimeError):
    """Static failure for an unlisted dependency or activation environment."""

    def __init__(self) -> None:
        super().__init__(CHROMA_SNAPSHOT_UNAVAILABLE_MESSAGE)


class ChromaSnapshotScanError(RuntimeError):
    """Static aggregate-only failure with no dependency or path details."""

    def __init__(self) -> None:
        super().__init__(CHROMA_SNAPSHOT_FAILURE_MESSAGE)


def _scrub_public_error(error: BaseException) -> BaseException:
    """Detach every retained exception before a static failure crosses the boundary."""
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        nested = getattr(current, "exceptions", ())
        if type(nested) is tuple:
            pending.extend(nested)
        current.__cause__ = None
        current.__context__ = None
        current.__suppress_context__ = True
    return error


def _bounded_integer(value: object, maximum: int) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ValueError("Aggregate counter is outside the WP7D contract.")
    return value


@dataclass(frozen=True)
class DetectorAggregate:
    """The complete privacy-minimal detector aggregate returned by WP7D."""

    records_completed: int
    source_segments_completed: int
    source_utf8_bytes_completed: int
    records_with_findings: int
    total_findings: int
    finding_counts_by_type: Mapping[str, int]

    def __post_init__(self) -> None:
        records = _bounded_integer(self.records_completed, 10_000)
        segments = _bounded_integer(self.source_segments_completed, 100_000)
        source_bytes = _bounded_integer(
            self.source_utf8_bytes_completed, 268_435_456
        )
        flagged = _bounded_integer(self.records_with_findings, 10_000)
        total = _bounded_integer(self.total_findings, 1_000_000)
        if not isinstance(self.finding_counts_by_type, Mapping):
            raise ValueError("Finding counts must be a mapping.")
        counts = {}
        for entity_type, count in self.finding_counts_by_type.items():
            if (
                type(entity_type) is not str
                or _ENTITY_TYPE_RE.fullmatch(entity_type) is None
                or type(count) is not int
                or count <= 0
                or count > 1_000_000
            ):
                raise ValueError("Finding aggregate is invalid.")
            counts[entity_type] = count
        if (
            len(counts) > 64
            or sum(counts.values()) != total
            or flagged > records
            or flagged > total
            or (total == 0) != (not counts)
            or (total == 0 and flagged != 0)
            or (total > 0 and flagged == 0)
            or (records == 0 and (segments != 0 or source_bytes != 0))
            or source_bytes > segments * 65_536
            or total > segments * 4_096
        ):
            raise ValueError("Detector aggregate arithmetic is inconsistent.")
        object.__setattr__(
            self, "finding_counts_by_type", MappingProxyType(dict(sorted(counts.items())))
        )


@dataclass(frozen=True)
class ChromaSnapshotScanResult:
    """Aggregate-only connector counters plus an equal detector aggregate."""

    collections_completed: int
    records_completed: int
    source_segments_completed: int
    source_utf8_bytes_completed: int
    detector: DetectorAggregate

    def __post_init__(self) -> None:
        collections = _bounded_integer(self.collections_completed, 1_000)
        records = _bounded_integer(self.records_completed, 10_000)
        segments = _bounded_integer(self.source_segments_completed, 100_000)
        source_bytes = _bounded_integer(
            self.source_utf8_bytes_completed, 268_435_456
        )
        if type(self.detector) is not DetectorAggregate:
            raise ValueError("Detector aggregate type is invalid.")
        if (
            (collections == 0 and records != 0)
            or (records == 0 and (segments != 0 or source_bytes != 0))
            or source_bytes > segments * 65_536
            or records != self.detector.records_completed
            or segments != self.detector.source_segments_completed
            or source_bytes != self.detector.source_utf8_bytes_completed
        ):
            raise ValueError("Connector and detector aggregates do not agree.")


def validate_chroma_source_id(value: object) -> str:
    """Validate a pseudonymous stable identifier without coercing hostile input."""
    if type(value) is not str or _SOURCE_ID_RE.fullmatch(value) is None:
        raise InvalidChromaSnapshotRequest() from None
    return value


def read_chroma(path: object, collection: object = None) -> None:
    """Fail synchronously without evaluating either supplied object."""
    raise ChromaConnectorUnavailableError() from None


def scan_chroma_snapshot(
    snapshot: object,
    work_parent: object,
    *,
    source_id: object,
    acknowledge_offline_complete_snapshot: object,
    locale: Optional[str] = None,
    cancelled: Optional[Callable[[], bool]] = None,
) -> ChromaSnapshotScanResult:
    """Scan one operator-created snapshot and return aggregates after cleanup.

    The acknowledgement records operator intent only.  It does not prove snapshot
    provenance, quiescence, completeness, or atomic multi-file consistency.
    """
    if acknowledge_offline_complete_snapshot is not True:
        raise InvalidChromaSnapshotRequest() from None
    validate_chroma_source_id(source_id)
    normalized_locale = normalize_locale(locale)
    normalized_locale = validate_detection_runtime(normalized_locale)
    activation_failure = None
    try:
        _chroma_snapshot._public_activation_gate(work_parent)
    except BaseException:
        activation_failure = ChromaSnapshotUnavailableError()
    if activation_failure is not None:
        raise _scrub_public_error(activation_failure)

    preparation_failure = None
    try:
        prepared = _snapshot._prepare_snapshot(
            snapshot,
            work_parent,
            cancelled=cancelled,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        preparation_failure = ChromaSnapshotScanError()
    if preparation_failure is not None:
        raise _scrub_public_error(preparation_failure)

    receipt = None
    detector_document = None
    failed = False
    try:
        receipt, detector_document = (
            _chroma_snapshot._scan_prepared_chroma_with_detection(
                prepared,
                locale=normalized_locale,
                cancelled=cancelled,
            )
        )
    except BaseException:
        failed = True
    cleanup_failure = None
    try:
        prepared.cleanup()
    except BaseException:
        cleanup_failure = ChromaSnapshotScanError()
    if cleanup_failure is not None:
        raise _scrub_public_error(cleanup_failure)
    if failed or receipt is None or type(detector_document) is not dict:
        raise ChromaSnapshotScanError() from None
    result_failure = None
    try:
        detector = DetectorAggregate(**detector_document)
        return ChromaSnapshotScanResult(
            collections_completed=receipt.collections_enumerated,
            records_completed=receipt.records_enumerated,
            source_segments_completed=receipt.source_segments_enumerated,
            source_utf8_bytes_completed=receipt.source_utf8_bytes_enumerated,
            detector=detector,
        )
    except BaseException:
        result_failure = ChromaSnapshotScanError()
    raise _scrub_public_error(result_failure)


def read_pinecone(index: str) -> Iterator[Dict[str, Any]]:
    """Read items from a Pinecone index. TODO (Week 2)."""
    raise NotImplementedError("Pinecone connector — Week 2")
