"""Private WP7C Chroma enumeration inside a held WP7B work copy.

This module deliberately exposes no public surface and imports Chroma only inside
the bounded worker after all parent and worker preflight gates have succeeded.
It returns counters, never source records or detector inputs.
"""
from __future__ import annotations

import errno
import hashlib
import hmac
import importlib.metadata
import json
import logging
import math
import os
import platform
import re
import secrets
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote

from . import _snapshot


__all__ = ()

_CANDIDATES = frozenset({"1.5.0", "1.5.9"})
_PUBLIC_ACTIVATION_VERSION = "1.5.9"
_PUBLIC_ACTIVATION_ENVIRONMENTS = {
    ("Linux", (3, 10)),
    ("Linux", (3, 11)),
    ("Linux", (3, 12)),
    ("Darwin", (3, 12)),
    ("Windows", (3, 12)),
}
_GLOBAL_SECONDS = 1_200.0
_USEFUL_SECONDS = 1_170.0
_GRACEFUL_SECONDS = 10.0
_TERMINATE_SECONDS = 5.0
_KILL_SECONDS = 5.0
_SETTLE_SECONDS = 0.1
_WAIT_QUANTUM_SECONDS = 0.1
_MAX_WAIT_POLLS = 12_000
_MAX_IPC_PAYLOAD = 262_144
_MAX_RECEIPT_PAYLOAD = 512
_MAX_DETECTOR_RESPONSE_PAYLOAD = 16_384
_MAX_ERROR_PAYLOAD = 256
_MAX_EFFECT_PATHS = 4_096
_AUTOMATIC_RETRIES = 0
_MAX_CHILD_STDERR = 0
_FRAME_PREFIX_BYTES = 4
_SQLITE_HEADER = b"SQLite format 3\x00"
_FILE_CHUNK = 1024**2
_STATIC_FAILURE = "Private Chroma enumeration failed closed."
_ERROR_CODE = "RLG_WP7C_PRIVATE_FAILURE"
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ENTITY_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_MIGRATION_DIRS = ("embeddings_queue", "metadb", "sysdb")
_TELEMETRY_CLASS = "ragleakguard._chroma_snapshot._LocalTelemetry"
_COLLECTION_DOMAIN = b"RLG/WP7C/chroma/collection/v1"
_RECORD_DOMAIN = b"RLG/WP7C/chroma/record-id/v1"
_CONTENT_DOMAIN = b"RLG/WP7C/chroma/content/v1"
_WITNESS_SUFFIX = b"/collision-witness"
_PATH_TYPE = type(Path())

# Audited against the Rust-embedded migration SQL in the exact 1.5.0 and 1.5.9
# tags and reproduced by same-version MD5 and SHA-256 fixture creation.
_MIGRATIONS = (
    ("embeddings_queue", 1, "00001-embeddings.sqlite.sql", "d3755dfd232be8e8301f4d7fcfb3a486", "fbcbdac621c6bdebe561ae0bd3eac840737af822f4edc0d567b94e2066eecf28"),
    ("embeddings_queue", 2, "00002-embeddings-queue-config.sqlite.sql", "8fbfe4ffb3e57f1d8bfdc58510a82e85", "788fe9b405526821be2f4e305da3891724871859a2ea8f48c1f8182745658fd9"),
    ("metadb", 1, "00001-embedding-metadata.sqlite.sql", "2b4cf52c4bb2676e21d6860a4409f856", "0e7477e62bd40830f28f9986f0703597817877503044324efe8c9ecc85392845"),
    ("metadb", 2, "00002-embedding-metadata.sqlite.sql", "12a570f7121b3a8ce750a2a7c36da20f", "337de70bb89c42bf01747642fbe9310f8ce38635ab50f2ce82ee98ac664e759b"),
    ("metadb", 3, "00003-full-text-tokenize.sqlite.sql", "f97ad6334aeaa8f419f01110b648b97a", "13fd5839823c8f1e236431c2f716a0aef02c5bfd80c35c15963496924ea8dda4"),
    ("metadb", 4, "00004-metadata-indices.sqlite.sql", "fb36603a45ee2cd0254cef3ef86585e8", "46e874a3bf99ae95611fd8f781b9aecccc8979dc4e06c91e86a6b56dac378443"),
    ("metadb", 5, "00005-max-seq-id-int.sqlite.sql", "0e9de46758761b373ce682925edcc326", "363f44b68fcda609e239e1e23263d655a0439a490394da3d690279939a716e45"),
    ("metadb", 6, "00006-metadata-array-support.sqlite.sql", "e026f01ea92c1baa1493f4ad5ca7cfe7", "352340cb5ffe1d2e2a44b3d6d2651128933f8f16479c7220692b52a19c9ad985"),
    ("sysdb", 1, "00001-collections.sqlite.sql", "38352d725ad1c16074fac420b22b4633", "dfa5720fb290880c9a7abac9262024cd32da703a312471b5d64eb29613a055bd"),
    ("sysdb", 2, "00002-segments.sqlite.sql", "2913cb6a503055a95f625448037e8912", "e459a7f668f9c9a38562e92211feeccc4549d5a04aca2972397291496d564a1c"),
    ("sysdb", 3, "00003-collection-dimension.sqlite.sql", "42d22d0574d31d419c2a0e7f625c93aa", "465c9dd473bf084e6acddcfd15c2587ecaf325b3043af49aaec87e4006bde8f3"),
    ("sysdb", 4, "00004-tenants-databases.sqlite.sql", "048867ce8fcdefe4023c7110e4433591", "0da5897ebd71a72ee540c1011265671f5ef6eb21da9eaaa1e58408d8a0480dc3"),
    ("sysdb", 5, "00005-remove-topic.sqlite.sql", "b1367c826b8fba5f96f27befdc1d42d2", "60a348031c4bcf98d611ca6362fa8b754cc854463ba65258aab366327a237343"),
    ("sysdb", 6, "00006-collection-segment-metadata.sqlite.sql", "4eea7468935bf25d4604a0fed2366116", "5768db7d49f555920dacc7012f173cfdd2eb4c3f71af910d3fd653661105a694"),
    ("sysdb", 7, "00007-collection-config.sqlite.sql", "1c7e63bba346a42a18b6ab7f1c989bed", "e787b736706f173e9b279505e0e7027f57a27031dfe7668a167677030715d5b9"),
    ("sysdb", 8, "00008-maintenance-log.sqlite.sql", "0a0e7e93111a01789addf64961c6127c", "66ad31eefddd3070be27963a053319f0fe9003e5dd1f38b50c42e2ed970812ad"),
    ("sysdb", 9, "00009-segment-collection-not-null.sqlite.sql", "054355aef9e63702bf54ea29e61563f1", "b5564781c2b24dfdc79024a2e8f17ad9830127cc9b43876d9428757c093bc99e"),
    ("sysdb", 10, "00010-collection-schema.sqlite.sql", "5c3a5ac4b79df76799b4721827ed5e1d", "38b8b08790d290caff0043129e71e983cb15c4cb0980773d8bb39d5855c1d5d6"),
)
_MIGRATION_MANIFESTS = {candidate: _MIGRATIONS for candidate in _CANDIDATES}

# Logical sqlite_master fingerprint reproduced from fresh, zero-collection stores
# created independently by both exact candidates. Physical root pages remain in
# the keyed before/after evidence but are deliberately excluded from this gate.
_SCHEMA_FINGERPRINTS = {
    "1.5.0": bytes.fromhex(
        "4bb4335170227c9b9d213878a01b47c64392b16e1948a00a7005a249d7e21241"
    ),
    "1.5.9": bytes.fromhex(
        "4bb4335170227c9b9d213878a01b47c64392b16e1948a00a7005a249d7e21241"
    ),
}

_HNSW_EFFECT_FILES = frozenset(
    {"data_level0.bin", "header.bin", "length.bin", "link_lists.bin", "index_metadata.pickle"}
)
_EFFECT_ALLOWLIST = {
    (candidate, system, python, filesystem): _HNSW_EFFECT_FILES
    for candidate in _CANDIDATES
    for system, python, filesystem in (
        ("Linux", (3, 10), "ext4"),
        ("Linux", (3, 11), "ext4"),
        ("Linux", (3, 12), "ext4"),
        ("Darwin", (3, 12), "apfs"),
        ("Windows", (3, 12), "ntfs"),
    )
}


class _ChromaScanError(RuntimeError):
    def __init__(self) -> None:
        super().__init__(_STATIC_FAILURE)


def _scrub(error: _ChromaScanError) -> _ChromaScanError:
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
        current.__cause__ = None
        current.__context__ = None
        current.__suppress_context__ = True
    return error


@dataclass(frozen=True)
class _ChromaScanLimits:
    collection_page: int = 100
    record_page: int = 16
    collections: int = 1_000
    records: int = 100_000
    source_segments: int = 1_000_000
    source_utf8_bytes: int = 1_073_741_824
    collection_name_bytes: int = 1_024
    record_id_bytes: int = 1_024
    metadata_key_bytes: int = 1_024
    document_bytes: int = 1_048_576
    scalar_bytes: int = 65_536
    array_elements: int = 1_024
    metadata_leaves: int = 4_096
    metadata_bytes: int = 1_048_576
    manifest_entries: int = 101_000
    manifest_memory: int = 33_554_432
    entry_accounting: int = 256
    token_bytes: int = 32

    def __post_init__(self) -> None:
        maxima = (
            (self.collection_page, 100),
            (self.record_page, 16),
            (self.collections, 1_000),
            (self.records, 100_000),
            (self.source_segments, 1_000_000),
            (self.source_utf8_bytes, 1_073_741_824),
            (self.collection_name_bytes, 1_024),
            (self.record_id_bytes, 1_024),
            (self.metadata_key_bytes, 1_024),
            (self.document_bytes, 1_048_576),
            (self.scalar_bytes, 65_536),
            (self.array_elements, 1_024),
            (self.metadata_leaves, 4_096),
            (self.metadata_bytes, 1_048_576),
            (self.manifest_entries, 101_000),
            (self.manifest_memory, 33_554_432),
            (self.entry_accounting, 256),
            (self.token_bytes, 32),
        )
        if any(type(value) is not int or value <= 0 or value > maximum for value, maximum in maxima):
            raise _ChromaScanError()
        if self.manifest_entries * self.entry_accounting > self.manifest_memory:
            raise _ChromaScanError()


_DEFAULT_CHROMA_SCAN_LIMITS = _ChromaScanLimits()

# WP7D narrows the reviewed WP7C ceilings.  It never widens the private
# candidate path, so the ten-cell WP7C evidence remains independently usable.
_PUBLIC_CHROMA_SCAN_LIMITS = _ChromaScanLimits(
    collections=1_000,
    records=10_000,
    source_segments=100_000,
    source_utf8_bytes=268_435_456,
    document_bytes=65_536,
    manifest_entries=11_000,
)


@dataclass(frozen=True)
class _DetectorLimits:
    records: int = 10_000
    source_segments: int = 100_000
    source_utf8_bytes: int = 268_435_456
    segment_bytes: int = 65_536
    findings_per_segment: int = 4_096
    total_findings: int = 1_000_000
    entity_types: int = 64

    def __post_init__(self) -> None:
        maxima = (
            (self.records, 10_000),
            (self.source_segments, 100_000),
            (self.source_utf8_bytes, 268_435_456),
            (self.segment_bytes, 65_536),
            (self.findings_per_segment, 4_096),
            (self.total_findings, 1_000_000),
            (self.entity_types, 64),
        )
        if any(
            type(value) is not int or value <= 0 or value > maximum
            for value, maximum in maxima
        ):
            raise _ChromaScanError()


_DEFAULT_DETECTOR_LIMITS = _DetectorLimits()


class _ChromaCompletionReceipt:
    __slots__ = (
        "_collections_enumerated",
        "_records_enumerated",
        "_source_segments_enumerated",
        "_source_utf8_bytes_enumerated",
        "_frozen",
    )

    def __init__(self, collections: int, records: int, segments: int, utf8_bytes: int) -> None:
        object.__setattr__(self, "_collections_enumerated", collections)
        object.__setattr__(self, "_records_enumerated", records)
        object.__setattr__(self, "_source_segments_enumerated", segments)
        object.__setattr__(self, "_source_utf8_bytes_enumerated", utf8_bytes)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name, value) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError("Private Chroma receipt is immutable.")
        object.__setattr__(self, name, value)

    @property
    def collections_enumerated(self) -> int:
        return self._collections_enumerated

    @property
    def records_enumerated(self) -> int:
        return self._records_enumerated

    @property
    def source_segments_enumerated(self) -> int:
        return self._source_segments_enumerated

    @property
    def source_utf8_bytes_enumerated(self) -> int:
        return self._source_utf8_bytes_enumerated

    def __repr__(self) -> str:
        return "<RAGLeakGuard private Chroma completion receipt: redacted>"

    def __reduce_ex__(self, protocol):
        raise TypeError("Private Chroma receipt serialization is disabled.")

    def __getstate__(self):
        raise TypeError("Private Chroma receipt serialization is disabled.")


class _StoreEvidence:
    __slots__ = (
        "algorithm",
        "schema",
        "catalog",
        "migration",
        "records",
        "vector_ids",
    )

    def __init__(self, algorithm, schema, catalog, migration, records, vector_ids) -> None:
        self.algorithm = algorithm
        self.schema = schema
        self.catalog = catalog
        self.migration = migration
        self.records = records
        self.vector_ids = vector_ids

    def __repr__(self) -> str:
        return "<RAGLeakGuard private Chroma store evidence: redacted>"

    def same_as(self, other: object) -> bool:
        return type(other) is _StoreEvidence and (
            self.algorithm,
            self.schema,
            self.catalog,
            self.migration,
            self.records,
            self.vector_ids,
        ) == (
            other.algorithm,
            other.schema,
            other.catalog,
            other.migration,
            other.records,
            other.vector_ids,
        )


def _safe_clock(clock: Callable[[], float]) -> float:
    try:
        value = clock()
    except BaseException:
        raise _ChromaScanError() from None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise _ChromaScanError()
    return float(value)


def _check_control(
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
) -> float:
    now = _safe_clock(clock)
    try:
        stopped = bool(cancelled()) if cancelled is not None else False
    except BaseException:
        raise _ChromaScanError() from None
    if stopped or now > deadline:
        raise _ChromaScanError()
    return now


def _exact_int(value: object, maximum: int) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise _ChromaScanError()
    return value


def _utf8_length(value: object, maximum: int) -> int:
    if type(value) is not str:
        raise _ChromaScanError()
    total = 0
    for character in value:
        point = ord(character)
        if 0xD800 <= point <= 0xDFFF:
            raise _ChromaScanError()
        total += 1 if point < 0x80 else 2 if point < 0x800 else 3 if point < 0x10000 else 4
        if total > maximum:
            raise _ChromaScanError()
    return total


def _encoded(value: object, maximum: int) -> bytes:
    _utf8_length(value, maximum)
    try:
        encoded = value.encode("utf-8")
    except (UnicodeError, AttributeError):
        raise _ChromaScanError() from None
    if len(encoded) > maximum:
        raise _ChromaScanError()
    return encoded


def _update_frame(digest, tag: bytes, encoded: bytes) -> None:
    if type(tag) is not bytes or type(encoded) is not bytes or len(tag) > 255:
        raise _ChromaScanError()
    digest.update(bytes((len(tag),)))
    digest.update(tag)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)


def _token(key: bytes, domain: bytes, frames: Iterable[Tuple[bytes, bytes]]) -> bytes:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    _update_frame(digest, b"domain", domain)
    for tag, encoded in frames:
        _update_frame(digest, tag, encoded)
    return digest.digest()


def _witness(key: bytes, domain: bytes, frames: Iterable[Tuple[bytes, bytes]]) -> bytes:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    _update_frame(digest, b"domain", domain + _WITNESS_SUFFIX)
    for tag, encoded in frames:
        _update_frame(digest, tag, encoded)
    return digest.digest()


def _candidate_version() -> str:
    try:
        raw = importlib.metadata.version("chromadb")
    except BaseException:
        raise _ChromaScanError() from None
    if type(raw) is not str or raw not in _CANDIDATES:
        raise _ChromaScanError()
    try:
        from packaging.version import InvalidVersion, Version

        parsed = Version(raw)
    except (ImportError, InvalidVersion, TypeError, ValueError):
        raise _ChromaScanError() from None
    if (
        str(parsed) != raw
        or parsed.is_prerelease
        or parsed.is_devrelease
        or parsed.local is not None
    ):
        raise _ChromaScanError()
    return raw


def _public_activation_gate() -> str:
    """Reject every non-WP7D dependency or host tuple before source access."""
    version = _candidate_version()
    system = platform.system()
    python = (sys.version_info.major, sys.version_info.minor)
    machine = platform.machine().lower()
    if version != _PUBLIC_ACTIVATION_VERSION:
        raise _ChromaScanError()
    if (system, python) not in _PUBLIC_ACTIVATION_ENVIRONMENTS:
        raise _ChromaScanError()
    if system in {"Linux", "Windows"} and machine not in {"x86_64", "amd64"}:
        raise _ChromaScanError()
    if system == "Darwin":
        if machine not in {"arm64", "aarch64", "x86_64"}:
            raise _ChromaScanError()
        try:
            if int(platform.mac_ver()[0].split(".", 1)[0]) != 15:
                raise _ChromaScanError()
        except (ValueError, IndexError):
            raise _ChromaScanError() from None
    return version


def _filesystem_type(path: Path) -> str:
    if type(path) is not _PATH_TYPE:
        raise _ChromaScanError()
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes
            from ctypes import wintypes

            volume = ctypes.create_unicode_buffer(261)
            if not ctypes.windll.kernel32.GetVolumePathNameW(str(path), volume, len(volume)):
                raise OSError
            filesystem = ctypes.create_unicode_buffer(261)
            if not ctypes.windll.kernel32.GetVolumeInformationW(
                volume.value, None, 0, None, None, None, filesystem, len(filesystem)
            ):
                raise OSError
            return filesystem.value.lower()
        except (OSError, ValueError, TypeError, AttributeError):
            raise _ChromaScanError() from None
    if system == "Linux":
        try:
            target = os.fsencode(os.path.realpath(path))
            best = None
            with open("/proc/self/mountinfo", "rb") as handle:
                for number, line in enumerate(handle):
                    if number >= 16_384 or len(line) > 65_536:
                        raise _ChromaScanError()
                    fields = line.rstrip(b"\n").split(b" ")
                    separator = fields.index(b"-")
                    mount = fields[4].replace(b"\\040", b" ").replace(b"\\134", b"\\")
                    if target == mount or target.startswith(mount.rstrip(b"/") + b"/"):
                        if best is None or len(mount) > len(best[0]):
                            best = (mount, fields[separator + 1])
            if best is None:
                raise _ChromaScanError()
            return best[1].decode("ascii").lower()
        except _ChromaScanError:
            raise
        except (OSError, ValueError, UnicodeError):
            raise _ChromaScanError() from None
    if system == "Darwin":
        try:
            import ctypes

            class _StatFs(ctypes.Structure):
                _fields_ = [
                    ("f_bsize", ctypes.c_uint32),
                    ("f_iosize", ctypes.c_int32),
                    ("f_blocks", ctypes.c_uint64),
                    ("f_bfree", ctypes.c_uint64),
                    ("f_bavail", ctypes.c_uint64),
                    ("f_files", ctypes.c_uint64),
                    ("f_ffree", ctypes.c_uint64),
                    ("f_fsid", ctypes.c_int32 * 2),
                    ("f_owner", ctypes.c_uint32),
                    ("f_type", ctypes.c_uint32),
                    ("f_flags", ctypes.c_uint32),
                    ("f_fssubtype", ctypes.c_uint32),
                    ("f_fstypename", ctypes.c_char * 16),
                    ("f_mntonname", ctypes.c_char * 1024),
                    ("f_mntfromname", ctypes.c_char * 1024),
                    ("f_reserved", ctypes.c_uint32 * 8),
                ]

            observed = _StatFs()
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            if libc.statfs(os.fsencode(path), ctypes.byref(observed)) != 0:
                raise OSError
            return bytes(observed.f_fstypename).split(b"\0", 1)[0].decode("ascii").lower()
        except (OSError, ValueError, TypeError, UnicodeError, AttributeError):
            raise _ChromaScanError() from None
    raise _ChromaScanError()


def _environment_gate(version: str, path: Path) -> Tuple[str, Tuple[int, int], str]:
    system = platform.system()
    python = (sys.version_info.major, sys.version_info.minor)
    filesystem = _filesystem_type(path)
    machine = platform.machine().lower()
    if (version, system, python, filesystem) not in _EFFECT_ALLOWLIST:
        raise _ChromaScanError()
    if system == "Windows" and machine not in {"amd64", "x86_64"}:
        raise _ChromaScanError()
    if system == "Linux" and machine not in {"x86_64", "amd64"}:
        raise _ChromaScanError()
    if system == "Darwin":
        if machine not in {"arm64", "aarch64", "x86_64"}:
            raise _ChromaScanError()
        try:
            if int(platform.mac_ver()[0].split(".", 1)[0]) != 15:
                raise _ChromaScanError()
        except (ValueError, IndexError):
            raise _ChromaScanError() from None
    return system, python, filesystem


def _regular_file(path: Path, root_device: int) -> _snapshot._Identity:
    try:
        raw = os.lstat(path)
        identity = _snapshot._identity(raw)
        if (
            identity.device != root_device
            or not stat.S_ISREG(identity.mode)
            or stat.S_ISLNK(identity.mode)
            or _snapshot._is_reparse(identity)
            or identity.links != 1
            or _snapshot._windows_has_named_streams(path)
        ):
            raise _ChromaScanError()
        _snapshot._assert_restrictive(path, False)
        return identity
    except _ChromaScanError:
        raise
    except BaseException:
        raise _ChromaScanError() from None


def _open_sqlite_readonly(data: Path):
    database = data / "chroma.sqlite3"
    root_identity = _snapshot._validate_directory(data, error_type=_ChromaScanError)
    expected = _regular_file(database, root_identity.device)
    descriptor = None
    try:
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOINHERIT", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(database, flags)
        opened = _snapshot._identity(os.fstat(descriptor))
        header = os.read(descriptor, len(_SQLITE_HEADER))
        if (
            not _snapshot._same_path_handle_identity(expected, opened)
            or header != _SQLITE_HEADER
            or not _snapshot._same_identity(expected, _snapshot._identity(os.lstat(database)))
        ):
            raise _ChromaScanError()
    except _ChromaScanError:
        raise
    except (OSError, ValueError, TypeError):
        raise _ChromaScanError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        absolute = os.path.abspath(database)
        uri = "file:" + quote(absolute.replace(os.sep, "/"), safe="/:\\") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=0.0)
        connection.execute("PRAGMA query_only=ON")
        if connection.execute("PRAGMA query_only").fetchone() != (1,):
            connection.close()
            raise _ChromaScanError()
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN")
        return connection
    except _ChromaScanError:
        raise
    except (sqlite3.Error, OSError, ValueError, TypeError):
        raise _ChromaScanError() from None


def _schema_evidence(connection: sqlite3.Connection, version: str, key: bytes) -> bytes:
    summary = connection.execute(
        "SELECT COUNT(*),MAX(length(CAST(type AS BLOB))),"
        "MAX(length(CAST(name AS BLOB))),MAX(length(CAST(tbl_name AS BLOB))),"
        "MAX(CASE WHEN sql IS NULL THEN 0 ELSE length(CAST(sql AS BLOB)) END),"
        "SUM(CASE WHEN typeof(type)!='text' OR typeof(name)!='text' "
        "OR typeof(tbl_name)!='text' OR typeof(rootpage)!='integer' "
        "OR (sql IS NOT NULL AND typeof(sql)!='text') THEN 1 ELSE 0 END) "
        "FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
    ).fetchone()
    if (
        type(summary) is not tuple
        or len(summary) != 6
        or type(summary[0]) is not int
        or summary[0] <= 0
        or summary[0] > 256
        or any(type(value) is not int or value < 0 for value in summary[1:])
        or any(value > 1_024 for value in summary[1:4])
        or summary[4] > 1_048_576
        or summary[5] != 0
    ):
        raise _ChromaScanError()

    evidence = hmac.new(key, digestmod=hashlib.sha256)
    logical = hashlib.sha256()
    _update_frame(evidence, b"domain", b"RLG/WP7C/sqlite/schema/v1")
    _update_frame(logical, b"domain", b"RLG/WP7C/sqlite/schema-allowlist/v1")
    count = 0
    cursor = connection.execute(
        "SELECT type,name,tbl_name,rootpage,sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    )
    for row in cursor:
        count += 1
        if count > summary[0] or type(row) is not tuple or len(row) != 5:
            raise _ChromaScanError()
        for value in row[:3]:
            _utf8_length(value, 1_024)
        _exact_int(row[3], 2**63 - 1)
        if row[4] is not None:
            _utf8_length(row[4], 1_048_576)
        row_frame = count.to_bytes(8, "big")
        _update_frame(evidence, b"row", row_frame)
        _update_frame(logical, b"row", row_frame)
        for value in row:
            _update_sql_value(evidence, value)
        for value in (row[0], row[1], row[2], row[4]):
            _update_sql_value(logical, value)
    if count != summary[0]:
        raise _ChromaScanError()
    rows_frame = count.to_bytes(8, "big")
    _update_frame(evidence, b"rows", rows_frame)
    _update_frame(logical, b"rows", rows_frame)
    expected = _SCHEMA_FINGERPRINTS.get(version)
    if type(expected) is not bytes or not hmac.compare_digest(logical.digest(), expected):
        raise _ChromaScanError()
    return evidence.digest()


def _update_sql_value(digest, value: object) -> None:
    if value is None:
        _update_frame(digest, b"none", b"")
    elif type(value) is str:
        _update_frame(digest, b"str", _encoded(value, 1_048_576))
    elif type(value) is int:
        _update_frame(digest, b"int", str(value).encode("ascii"))
    elif type(value) is float and math.isfinite(value):
        _update_frame(digest, b"float", _canonical_float(value).encode("ascii"))
    elif type(value) is bytes and len(value) <= 1_048_576:
        _update_frame(digest, b"bytes", value)
    else:
        raise _ChromaScanError()


def _digest_sql_rows(
    key: bytes,
    domain: bytes,
    rows: Iterable[Sequence[object]],
    check_control: Optional[Callable[[], None]] = None,
) -> bytes:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    _update_frame(digest, b"domain", domain)
    count = 0
    for row in rows:
        if check_control is not None:
            check_control()
        count += 1
        if count > 1_000_000:
            raise _ChromaScanError()
        _update_frame(digest, b"row", count.to_bytes(8, "big"))
        for value in row:
            _update_sql_value(digest, value)
    _update_frame(digest, b"rows", count.to_bytes(8, "big"))
    return digest.digest()


def _migration_evidence(
    connection: sqlite3.Connection, version: str, key: bytes
) -> Tuple[str, bytes]:
    schema = connection.execute("PRAGMA table_info(migrations)").fetchall()
    if schema != [
        (0, "dir", "TEXT", 1, None, 1),
        (1, "version", "INTEGER", 1, None, 2),
        (2, "filename", "TEXT", 1, None, 0),
        (3, "sql", "TEXT", 1, None, 0),
        (4, "hash", "TEXT", 1, None, 0),
    ]:
        raise _ChromaScanError()
    summary = connection.execute(
        "SELECT COUNT(*),MAX(length(CAST(dir AS BLOB))),"
        "MAX(length(CAST(filename AS BLOB))),MAX(length(CAST(sql AS BLOB))),"
        "MAX(length(CAST(hash AS BLOB))),"
        "SUM(CASE WHEN typeof(dir)!='text' OR typeof(version)!='integer' "
        "OR typeof(filename)!='text' OR typeof(sql)!='text' OR typeof(hash)!='text' "
        "THEN 1 ELSE 0 END) FROM migrations"
    ).fetchone()
    if (
        type(summary) is not tuple
        or len(summary) != 6
        or any(type(value) is not int or value < 0 for value in summary)
        or summary[0] != len(_MIGRATION_MANIFESTS[version])
        or summary[1]
        != max(len(row[0].encode("utf-8")) for row in _MIGRATION_MANIFESTS[version])
        or summary[2]
        != max(len(row[2].encode("utf-8")) for row in _MIGRATION_MANIFESTS[version])
        or summary[3] > 1_048_576
        or summary[4] not in {32, 64}
        or summary[5] != 0
    ):
        raise _ChromaScanError()
    rows = connection.execute(
        "SELECT dir,version,filename,sql,hash FROM migrations ORDER BY dir,version"
    ).fetchall()
    if len(rows) != len(set((row[0], row[1]) for row in rows)):
        raise _ChromaScanError()
    lengths = {len(row[4]) for row in rows if type(row) is tuple and len(row) == 5 and type(row[4]) is str}
    if lengths == {32}:
        algorithm, pattern, position = "md5", _MD5_RE, 3
    elif lengths == {64}:
        algorithm, pattern, position = "sha256", _SHA256_RE, 4
    else:
        raise _ChromaScanError()
    expected = _MIGRATION_MANIFESTS[version]
    for observed, wanted in zip(rows, expected):
        if type(observed) is not tuple or len(observed) != 5:
            raise _ChromaScanError()
        directory, number, filename, sql, stored_hash = observed
        if (
            type(directory) is not str
            or directory not in _MIGRATION_DIRS
            or type(number) is not int
            or type(filename) is not str
            or type(sql) is not str
            or type(stored_hash) is not str
            or pattern.fullmatch(stored_hash) is None
            or (directory, number, filename) != wanted[:3]
            or stored_hash != wanted[position]
        ):
            raise _ChromaScanError()
        try:
            recomputed = getattr(hashlib, algorithm)(sql.encode("utf-8")).hexdigest()
        except (UnicodeError, AttributeError):
            raise _ChromaScanError() from None
        if not hmac.compare_digest(recomputed, stored_hash):
            raise _ChromaScanError()
    return algorithm, _digest_sql_rows(key, b"RLG/WP7C/sqlite/migrations/v1", rows)


def _require_table_schema(connection: sqlite3.Connection, table: str, columns: Sequence[str]) -> None:
    if not re.fullmatch(r"[a-z_]+", table):
        raise _ChromaScanError()
    rows = connection.execute("PRAGMA table_info(" + table + ")").fetchall()
    if [row[1] for row in rows] != list(columns) or any(type(row[1]) is not str for row in rows):
        raise _ChromaScanError()


def _bounded_table_summary(
    connection: sqlite3.Connection,
    query: str,
    maximum_rows: int,
    maximum_lengths: Sequence[int],
) -> int:
    row = connection.execute(query).fetchone()
    if type(row) is not tuple or len(row) != len(maximum_lengths) + 2:
        raise _ChromaScanError()
    row = tuple(0 if value is None else value for value in row)
    if (
        any(type(value) is not int or value < 0 for value in row)
        or row[0] > maximum_rows
        or any(value > maximum for value, maximum in zip(row[1:-1], maximum_lengths))
        or row[-1] != 0
    ):
        raise _ChromaScanError()
    return row[0]


def _catalog_evidence(
    connection: sqlite3.Connection, key: bytes, limits: _ChromaScanLimits
) -> Tuple[bytes, frozenset]:
    _require_table_schema(connection, "tenants", ("id",))
    _require_table_schema(connection, "databases", ("id", "name", "tenant_id"))
    _require_table_schema(connection, "collections", ("id", "name", "dimension", "database_id", "config_json_str", "schema_str"))
    _require_table_schema(connection, "segments", ("id", "type", "scope", "collection"))
    _require_table_schema(connection, "collection_metadata", ("collection_id", "key", "str_value", "int_value", "float_value", "bool_value"))
    _require_table_schema(connection, "segment_metadata", ("segment_id", "key", "str_value", "int_value", "float_value", "bool_value"))
    _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(length(CAST(id AS BLOB))),"
        "SUM(CASE WHEN typeof(id)!='text' THEN 1 ELSE 0 END) FROM tenants",
        1,
        (1_024,),
    )
    _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(length(CAST(id AS BLOB))),MAX(length(CAST(name AS BLOB))),"
        "MAX(length(CAST(tenant_id AS BLOB))),"
        "SUM(CASE WHEN typeof(id)!='text' OR typeof(name)!='text' "
        "OR typeof(tenant_id)!='text' THEN 1 ELSE 0 END) FROM databases",
        1,
        (36, 1_024, 1_024),
    )
    tenants = connection.execute("SELECT id FROM tenants ORDER BY id").fetchall()
    databases = connection.execute("SELECT id,name,tenant_id FROM databases ORDER BY id").fetchall()
    if tenants != [("default_tenant",)] or databases != [
        ("00000000-0000-0000-0000-000000000000", "default_database", "default_tenant")
    ]:
        raise _ChromaScanError()
    collection_count = _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(length(CAST(id AS BLOB))),MAX(length(CAST(name AS BLOB))),"
        "MAX(length(CAST(database_id AS BLOB))),"
        "MAX(CASE WHEN config_json_str IS NULL THEN 0 ELSE length(CAST(config_json_str AS BLOB)) END),"
        "MAX(CASE WHEN schema_str IS NULL THEN 0 ELSE length(CAST(schema_str AS BLOB)) END),"
        "SUM(CASE WHEN typeof(id)!='text' OR typeof(name)!='text' "
        "OR (dimension IS NOT NULL AND typeof(dimension)!='integer') "
        "OR typeof(database_id)!='text' "
        "OR (config_json_str IS NOT NULL AND typeof(config_json_str)!='text') "
        "OR (schema_str IS NOT NULL AND typeof(schema_str)!='text') THEN 1 ELSE 0 END) "
        "FROM collections",
        limits.collections,
        (36, limits.collection_name_bytes, 36, 1_048_576, 1_048_576),
    )
    collection_ids = set()
    segment_count = _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(length(CAST(id AS BLOB))),MAX(length(CAST(type AS BLOB))),"
        "MAX(length(CAST(scope AS BLOB))),MAX(length(CAST(collection AS BLOB))),"
        "SUM(CASE WHEN typeof(id)!='text' OR typeof(type)!='text' "
        "OR typeof(scope)!='text' OR typeof(collection)!='text' THEN 1 ELSE 0 END) "
        "FROM segments",
        limits.source_segments,
        (36, 1_024, 1_024, 36),
    )
    collection_metadata_count = _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(length(CAST(collection_id AS BLOB))),"
        "MAX(length(CAST(key AS BLOB))),"
        "MAX(CASE WHEN str_value IS NULL THEN 0 ELSE length(CAST(str_value AS BLOB)) END),"
        "SUM(CASE WHEN typeof(collection_id)!='text' OR typeof(key)!='text' "
        "OR (str_value IS NOT NULL AND typeof(str_value)!='text') "
        "OR (int_value IS NOT NULL AND typeof(int_value)!='integer') "
        "OR (float_value IS NOT NULL AND typeof(float_value) NOT IN ('real','integer')) "
        "OR (bool_value IS NOT NULL AND typeof(bool_value)!='integer') "
        "OR ((str_value IS NOT NULL)+(int_value IS NOT NULL)+(float_value IS NOT NULL)+"
        "(bool_value IS NOT NULL))!=1 THEN 1 ELSE 0 END) FROM collection_metadata",
        limits.source_segments,
        (36, limits.metadata_key_bytes, limits.scalar_bytes),
    )
    segment_metadata_count = _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(length(CAST(segment_id AS BLOB))),"
        "MAX(length(CAST(key AS BLOB))),"
        "MAX(CASE WHEN str_value IS NULL THEN 0 ELSE length(CAST(str_value AS BLOB)) END),"
        "SUM(CASE WHEN typeof(segment_id)!='text' OR typeof(key)!='text' "
        "OR (str_value IS NOT NULL AND typeof(str_value)!='text') "
        "OR (int_value IS NOT NULL AND typeof(int_value)!='integer') "
        "OR (float_value IS NOT NULL AND typeof(float_value) NOT IN ('real','integer')) "
        "OR (bool_value IS NOT NULL AND typeof(bool_value)!='integer') "
        "OR ((str_value IS NOT NULL)+(int_value IS NOT NULL)+(float_value IS NOT NULL)+"
        "(bool_value IS NOT NULL))!=1 THEN 1 ELSE 0 END) FROM segment_metadata",
        limits.source_segments,
        (36, limits.metadata_key_bytes, limits.scalar_bytes),
    )
    if collection_metadata_count + segment_metadata_count > limits.source_segments:
        raise _ChromaScanError()
    if connection.execute(
        "SELECT COUNT(*) FROM collection_metadata m LEFT JOIN collections c "
        "ON c.id=m.collection_id WHERE c.id IS NULL"
    ).fetchone() != (0,) or connection.execute(
        "SELECT COUNT(*) FROM segment_metadata m LEFT JOIN segments s "
        "ON s.id=m.segment_id WHERE s.id IS NULL"
    ).fetchone() != (0,):
        raise _ChromaScanError()
    vector_ids = set()

    def rows():
        for row in tenants:
            yield ("tenant",) + row
        for row in databases:
            yield ("database",) + row
        observed = 0
        for row in connection.execute(
            "SELECT id,name,dimension,database_id,config_json_str,schema_str "
            "FROM collections ORDER BY id"
        ):
            observed += 1
            if type(row) is not tuple or len(row) != 6:
                raise _ChromaScanError()
            identifier, name, dimension, database_id, config, schema_value = row
            if (
                type(identifier) is not str
                or _UUID_RE.fullmatch(identifier) is None
                or identifier in collection_ids
                or database_id != "00000000-0000-0000-0000-000000000000"
                or (dimension is not None and (type(dimension) is not int or dimension <= 0))
            ):
                raise _ChromaScanError()
            collection_ids.add(identifier)
            _utf8_length(name, limits.collection_name_bytes)
            for value in (config, schema_value):
                if value is not None:
                    _utf8_length(value, 1_048_576)
            yield ("collection",) + row
        if observed != collection_count:
            raise _ChromaScanError()
        observed = 0
        for row in connection.execute(
            "SELECT id,type,scope,collection FROM segments ORDER BY id"
        ):
            observed += 1
            if type(row) is not tuple or len(row) != 4:
                raise _ChromaScanError()
            identifier, kind, scope, collection = row
            if (
                type(identifier) is not str
                or _UUID_RE.fullmatch(identifier) is None
                or collection not in collection_ids
            ):
                raise _ChromaScanError()
            if scope == "VECTOR" and kind == "urn:chroma:segment/vector/hnsw-local-persisted":
                vector_ids.add(identifier)
                if len(vector_ids) > limits.collections:
                    raise _ChromaScanError()
            yield ("segment",) + row
        if observed != segment_count:
            raise _ChromaScanError()
        metadata_tables = (
            ("collection_metadata", "collection_id", collection_metadata_count),
            ("segment_metadata", "segment_id", segment_metadata_count),
        )
        for table, identity_column, expected_count in metadata_tables:
            observed = 0
            cursor = connection.execute(
                "SELECT " + identity_column + ",key,str_value,int_value,float_value,bool_value "
                "FROM " + table + " ORDER BY " + identity_column + ",key"
            )
            for row in cursor:
                observed += 1
                if type(row) is not tuple or len(row) != 6:
                    raise _ChromaScanError()
                _utf8_length(row[0], 36)
                _utf8_length(row[1], limits.metadata_key_bytes)
                values = row[2:]
                if sum(value is not None for value in values) != 1:
                    raise _ChromaScanError()
                if values[0] is not None:
                    _utf8_length(values[0], limits.scalar_bytes)
                if values[1] is not None and type(values[1]) is not int:
                    raise _ChromaScanError()
                if values[2] is not None and (
                    type(values[2]) not in {int, float}
                    or (type(values[2]) is float and not math.isfinite(values[2]))
                ):
                    raise _ChromaScanError()
                if values[3] is not None and values[3] not in {0, 1}:
                    raise _ChromaScanError()
                yield (table,) + row
            if observed != expected_count:
                raise _ChromaScanError()

    digest = _digest_sql_rows(key, b"RLG/WP7C/sqlite/catalog/v1", rows())
    return digest, frozenset(vector_ids)


def _record_store_evidence(
    connection: sqlite3.Connection,
    key: bytes,
    limits: _ChromaScanLimits,
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
) -> bytes:
    """Hash every record-bearing SQLite value without retaining source rows."""
    def check_control() -> None:
        _check_control(deadline, clock, cancelled)

    check_control()
    for table, columns in (
        (
            "embeddings_queue",
            (
                "seq_id",
                "created_at",
                "operation",
                "topic",
                "id",
                "vector",
                "encoding",
                "metadata",
            ),
        ),
        ("embeddings_queue_config", ("id", "config_json_str")),
        (
            "embeddings",
            ("id", "segment_id", "embedding_id", "seq_id", "created_at"),
        ),
        (
            "embedding_metadata",
            (
                "id",
                "key",
                "string_value",
                "int_value",
                "float_value",
                "bool_value",
            ),
        ),
        ("max_seq_id", ("segment_id", "seq_id")),
        (
            "embedding_metadata_array",
            (
                "id",
                "key",
                "string_value",
                "int_value",
                "float_value",
                "bool_value",
            ),
        ),
        ("embedding_fulltext_search", ("string_value",)),
        ("maintenance_log", ("id", "timestamp", "operation")),
    ):
        _require_table_schema(connection, table, columns)

    queue_summary = connection.execute(
        "SELECT COUNT(*),MAX(length(CAST(created_at AS BLOB))),"
        "MAX(length(CAST(topic AS BLOB))),MAX(length(CAST(id AS BLOB))),"
        "MAX(CASE WHEN encoding IS NULL THEN 0 ELSE length(CAST(encoding AS BLOB)) END),"
        "MAX(CASE WHEN vector IS NULL THEN 0 ELSE length(vector) END),"
        "MAX(CASE WHEN metadata IS NULL THEN 0 ELSE length(CAST(metadata AS BLOB)) END),"
        "SUM(CASE WHEN vector IS NULL THEN 0 ELSE length(vector) END)+"
        "SUM(CASE WHEN metadata IS NULL THEN 0 ELSE length(CAST(metadata AS BLOB)) END),"
        "SUM(CASE WHEN typeof(seq_id)!='integer' OR typeof(created_at)!='text' "
        "OR typeof(operation)!='integer' OR typeof(topic)!='text' OR typeof(id)!='text' "
        "OR (vector IS NOT NULL AND typeof(vector)!='blob') "
        "OR (encoding IS NOT NULL AND typeof(encoding)!='text') "
        "OR (metadata IS NOT NULL AND typeof(metadata)!='text') THEN 1 ELSE 0 END) "
        "FROM embeddings_queue"
    ).fetchone()
    if type(queue_summary) is not tuple or len(queue_summary) != 9:
        raise _ChromaScanError()
    queue_summary = tuple(0 if value is None else value for value in queue_summary)
    if (
        any(type(value) is not int or value < 0 for value in queue_summary)
        or queue_summary[0] > limits.source_segments
        or queue_summary[1] > 64
        or queue_summary[2] > 1_024
        or queue_summary[3] > limits.record_id_bytes
        or queue_summary[4] > 64
        or queue_summary[5] > _snapshot._MAX_SINGLE_FILE_BYTES
        or queue_summary[6] > _snapshot._MAX_SINGLE_FILE_BYTES
        or queue_summary[7] > _snapshot._MAX_SOURCE_BYTES
        or queue_summary[8] != 0
    ):
        raise _ChromaScanError()

    queue_digest = hmac.new(key, digestmod=hashlib.sha256)
    _update_frame(queue_digest, b"domain", b"RLG/WP7C/sqlite/queue/v1")
    observed_queue = 0
    queue_cursor = connection.execute(
        "SELECT seq_id,created_at,operation,topic,id,encoding,"
        "CASE WHEN vector IS NULL THEN NULL ELSE length(vector) END,"
        "CASE WHEN metadata IS NULL THEN NULL ELSE length(CAST(metadata AS BLOB)) END "
        "FROM embeddings_queue ORDER BY seq_id"
    )
    for row in queue_cursor:
        check_control()
        observed_queue += 1
        if type(row) is not tuple or len(row) != 8 or observed_queue > queue_summary[0]:
            raise _ChromaScanError()
        seq_id, created_at, operation, topic, record_id, encoding, vector_size, metadata_size = row
        if (
            type(seq_id) is not int
            or type(created_at) is not str
            or type(operation) is not int
            or type(topic) is not str
            or type(record_id) is not str
            or (encoding is not None and type(encoding) is not str)
            or (vector_size is not None and type(vector_size) is not int)
            or (metadata_size is not None and type(metadata_size) is not int)
        ):
            raise _ChromaScanError()
        _utf8_length(created_at, 64)
        _utf8_length(topic, 1_024)
        _utf8_length(record_id, limits.record_id_bytes)
        if encoding is not None:
            _utf8_length(encoding, 64)
        _update_frame(queue_digest, b"row", observed_queue.to_bytes(8, "big"))
        for value in row:
            _update_sql_value(queue_digest, value)
        for column, size in (("vector", vector_size), ("metadata", metadata_size)):
            if size is None:
                continue
            if size < 0 or size > _snapshot._MAX_SINGLE_FILE_BYTES:
                raise _ChromaScanError()
            offset = 1
            chunk_number = 0
            remaining = size
            while remaining:
                check_control()
                chunk_number += 1
                chunk_size = min(_FILE_CHUNK, remaining)
                chunk_row = connection.execute(
                    "SELECT substr(CAST(" + column + " AS BLOB),?,?) "
                    "FROM embeddings_queue WHERE seq_id=?",
                    (offset, chunk_size, seq_id),
                ).fetchone()
                if (
                    type(chunk_row) is not tuple
                    or len(chunk_row) != 1
                    or type(chunk_row[0]) is not bytes
                    or len(chunk_row[0]) != chunk_size
                ):
                    raise _ChromaScanError()
                _update_frame(
                    queue_digest,
                    column.encode("ascii") + b"-chunk",
                    chunk_number.to_bytes(8, "big") + chunk_row[0],
                )
                offset += chunk_size
                remaining -= chunk_size
    if observed_queue != queue_summary[0]:
        raise _ChromaScanError()
    _update_frame(queue_digest, b"rows", observed_queue.to_bytes(8, "big"))

    _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(CASE WHEN config_json_str IS NULL THEN 0 ELSE "
        "length(CAST(config_json_str AS BLOB)) END),"
        "SUM(CASE WHEN typeof(id)!='integer' OR (config_json_str IS NOT NULL AND "
        "typeof(config_json_str)!='text') THEN 1 ELSE 0 END) "
        "FROM embeddings_queue_config",
        1,
        (1_048_576,),
    )
    _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(length(CAST(segment_id AS BLOB))),"
        "MAX(length(CAST(embedding_id AS BLOB))),MAX(length(CAST(seq_id AS BLOB))),"
        "MAX(length(CAST(created_at AS BLOB))),"
        "SUM(CASE WHEN typeof(id)!='integer' OR typeof(segment_id)!='text' "
        "OR typeof(embedding_id)!='text' OR typeof(seq_id) NOT IN ('blob','integer') "
        "OR typeof(created_at)!='text' THEN 1 ELSE 0 END) FROM embeddings",
        limits.records,
        (36, limits.record_id_bytes, 64, 64),
    )
    for table in ("embedding_metadata", "embedding_metadata_array"):
        _bounded_table_summary(
            connection,
            "SELECT COUNT(*),MAX(length(CAST(key AS BLOB))),"
            "MAX(CASE WHEN string_value IS NULL THEN 0 ELSE "
            "length(CAST(string_value AS BLOB)) END),"
            "SUM(CASE WHEN typeof(id)!='integer' OR typeof(key)!='text' "
            "OR (string_value IS NOT NULL AND typeof(string_value)!='text') "
            "OR (int_value IS NOT NULL AND typeof(int_value)!='integer') "
            "OR (float_value IS NOT NULL AND typeof(float_value) NOT IN ('real','integer')) "
            "OR (bool_value IS NOT NULL AND typeof(bool_value)!='integer') "
            "OR ((string_value IS NOT NULL)+(int_value IS NOT NULL)+"
            "(float_value IS NOT NULL)+(bool_value IS NOT NULL))!=1 "
            "THEN 1 ELSE 0 END) FROM " + table,
            limits.source_segments,
            (limits.metadata_key_bytes, limits.scalar_bytes),
        )
    _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(length(CAST(segment_id AS BLOB))),"
        "SUM(CASE WHEN typeof(segment_id)!='text' OR typeof(seq_id)!='integer' "
        "THEN 1 ELSE 0 END) FROM max_seq_id",
        limits.collections,
        (36,),
    )
    _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(length(CAST(string_value AS BLOB))),"
        "SUM(CASE WHEN typeof(string_value)!='text' THEN 1 ELSE 0 END) "
        "FROM embedding_fulltext_search",
        limits.source_segments,
        (limits.document_bytes,),
    )
    _bounded_table_summary(
        connection,
        "SELECT COUNT(*),MAX(length(CAST(operation AS BLOB))),"
        "SUM(CASE WHEN typeof(id)!='integer' OR typeof(timestamp)!='integer' "
        "OR typeof(operation)!='text' THEN 1 ELSE 0 END) FROM maintenance_log",
        limits.source_segments,
        (1_024,),
    )

    def rows():
        table_queries = (
            ("embeddings_queue_config", "SELECT id,config_json_str FROM embeddings_queue_config ORDER BY id"),
            ("embeddings", "SELECT id,segment_id,embedding_id,seq_id,created_at FROM embeddings ORDER BY id"),
            ("embedding_metadata", "SELECT id,key,string_value,int_value,float_value,bool_value FROM embedding_metadata ORDER BY id,key"),
            ("max_seq_id", "SELECT segment_id,seq_id FROM max_seq_id ORDER BY segment_id"),
            ("embedding_metadata_array", "SELECT id,key,string_value,int_value,float_value,bool_value FROM embedding_metadata_array ORDER BY id,key,rowid"),
            ("embedding_fulltext_search", "SELECT rowid,string_value FROM embedding_fulltext_search ORDER BY rowid"),
            ("maintenance_log", "SELECT id,timestamp,operation FROM maintenance_log ORDER BY id"),
        )
        total = 0
        for table, query in table_queries:
            for row in connection.execute(query):
                check_control()
                total += 1
                if total > 1_000_000:
                    raise _ChromaScanError()
                yield (table,) + row

    table_digest = _digest_sql_rows(
        key,
        b"RLG/WP7C/sqlite/record-tables/v1",
        rows(),
        check_control,
    )
    check_control()
    return _token(
        key,
        b"RLG/WP7C/sqlite/records/v1",
        ((b"queue", queue_digest.digest()), (b"tables", table_digest)),
    )


def _store_preflight(
    data: Path,
    version: str,
    key: bytes,
    limits: _ChromaScanLimits,
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
) -> _StoreEvidence:
    connection = _open_sqlite_readonly(data)
    interrupted = [False]

    def progress() -> int:
        try:
            now = clock()
            stopped = cancelled() if cancelled is not None else False
            invalid = (
                isinstance(now, bool)
                or not isinstance(now, (int, float))
                or not math.isfinite(now)
                or bool(stopped)
                or float(now) > deadline
            )
        except BaseException:
            invalid = True
        if invalid:
            interrupted[0] = True
            return 1
        return 0

    try:
        connection.set_progress_handler(progress, 1_000)
        _check_control(deadline, clock, cancelled)
        schema = _schema_evidence(connection, version, key)
        _check_control(deadline, clock, cancelled)
        algorithm, migration = _migration_evidence(connection, version, key)
        _check_control(deadline, clock, cancelled)
        catalog, vector_ids = _catalog_evidence(connection, key, limits)
        _check_control(deadline, clock, cancelled)
        records = _record_store_evidence(
            connection, key, limits, deadline, clock, cancelled
        )
        if (
            interrupted[0]
            or connection.execute("PRAGMA query_only").fetchone() != (1,)
        ):
            raise _ChromaScanError()
        _check_control(deadline, clock, cancelled)
        return _StoreEvidence(
            algorithm, schema, catalog, migration, records, vector_ids
        )
    except _ChromaScanError:
        raise
    except (sqlite3.Error, OSError, ValueError, TypeError):
        raise _ChromaScanError() from None
    finally:
        connection.set_progress_handler(None, 0)
        connection.close()


def _inventory_files(
    data: Path,
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
) -> Dict[Tuple[str, ...], Tuple[int, bytes]]:
    root = _snapshot._validate_directory(data, error_type=_ChromaScanError)
    pending = [(data, tuple(), 0)]
    result = {}
    directories = 0
    scheduled = 0
    while pending:
        _check_control(deadline, clock, cancelled)
        current, parts, depth = pending.pop()
        if depth > _snapshot._MAX_RELATIVE_DEPTH:
            raise _ChromaScanError()
        identity = _snapshot._validate_directory(
            current, device=root.device, error_type=_ChromaScanError
        )
        if _snapshot._windows_has_named_streams(current):
            raise _ChromaScanError()
        _snapshot._assert_restrictive(current, True)
        directories += 1
        if directories > _snapshot._MAX_SOURCE_DIRECTORIES:
            raise _ChromaScanError()
        if parts:
            if parts in result or len(result) >= _MAX_EFFECT_PATHS:
                raise _ChromaScanError()
            result[parts] = (-1, b"directory")
        children = []
        try:
            with os.scandir(current) as iterator:
                for child in iterator:
                    scheduled += 1
                    if scheduled > _MAX_EFFECT_PATHS:
                        raise _ChromaScanError()
                    children.append(child.name)
            children.sort(key=os.fsencode)
        except _ChromaScanError:
            raise
        except (OSError, ValueError, TypeError, UnicodeError):
            raise _ChromaScanError() from None
        for name in children:
            _check_control(deadline, clock, cancelled)
            _snapshot._validate_component(name)
            path = current / name
            child_parts = parts + (name,)
            raw = os.lstat(path)
            observed = _snapshot._identity(raw)
            if observed.device != root.device or stat.S_ISLNK(observed.mode) or _snapshot._is_reparse(observed):
                raise _ChromaScanError()
            if stat.S_ISDIR(observed.mode):
                pending.append((path, child_parts, depth + 1))
                continue
            _regular_file(path, root.device)
            digest = hashlib.sha256()
            descriptor = None
            try:
                flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
                flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOINHERIT", 0))
                flags |= int(getattr(os, "O_NOFOLLOW", 0))
                descriptor = os.open(path, flags)
                opened = _snapshot._identity(os.fstat(descriptor))
                if not _snapshot._same_path_handle_identity(observed, opened):
                    raise _ChromaScanError()
                total = 0
                while True:
                    _check_control(deadline, clock, cancelled)
                    chunk = os.read(descriptor, _FILE_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _snapshot._MAX_SINGLE_FILE_BYTES:
                        raise _ChromaScanError()
                    digest.update(chunk)
                closed = _snapshot._identity(os.fstat(descriptor))
                if (
                    total != observed.size
                    or not _snapshot._same_identity(opened, closed)
                    or not _snapshot._same_identity(observed, _snapshot._identity(os.lstat(path)))
                ):
                    raise _ChromaScanError()
            except _ChromaScanError:
                raise
            except (OSError, ValueError, TypeError):
                raise _ChromaScanError() from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if child_parts in result:
                raise _ChromaScanError()
            result[child_parts] = (total, digest.digest())
    return result


def _inventory_evidence(
    key: bytes, inventory: Mapping[Tuple[str, ...], Tuple[int, bytes]]
) -> bytes:
    return _snapshot._work_copy_evidence(
        key,
        (
            (
                parts,
                value == (-1, b"directory"),
                value[0],
                None if value == (-1, b"directory") else value[1],
            )
            for parts, value in inventory.items()
        ),
    )


def _borrow_request(
    version: str,
    algorithm: str,
    limits: _ChromaScanLimits,
    useful_seconds: float,
) -> dict:
    return {
        "algorithm": algorithm,
        "limits": {name: getattr(limits, name) for name in limits.__dataclass_fields__},
        "useful_seconds": useful_seconds,
        "version": version,
    }


def _detection_request(
    version: str,
    algorithm: str,
    limits: _ChromaScanLimits,
    detector_limits: _DetectorLimits,
    locale: Optional[str],
    useful_seconds: float,
) -> dict:
    if locale is not None and type(locale) is not str:
        raise _ChromaScanError()
    return {
        "algorithm": algorithm,
        "detector_limits": {
            name: getattr(detector_limits, name)
            for name in detector_limits.__dataclass_fields__
        },
        "limits": {name: getattr(limits, name) for name in limits.__dataclass_fields__},
        "locale": locale,
        "mode": "detect",
        "useful_seconds": useful_seconds,
        "version": version,
    }


def _json_object(pairs: Iterable[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise _ChromaScanError()
        result[key] = value
    return result


def _encode_frame(document: dict, maximum: int) -> bytes:
    try:
        payload = json.dumps(
            document, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise _ChromaScanError() from None
    if len(payload) > maximum:
        raise _ChromaScanError()
    return len(payload).to_bytes(_FRAME_PREFIX_BYTES, "big") + payload


def _decode_frame(encoded: bytes, maximum: int) -> dict:
    if type(encoded) is not bytes or len(encoded) < _FRAME_PREFIX_BYTES:
        raise _ChromaScanError()
    length = int.from_bytes(encoded[:_FRAME_PREFIX_BYTES], "big")
    if length > maximum or len(encoded) != _FRAME_PREFIX_BYTES + length:
        raise _ChromaScanError()
    try:
        value = json.loads(encoded[_FRAME_PREFIX_BYTES:].decode("ascii"), object_pairs_hook=_json_object)
    except _ChromaScanError:
        raise
    except (UnicodeError, ValueError, TypeError):
        raise _ChromaScanError() from None
    if type(value) is not dict:
        raise _ChromaScanError()
    return value


def _canonical_float(value: float) -> str:
    if type(value) is not float or not math.isfinite(value):
        raise _ChromaScanError()
    text = repr(value).lower()
    if "e" not in text:
        return text
    mantissa, exponent = text.split("e", 1)
    sign = ""
    if exponent[:1] in {"+", "-"}:
        sign, exponent = exponent[0], exponent[1:]
    if not exponent.isdigit():
        raise _ChromaScanError()
    exponent = exponent.lstrip("0") or "0"
    return mantissa + "e" + sign + exponent


def _canonical_scalar(value: object, limits: _ChromaScanLimits) -> Tuple[bytes, bytes]:
    if type(value) is str:
        return b"string", _encoded(value, limits.scalar_bytes)
    if type(value) is bool:
        return b"bool", b"true" if value else b"false"
    if type(value) is int:
        encoded = str(value).encode("ascii")
        if len(encoded) > limits.scalar_bytes:
            raise _ChromaScanError()
        return b"integer", encoded
    if type(value) is float:
        encoded = _canonical_float(value).encode("ascii")
        if len(encoded) > limits.scalar_bytes:
            raise _ChromaScanError()
        return b"float", encoded
    raise _ChromaScanError()


class _DetectorAccumulator:
    """Validate findings in-worker and retain privacy-minimal counters only."""

    __slots__ = (
        "_allowed_types",
        "_by_type",
        "_current_findings",
        "_detect",
        "_in_record",
        "_limits",
        "_locale",
        "_records",
        "_records_with_findings",
        "_segments",
        "_source_bytes",
        "_total_findings",
    )

    def __init__(
        self,
        locale: Optional[str],
        limits: _DetectorLimits,
        detect_function,
        allowed_types: frozenset,
    ) -> None:
        if (
            locale is not None and type(locale) is not str
        ) or type(limits) is not _DetectorLimits or type(allowed_types) is not frozenset:
            raise _ChromaScanError()
        if (
            not allowed_types
            or len(allowed_types) > limits.entity_types
            or any(
                type(value) is not str or _ENTITY_TYPE_RE.fullmatch(value) is None
                for value in allowed_types
            )
        ):
            raise _ChromaScanError()
        self._locale = locale
        self._limits = limits
        self._detect = detect_function
        self._allowed_types = allowed_types
        self._records = 0
        self._records_with_findings = 0
        self._segments = 0
        self._source_bytes = 0
        self._total_findings = 0
        self._by_type: Dict[str, int] = {}
        self._in_record = False
        self._current_findings = 0

    def start_record(self) -> None:
        if self._in_record or self._records >= self._limits.records:
            raise _ChromaScanError()
        self._in_record = True
        self._current_findings = 0

    def consume(self, text: object, utf8_bytes: object) -> None:
        if not self._in_record or type(utf8_bytes) is not int or utf8_bytes < 0:
            raise _ChromaScanError()
        observed_bytes = _utf8_length(text, self._limits.segment_bytes)
        if observed_bytes != utf8_bytes:
            raise _ChromaScanError()
        next_segments = self._segments + 1
        next_bytes = self._source_bytes + utf8_bytes
        if (
            next_segments > self._limits.source_segments
            or next_bytes > self._limits.source_utf8_bytes
        ):
            raise _ChromaScanError()
        try:
            findings = self._detect(text, locale=self._locale)
        except BaseException:
            raise _ChromaScanError() from None
        if type(findings) is not list or len(findings) > self._limits.findings_per_segment:
            raise _ChromaScanError()
        counts: Dict[str, int] = {}
        for finding in findings:
            if type(finding) is not dict or set(finding) != {
                "type",
                "start",
                "end",
                "score",
                "text",
            }:
                raise _ChromaScanError()
            entity_type = finding.get("type")
            start = finding.get("start")
            end = finding.get("end")
            score = finding.get("score")
            detected_text = finding.get("text")
            if (
                type(entity_type) is not str
                or entity_type not in self._allowed_types
                or _ENTITY_TYPE_RE.fullmatch(entity_type) is None
                or type(start) is not int
                or type(end) is not int
                or start < 0
                or end <= start
                or end > len(text)
                or isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not math.isfinite(score)
                or score < 0
                or score > 1
                or type(detected_text) is not str
                or detected_text != text[start:end]
            ):
                raise _ChromaScanError()
            counts[entity_type] = counts.get(entity_type, 0) + 1

        next_total = self._total_findings + len(findings)
        if next_total > self._limits.total_findings:
            raise _ChromaScanError()
        for entity_type, count in counts.items():
            self._by_type[entity_type] = self._by_type.get(entity_type, 0) + count
        if len(self._by_type) > self._limits.entity_types:
            raise _ChromaScanError()
        self._segments = next_segments
        self._source_bytes = next_bytes
        self._total_findings = next_total
        self._current_findings += len(findings)

    def finish_record(self) -> None:
        if not self._in_record:
            raise _ChromaScanError()
        self._records += 1
        if self._current_findings:
            self._records_with_findings += 1
        self._current_findings = 0
        self._in_record = False

    def result(self) -> dict:
        if self._in_record or sum(self._by_type.values()) != self._total_findings:
            raise _ChromaScanError()
        if (
            self._records_with_findings > self._records
            or self._records_with_findings > self._total_findings
            or (self._total_findings == 0) != (not self._by_type)
        ):
            raise _ChromaScanError()
        return {
            "finding_counts_by_type": dict(sorted(self._by_type.items())),
            "records_completed": self._records,
            "records_with_findings": self._records_with_findings,
            "source_segments_completed": self._segments,
            "source_utf8_bytes_completed": self._source_bytes,
            "total_findings": self._total_findings,
        }


def _canonical_content(
    key: bytes,
    document: object,
    metadata: object,
    limits: _ChromaScanLimits,
    deadline: Optional[float] = None,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Optional[Callable[[], bool]] = None,
    segment_consumer=None,
) -> Tuple[bytes, bytes, int, int]:
    def check_control() -> None:
        if deadline is not None:
            _check_control(deadline, clock, cancelled)

    check_control()
    frames = []
    segments = 0
    source_bytes = 0
    if document is None:
        frames.append((b"document-none", b""))
    else:
        encoded_document = _encoded(document, limits.document_bytes)
        if segment_consumer is not None:
            segment_consumer(document, len(encoded_document))
        frames.append((b"document", encoded_document))
        segments += 1
        source_bytes += len(encoded_document)
        check_control()
    if metadata is None:
        frames.append((b"metadata-none", b""))
    elif type(metadata) is dict:
        if len(metadata) > limits.metadata_leaves:
            raise _ChromaScanError()
        frames.append((b"metadata-map", len(metadata).to_bytes(8, "big")))
        ordered = []
        for metadata_key, value in metadata.items():
            key_encoded = _encoded(metadata_key, limits.metadata_key_bytes)
            ordered.append((key_encoded, metadata_key, value))
        ordered.sort(key=lambda item: item[0])
        metadata_bytes = 0
        leaves = 0
        for key_encoded, metadata_key, value in ordered:
            check_control()
            frames.append((b"metadata-key", key_encoded))
            if segment_consumer is not None:
                segment_consumer(metadata_key, len(key_encoded))
            segments += 1
            source_bytes += len(key_encoded)
            metadata_bytes += len(key_encoded)
            if metadata_bytes > limits.metadata_bytes:
                raise _ChromaScanError()
            if value is None:
                frames.append((b"value-none", b""))
            elif type(value) is list:
                if not value or len(value) > limits.array_elements:
                    raise _ChromaScanError()
                scalar_type = type(value[0])
                if scalar_type not in {str, bool, int, float} or any(type(item) is not scalar_type for item in value):
                    raise _ChromaScanError()
                frames.append((b"array", len(value).to_bytes(8, "big")))
                for item in value:
                    check_control()
                    tag, encoded = _canonical_scalar(item, limits)
                    if segment_consumer is not None:
                        segment_consumer(encoded.decode("utf-8"), len(encoded))
                    leaves += 1
                    segments += 1
                    source_bytes += len(encoded)
                    metadata_bytes += len(encoded)
                    if leaves > limits.metadata_leaves or metadata_bytes > limits.metadata_bytes:
                        raise _ChromaScanError()
                    frames.append((b"array-" + tag, encoded))
                    check_control()
            else:
                tag, encoded = _canonical_scalar(value, limits)
                if segment_consumer is not None:
                    segment_consumer(encoded.decode("utf-8"), len(encoded))
                leaves += 1
                segments += 1
                source_bytes += len(encoded)
                metadata_bytes += len(encoded)
                if leaves > limits.metadata_leaves or metadata_bytes > limits.metadata_bytes:
                    raise _ChromaScanError()
                frames.append((b"scalar-" + tag, encoded))
                check_control()
            check_control()
    else:
        raise _ChromaScanError()
    if segments > limits.source_segments or source_bytes > limits.source_utf8_bytes:
        raise _ChromaScanError()
    check_control()
    return (
        _token(key, _CONTENT_DOMAIN, frames),
        _witness(key, _CONTENT_DOMAIN, frames),
        segments,
        source_bytes,
    )


def _call(
    function,
    deadline: float,
    cancelled: Optional[Callable[[], bool]],
    *args,
    **kwargs,
):
    _check_control(deadline, time.monotonic, cancelled)
    try:
        result = function(*args, **kwargs)
    except BaseException:
        raise _ChromaScanError() from None
    _check_control(deadline, time.monotonic, cancelled)
    return result


def _record_page(result: object, expected: int) -> Tuple[list, list, list]:
    if type(result) is not dict or set(result) != {
        "ids",
        "embeddings",
        "documents",
        "uris",
        "included",
        "data",
        "metadatas",
    }:
        raise _ChromaScanError()
    ids = result.get("ids")
    documents = result.get("documents")
    metadatas = result.get("metadatas")
    included = result.get("included")
    if (
        type(ids) is not list
        or type(documents) is not list
        or type(metadatas) is not list
        or len(ids) != expected
        or len(documents) != expected
        or len(metadatas) != expected
        or result.get("embeddings") is not None
        or result.get("uris") is not None
        or result.get("data") is not None
        or type(included) is not list
        or set(included) != {"documents", "metadatas"}
        or len(included) != 2
    ):
        raise _ChromaScanError()
    return ids, documents, metadatas


def _enumeration_pass(
    client,
    key: bytes,
    limits: _ChromaScanLimits,
    deadline: float,
    detector: Optional[_DetectorAccumulator] = None,
):
    collection_count = _call(client.count_collections, deadline, None)
    collection_count = _exact_int(collection_count, limits.collections)
    collection_manifest = []
    total_records = 0
    total_segments = 0
    total_source_bytes = 0
    retained_entries = 0
    offset = 0
    while offset < collection_count:
        expected = min(limits.collection_page, collection_count - offset)
        page = _call(
            client.list_collections,
            deadline,
            None,
            limit=limits.collection_page,
            offset=offset,
        )
        if type(page) is not list or len(page) != expected:
            raise _ChromaScanError()
        for collection_value in page:
            _check_control(deadline, time.monotonic, None)
            try:
                name = collection_value.name
                identifier_value = collection_value.id
            except BaseException:
                raise _ChromaScanError() from None
            name_encoded = _encoded(name, limits.collection_name_bytes)
            if type(identifier_value) is not uuid.UUID:
                raise _ChromaScanError()
            identifier = str(identifier_value).encode("ascii")
            frames = ((b"name", name_encoded), (b"uuid", identifier))
            collection_token = _token(key, _COLLECTION_DOMAIN, frames)
            collection_witness = _witness(key, _COLLECTION_DOMAIN, frames)
            if any(entry[0][:32] == collection_token for entry in collection_manifest):
                raise _ChromaScanError()
            retained_entries += 1
            if (
                retained_entries > limits.manifest_entries
                or retained_entries * limits.entry_accounting > limits.manifest_memory
            ):
                raise _ChromaScanError()
            collection = _call(
                client.get_collection,
                deadline,
                None,
                name=name,
                embedding_function=None,
            )
            try:
                opened_name = collection.name
                opened_identifier = collection.id
            except BaseException:
                raise _ChromaScanError() from None
            if opened_name != name or opened_identifier != identifier_value:
                raise _ChromaScanError()
            record_count = _call(collection.count, deadline, None)
            record_count = _exact_int(record_count, limits.records - total_records)
            records = []
            record_offset = 0
            while record_offset < record_count:
                record_expected = min(limits.record_page, record_count - record_offset)
                result = _call(
                    collection.get,
                    deadline,
                    None,
                    limit=limits.record_page,
                    offset=record_offset,
                    include=["documents", "metadatas"],
                )
                ids, documents, metadatas = _record_page(result, record_expected)
                for record_id, document, metadata in zip(ids, documents, metadatas):
                    _check_control(deadline, time.monotonic, None)
                    record_encoded = _encoded(record_id, limits.record_id_bytes)
                    record_frames = (
                        (b"collection", collection_token),
                        (b"record-id", record_encoded),
                    )
                    record_token = _token(key, _RECORD_DOMAIN, record_frames)
                    record_witness = _witness(key, _RECORD_DOMAIN, record_frames)
                    if detector is not None:
                        detector.start_record()
                    content, content_witness, segments, source_bytes = _canonical_content(
                        key,
                        document,
                        metadata,
                        limits,
                        deadline,
                        segment_consumer=(detector.consume if detector is not None else None),
                    )
                    if detector is not None:
                        detector.finish_record()
                    records.append(
                        record_token + record_witness + content + content_witness
                    )
                    retained_entries += 1
                    total_records += 1
                    total_segments += segments
                    total_source_bytes += source_bytes
                    if (
                        retained_entries > limits.manifest_entries
                        or retained_entries * limits.entry_accounting > limits.manifest_memory
                        or total_records > limits.records
                        or total_segments > limits.source_segments
                        or total_source_bytes > limits.source_utf8_bytes
                    ):
                        raise _ChromaScanError()
                record_offset += record_expected
            trailing = _call(
                collection.get,
                deadline,
                None,
                limit=limits.record_page,
                offset=record_count,
                include=["documents", "metadatas"],
            )
            _record_page(trailing, 0)
            if _call(collection.count, deadline, None) != record_count:
                raise _ChromaScanError()
            records.sort()
            for previous, current in zip(records, records[1:]):
                if previous[:32] == current[:32]:
                    raise _ChromaScanError()
            content_order = sorted(records, key=lambda entry: entry[64:96])
            for previous, current in zip(content_order, content_order[1:]):
                if (
                    previous[64:96] == current[64:96]
                    and previous[96:128] != current[96:128]
                ):
                    raise _ChromaScanError()
            collection_manifest.append(
                (
                    collection_token + collection_witness,
                    record_count,
                    tuple(records),
                )
            )
        offset += expected
    trailing_collections = _call(
        client.list_collections,
        deadline,
        None,
        limit=limits.collection_page,
        offset=collection_count,
    )
    if type(trailing_collections) is not list or trailing_collections:
        raise _ChromaScanError()
    if _call(client.count_collections, deadline, None) != collection_count:
        raise _ChromaScanError()
    collection_manifest.sort(key=lambda entry: entry[0])
    return tuple(collection_manifest), (
        collection_count,
        total_records,
        total_segments,
        total_source_bytes,
    )


def _lease_is_held(path: Path, expected: _snapshot._Identity) -> bool:
    descriptor = None
    locked = False
    try:
        flags = os.O_RDWR | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOINHERIT", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(path, flags)
        if not _snapshot._same_path_handle_identity(
            expected, _snapshot._identity(os.fstat(descriptor))
        ):
            return False
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
            return False
        except OSError as error:
            return error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK} or getattr(
                error, "winerror", None
            ) in {32, 33, 36}
    except (OSError, ValueError, TypeError):
        return False
    finally:
        if descriptor is not None:
            if locked:
                try:
                    if os.name == "nt":
                        import msvcrt

                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(descriptor)


def _read_held_lease(path: Path, expected: _snapshot._Identity) -> bytes:
    descriptor = None
    try:
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOINHERIT", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(path, flags)
        identity = _snapshot._identity(os.fstat(descriptor))
        if (
            not _snapshot._same_path_handle_identity(expected, identity)
            or identity.size < 2
            or identity.size > 4_096
        ):
            raise _ChromaScanError()
        if os.name == "nt":
            os.lseek(descriptor, 1, os.SEEK_SET)
            encoded = b"{" + os.read(descriptor, 4_096)
        else:
            encoded = os.read(descriptor, 4_097)
        if (
            len(encoded) != identity.size
            or not _snapshot._same_identity(identity, _snapshot._identity(os.fstat(descriptor)))
            or not _snapshot._same_path_handle_identity(
                identity, _snapshot._identity(os.lstat(path))
            )
        ):
            raise _ChromaScanError()
        return encoded
    except _ChromaScanError:
        raise
    except (OSError, ValueError, TypeError):
        raise _ChromaScanError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _load_held_snapshot_marker(
    snapshot_path: Path,
    workspace_id: str,
    key: bytes,
    lease_expected: _snapshot._Identity,
) -> Tuple[str, str, str]:
    document = _snapshot._parse_document(
        _snapshot._read_bounded(
            snapshot_path / _snapshot._SNAPSHOT_MARKER, 4_096, _ChromaScanError
        ),
        _ChromaScanError,
    )
    if set(document) != {
        "authentication",
        "construction",
        "lease_id",
        "phase",
        "snapshot_id",
        "version",
        "workspace_id",
    }:
        raise _ChromaScanError()
    authentication = document.pop("authentication")
    snapshot_id = document.get("snapshot_id")
    lease_id = document.get("lease_id")
    phase = document.get("phase")
    if (
        type(authentication) is not str
        or type(snapshot_id) is not str
        or type(lease_id) is not str
        or phase != "ready"
        or document != _snapshot._snapshot_body(workspace_id, snapshot_id, lease_id, phase)
        or not hmac.compare_digest(authentication, _snapshot._authentication(key, document))
    ):
        raise _ChromaScanError()
    lease = _snapshot._parse_document(
        _read_held_lease(snapshot_path / _snapshot._LEASE_FILE, lease_expected),
        _ChromaScanError,
    )
    if set(lease) != {
        "authentication",
        "construction",
        "lease_id",
        "snapshot_id",
        "version",
        "workspace_id",
    }:
        raise _ChromaScanError()
    lease_authentication = lease.pop("authentication")
    if (
        type(lease_authentication) is not str
        or lease != _snapshot._lease_body(workspace_id, snapshot_id, lease_id)
        or not hmac.compare_digest(
            lease_authentication, _snapshot._authentication(key, lease)
        )
    ):
        raise _ChromaScanError()
    return snapshot_id, lease_id, phase


def _worker_capability() -> Path:
    data = Path.cwd()
    if type(data) is not _PATH_TYPE or not data.is_absolute():
        raise _ChromaScanError()
    snapshot_path = data.parent
    workspace = snapshot_path.parent
    workspace_id = workspace.name.removeprefix(_snapshot._WORKSPACE_PREFIX)
    expected_snapshot_id = snapshot_path.name.removeprefix(_snapshot._SNAPSHOT_PREFIX)
    if (
        data.name != _snapshot._PAYLOAD_DIRECTORY
        or workspace.name != _snapshot._WORKSPACE_PREFIX + workspace_id
        or snapshot_path.name != _snapshot._SNAPSHOT_PREFIX + expected_snapshot_id
        or _snapshot._TOKEN_RE.fullmatch(workspace_id) is None
        or _snapshot._TOKEN_RE.fullmatch(expected_snapshot_id) is None
        or _snapshot._resolved(data, _ChromaScanError) != data
    ):
        raise _ChromaScanError()
    workspace_identity = _snapshot._validate_directory(workspace, error_type=_ChromaScanError)
    snapshot_identity = _snapshot._validate_directory(
        snapshot_path, device=workspace_identity.device, error_type=_ChromaScanError
    )
    data_identity = _snapshot._validate_directory(
        data, device=workspace_identity.device, error_type=_ChromaScanError
    )
    for path in (workspace, snapshot_path, data):
        if _snapshot._windows_has_named_streams(path):
            raise _ChromaScanError()
        _snapshot._assert_restrictive(path, True)
    loaded_workspace_id, _, loaded_key = _snapshot._load_workspace(
        workspace, _ChromaScanError
    )
    lease_path = snapshot_path / _snapshot._LEASE_FILE
    lease_identity = _regular_file(lease_path, workspace_identity.device)
    snapshot_id, lease_id, phase = _load_held_snapshot_marker(
        snapshot_path, loaded_workspace_id, loaded_key, lease_identity
    )
    if (
        loaded_workspace_id != workspace_id
        or snapshot_id != expected_snapshot_id
        or _snapshot._TOKEN_RE.fullmatch(lease_id) is None
        or phase != "ready"
        or not _lease_is_held(lease_path, lease_identity)
    ):
        raise _ChromaScanError()
    return data


_ATTEMPTED_EGRESS_OR_PROCESS = False


def _deny_attempt(*args, **kwargs):
    global _ATTEMPTED_EGRESS_OR_PROCESS
    _ATTEMPTED_EGRESS_OR_PROCESS = True
    raise _ChromaScanError()


def _audit_hook(event: str, args: tuple) -> None:
    global _ATTEMPTED_EGRESS_OR_PROCESS
    if event.startswith("socket.") or event in {
        "subprocess.Popen",
        "os.system",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.fork",
        "os.forkpty",
    }:
        _ATTEMPTED_EGRESS_OR_PROCESS = True
        raise _ChromaScanError()


class _DeniedSocket(socket.socket):
    def __new__(cls, *args, **kwargs):
        _deny_attempt()


class _UnavailableIPv6Probe:
    """Fail urllib3's import-time local IPv6 bind probe without a real socket."""

    def __new__(cls, *args, **kwargs):
        if args == (socket.AF_INET6,) and not kwargs:
            raise OSError
        _deny_attempt()


class _DeniedPopen(subprocess.Popen):
    def __new__(cls, *args, **kwargs):
        _deny_attempt()


def _sanitize_worker() -> None:
    system_name = {"win32": "Windows", "darwin": "Darwin", "linux": "Linux"}.get(
        sys.platform
    )
    if system_name is None:
        raise _ChromaScanError()
    if os.name == "nt":
        machine_name = os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64")
    else:
        try:
            machine_name = os.uname().machine
        except (OSError, AttributeError):
            raise _ChromaScanError() from None
    platform.system = lambda: system_name
    platform.machine = lambda: machine_name
    preserved = {}
    for name in (
        "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
        "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "SYSTEMDRIVE",
        "PROGRAMDATA", "APPDATA", "LOCALAPPDATA", "TMPDIR",
    ):
        value = os.environ.get(name)
        if value is not None:
            preserved[name] = value
    os.environ.clear()
    os.environ.update(preserved)
    logging.disable(logging.CRITICAL)
    root = logging.getLogger()
    root.handlers.clear()
    socket.socket = _DeniedSocket
    socket.create_connection = _deny_attempt
    socket.getaddrinfo = _deny_attempt
    socket.gethostbyname = _deny_attempt
    socket.gethostbyname_ex = _deny_attempt
    socket.gethostbyaddr = _deny_attempt
    subprocess.Popen = _DeniedPopen
    subprocess.run = _deny_attempt
    subprocess.call = _deny_attempt
    subprocess.check_call = _deny_attempt
    subprocess.check_output = _deny_attempt
    os.system = _deny_attempt
    for name in ("fork", "forkpty", "posix_spawn", "posix_spawnp"):
        if hasattr(os, name):
            setattr(os, name, _deny_attempt)
    sys.addaudithook(_audit_hook)


class _ForbiddenText:
    encoding = "utf-8"
    errors = "strict"

    def write(self, value):
        if value:
            _deny_attempt()
        return 0

    def flush(self):
        return None

    def isatty(self):
        return False

    def fileno(self):
        raise OSError


def _settings_expected(data: Path, algorithm: str) -> dict:
    return {
        "chroma_api_impl": "chromadb.api.rust.RustBindingsAPI",
        "is_persistent": True,
        "persist_directory": str(data),
        "allow_reset": False,
        "anonymized_telemetry": False,
        "chroma_product_telemetry_impl": _TELEMETRY_CLASS,
        "chroma_telemetry_impl": _TELEMETRY_CLASS,
        "chroma_otel_collection_endpoint": "",
        "chroma_otel_collection_headers": {},
        "chroma_otel_granularity": None,
        "chroma_server_host": None,
        "chroma_server_http_port": None,
        "chroma_server_headers": None,
        "chroma_server_ssl_enabled": False,
        "chroma_server_ssl_verify": None,
        "chroma_client_auth_provider": None,
        "chroma_client_auth_credentials": None,
        "migrations": "validate",
        "migrations_hash_algorithm": algorithm,
    }


def _audit_settings(settings, expected: Mapping[str, object]) -> None:
    for name, wanted in expected.items():
        try:
            observed = getattr(settings, name)
        except BaseException:
            raise _ChromaScanError() from None
        if type(observed) is not type(wanted) or observed != wanted:
            raise _ChromaScanError()


def _worker_scan(request: dict) -> dict:
    private_keys = {
        "algorithm",
        "limits",
        "useful_seconds",
        "version",
    }
    detection_keys = private_keys | {"detector_limits", "locale", "mode"}
    if type(request) is not dict:
        raise _ChromaScanError()
    request_keys = frozenset(request)
    if request_keys not in {frozenset(private_keys), frozenset(detection_keys)}:
        raise _ChromaScanError()
    detection_mode = request_keys == frozenset(detection_keys)
    if detection_mode and request.get("mode") != "detect":
        raise _ChromaScanError()
    version = request.get("version")
    algorithm = request.get("algorithm")
    if version not in _CANDIDATES or algorithm not in {"md5", "sha256"}:
        raise _ChromaScanError()
    if detection_mode and version != _PUBLIC_ACTIVATION_VERSION:
        raise _ChromaScanError()
    useful_seconds = request.get("useful_seconds")
    if (
        isinstance(useful_seconds, bool)
        or not isinstance(useful_seconds, (int, float))
        or not math.isfinite(useful_seconds)
        or useful_seconds <= 0
        or useful_seconds > _USEFUL_SECONDS
    ):
        raise _ChromaScanError()
    if type(request.get("limits")) is not dict:
        raise _ChromaScanError()
    try:
        limits = _ChromaScanLimits(**request["limits"])
        detector_limits = (
            _DetectorLimits(**request["detector_limits"])
            if detection_mode and type(request.get("detector_limits")) is dict
            else None
        )
        key = secrets.token_bytes(limits.token_bytes)
    except (TypeError, ValueError, OSError):
        raise _ChromaScanError() from None
    if detection_mode and (
        limits != _PUBLIC_CHROMA_SCAN_LIMITS
        or detector_limits != _DEFAULT_DETECTOR_LIMITS
        or (request.get("locale") is not None and type(request.get("locale")) is not str)
    ):
        raise _ChromaScanError()
    if type(key) is not bytes or len(key) != limits.token_bytes:
        raise _ChromaScanError()
    deadline = time.monotonic() + float(useful_seconds)
    data = _worker_capability()
    if _candidate_version() != version:
        raise _ChromaScanError()
    before = _store_preflight(
        data, version, key, limits, deadline, time.monotonic, None
    )
    if before.algorithm != algorithm:
        raise _ChromaScanError()
    _sanitize_worker()
    detector = None
    if detection_mode:
        denied_socket = socket.socket
        try:
            socket.socket = _UnavailableIPv6Probe
            import tldextract

            offline_tldextract = tldextract.TLDExtract(
                cache_dir=None,
                suffix_list_urls=(),
            )
        except BaseException:
            raise _ChromaScanError() from None
        finally:
            socket.socket = denied_socket
        try:
            tldextract.extract = offline_tldextract
            from ragleakguard.detect import (
                DEFAULT_ENTITIES,
                LOCALE_PACKS,
                detect,
                validate_detection_runtime,
            )

            locale = validate_detection_runtime(request.get("locale"))
            if locale != request.get("locale"):
                raise _ChromaScanError()
            allowed_types = set(DEFAULT_ENTITIES)
            if locale is not None:
                allowed_types.update(LOCALE_PACKS[locale])
            detector = _DetectorAccumulator(
                locale,
                detector_limits,
                detect,
                frozenset(allowed_types),
            )
        except _ChromaScanError:
            raise
        except BaseException:
            raise _ChromaScanError() from None
    try:
        import chromadb
        from chromadb.config import DEFAULT_DATABASE, DEFAULT_TENANT, Settings
        from chromadb.telemetry.product import ProductTelemetryClient
    except BaseException:
        raise _ChromaScanError() from None

    global _LocalTelemetry

    def _capture(self, event) -> None:
        return None

    _capture.__override__ = True
    _LocalTelemetry = type(
        "_LocalTelemetry",
        (ProductTelemetryClient,),
        {"__module__": __name__, "capture": _capture},
    )

    if chromadb.__version__ != version or DEFAULT_TENANT != "default_tenant" or DEFAULT_DATABASE != "default_database":
        raise _ChromaScanError()
    expected = _settings_expected(data, algorithm)
    try:
        settings = Settings(
            _env_file=None,
            chroma_api_impl=expected["chroma_api_impl"],
            is_persistent=True,
            persist_directory=str(data),
            allow_reset=False,
            anonymized_telemetry=False,
            chroma_product_telemetry_impl=_TELEMETRY_CLASS,
            chroma_telemetry_impl=_TELEMETRY_CLASS,
            chroma_otel_collection_endpoint="",
            chroma_otel_collection_headers={},
            chroma_otel_granularity=None,
            chroma_server_host=None,
            chroma_server_http_port=None,
            chroma_server_headers=None,
            chroma_server_ssl_enabled=False,
            chroma_server_ssl_verify=None,
            chroma_client_auth_provider=None,
            chroma_client_auth_credentials=None,
            migrations="validate",
            migrations_hash_algorithm=algorithm,
        )
    except BaseException:
        raise _ChromaScanError() from None
    _audit_settings(settings, expected)
    _worker_capability()
    try:
        client = chromadb.PersistentClient(
            path=str(data),
            settings=settings,
            tenant=DEFAULT_TENANT,
            database=DEFAULT_DATABASE,
        )
    except BaseException:
        raise _ChromaScanError() from None
    _audit_settings(settings, expected)
    try:
        if client.tenant != DEFAULT_TENANT or client.database != DEFAULT_DATABASE:
            raise _ChromaScanError()
    except BaseException:
        raise _ChromaScanError() from None
    constructed = _store_preflight(
        data, version, key, limits, deadline, time.monotonic, None
    )
    if not before.same_as(constructed):
        raise _ChromaScanError()
    _worker_capability()
    first_manifest, first_counts = _enumeration_pass(
        client, key, limits, deadline, detector
    )
    _worker_capability()
    second_manifest, second_counts = _enumeration_pass(client, key, limits, deadline)
    if first_manifest != second_manifest or first_counts != second_counts:
        raise _ChromaScanError()
    _worker_capability()
    final = _store_preflight(
        data, version, key, limits, deadline, time.monotonic, None
    )
    if not before.same_as(final) or _ATTEMPTED_EGRESS_OR_PROCESS:
        raise _ChromaScanError()
    _check_control(deadline, time.monotonic, None)
    response = {
        "collections": first_counts[0],
        "ok": True,
        "records": first_counts[1],
        "segments": first_counts[2],
        "utf8_bytes": first_counts[3],
    }
    if detector is not None:
        detector_result = detector.result()
        if (
            detector_result["records_completed"] != first_counts[1]
            or detector_result["source_segments_completed"] != first_counts[2]
            or detector_result["source_utf8_bytes_completed"] != first_counts[3]
        ):
            raise _ChromaScanError()
        response["detector"] = detector_result
    return response


def _read_worker_request(handle) -> dict:
    prefix = handle.read(_FRAME_PREFIX_BYTES)
    if len(prefix) != _FRAME_PREFIX_BYTES:
        raise _ChromaScanError()
    length = int.from_bytes(prefix, "big")
    if length > _MAX_IPC_PAYLOAD:
        raise _ChromaScanError()
    payload = handle.read(length + 1)
    if len(payload) != length:
        raise _ChromaScanError()
    if len(payload) != length or handle.read(1):
        raise _ChromaScanError()
    return _decode_frame(prefix + payload, _MAX_IPC_PAYLOAD)


def _worker_main() -> None:
    response = os.fdopen(os.dup(sys.stdout.fileno()), "wb", buffering=0)
    sys.stdout = _ForbiddenText()
    sys.stderr = _ForbiddenText()
    exit_code = 1
    try:
        request = _read_worker_request(sys.stdin.buffer)
        document = _worker_scan(request)
        maximum = (
            _MAX_DETECTOR_RESPONSE_PAYLOAD
            if "detector" in document
            else _MAX_RECEIPT_PAYLOAD
        )
        encoded = _encode_frame(document, maximum)
        exit_code = 0
    except BaseException:
        encoded = _encode_frame({"code": _ERROR_CODE, "ok": False}, _MAX_ERROR_PAYLOAD)
    try:
        response.write(encoded)
        response.flush()
    except BaseException:
        exit_code = 1
    finally:
        try:
            response.close()
        finally:
            os._exit(exit_code)


class _PipeCapture:
    __slots__ = ("handle", "limit", "data", "total", "failed")

    def __init__(self, handle, limit: int) -> None:
        self.handle = handle
        self.limit = limit
        self.data = bytearray()
        self.total = 0
        self.failed = False

    def run(self) -> None:
        try:
            while True:
                chunk = self.handle.read(8_192)
                if not chunk:
                    break
                self.total += len(chunk)
                remaining = self.limit + 1 - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
        except BaseException:
            self.failed = True
        finally:
            try:
                self.handle.close()
            except BaseException:
                self.failed = True


class _PipeWriter:
    __slots__ = ("handle", "data", "failed")

    def __init__(self, handle, data: bytes) -> None:
        self.handle = handle
        self.data = data
        self.failed = False

    def run(self) -> None:
        try:
            self.handle.write(self.data)
            self.handle.flush()
        except BaseException:
            self.failed = True
        finally:
            try:
                self.handle.close()
            except BaseException:
                self.failed = True


def _worker_environment() -> dict:
    result = {"HOME": ".", "TEMP": ".", "TMP": ".", "TMPDIR": "."}
    if os.name == "nt":
        system_root = Path(os.environ.get("SYSTEMROOT", ""))
        if (
            not system_root.is_absolute()
            or not system_root.drive
            or system_root.name.lower() != "windows"
        ):
            raise _ChromaScanError()
        drive = system_root.drive
        program_data = drive + "\\ProgramData"
        result.update(
            {
                "APPDATA": program_data,
                "HOMEDRIVE": drive,
                "HOMEPATH": "\\",
                "LOCALAPPDATA": program_data,
                "PATH": os.pathsep.join(
                    (str(Path(sys.executable).parent), str(system_root / "System32"))
                ),
                "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                "PROGRAMDATA": program_data,
                "SYSTEMDRIVE": drive,
                "SYSTEMROOT": str(system_root),
                "USERPROFILE": ".",
                "WINDIR": str(system_root),
            }
        )
    else:
        result["PATH"] = "/usr/bin:/bin"
    return result


def _wait_process(
    process: subprocess.Popen,
    until: float,
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
    *,
    cancellation_fails: bool,
) -> bool:
    polls = 0
    while polls < _MAX_WAIT_POLLS:
        now = _safe_clock(clock)
        if now > deadline:
            return False
        if cancellation_fails and cancelled is not None:
            try:
                if bool(cancelled()):
                    return False
            except BaseException:
                return False
        try:
            if process.poll() is not None:
                return True
        except BaseException:
            return False
        if now >= until:
            return False
        time.sleep(min(_WAIT_QUANTUM_SECONDS, max(0.0, until - now,)))
        polls += 1
    return False


def _terminate_process(
    process: subprocess.Popen,
    deadline: float,
    clock: Callable[[], float],
) -> bool:
    now = _safe_clock(clock)
    graceful_end = min(deadline, now + _GRACEFUL_SECONDS)
    if _wait_process(process, graceful_end, deadline, clock, None, cancellation_fails=False):
        return True
    if _safe_clock(clock) >= deadline:
        return False
    try:
        process.terminate()
    except BaseException:
        return False
    terminate_end = min(deadline, _safe_clock(clock) + _TERMINATE_SECONDS)
    if _wait_process(process, terminate_end, deadline, clock, None, cancellation_fails=False):
        return True
    if _safe_clock(clock) >= deadline:
        return False
    try:
        process.kill()
    except BaseException:
        return False
    kill_end = min(deadline, _safe_clock(clock) + _KILL_SECONDS)
    return _wait_process(process, kill_end, deadline, clock, None, cancellation_fails=False)


def _run_worker_document(
    request: dict,
    data: Path,
    deadline: float,
    useful_cutoff: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
    response_maximum: int,
) -> dict:
    frame = _encode_frame(request, _MAX_IPC_PAYLOAD)
    creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) if os.name == "nt" else 0
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", "-m", "ragleakguard._chroma_snapshot", "--worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=data,
            env=_worker_environment(),
            bufsize=0,
            close_fds=True,
            creationflags=creationflags,
        )
    except BaseException:
        raise _ChromaScanError() from None
    if process.stdin is None or process.stdout is None or process.stderr is None:
        try:
            process.kill()
        except BaseException:
            pass
        raise _ChromaScanError()
    stdout_capture = _PipeCapture(process.stdout, _FRAME_PREFIX_BYTES + response_maximum)
    stderr_capture = _PipeCapture(process.stderr, _MAX_CHILD_STDERR)
    writer = _PipeWriter(process.stdin, frame)
    threads = [
        threading.Thread(target=stdout_capture.run, daemon=True),
        threading.Thread(target=stderr_capture.run, daemon=True),
        threading.Thread(target=writer.run, daemon=True),
    ]
    for thread in threads:
        thread.start()
    completed_in_time = _wait_process(
        process,
        min(useful_cutoff, deadline),
        deadline,
        clock,
        cancelled,
        cancellation_fails=True,
    )
    if not completed_in_time and not _terminate_process(process, deadline, clock):
        raise _ChromaScanError()
    remaining = deadline - _safe_clock(clock)
    if remaining < _SETTLE_SECONDS:
        raise _ChromaScanError()
    time.sleep(_SETTLE_SECONDS)
    _check_control(deadline, clock, cancelled)
    for thread in threads:
        remaining = deadline - _safe_clock(clock)
        if remaining <= 0:
            raise _ChromaScanError()
        thread.join(min(remaining, 1.0))
        if thread.is_alive():
            raise _ChromaScanError()
    if (
        writer.failed
        or stdout_capture.failed
        or stderr_capture.failed
        or stderr_capture.total != 0
        or stdout_capture.total > _FRAME_PREFIX_BYTES + response_maximum
        or process.returncode != 0
        or not completed_in_time
    ):
        raise _ChromaScanError()
    return _decode_frame(bytes(stdout_capture.data), response_maximum)


def _run_worker(
    request: dict,
    data: Path,
    deadline: float,
    useful_cutoff: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
) -> Tuple[int, int, int, int]:
    response = _run_worker_document(
        request,
        data,
        deadline,
        useful_cutoff,
        clock,
        cancelled,
        _MAX_RECEIPT_PAYLOAD,
    )
    if set(response) != {"collections", "ok", "records", "segments", "utf8_bytes"} or response["ok"] is not True:
        raise _ChromaScanError()
    limits = request["limits"]
    return (
        _exact_int(response["collections"], limits["collections"]),
        _exact_int(response["records"], limits["records"]),
        _exact_int(response["segments"], limits["source_segments"]),
        _exact_int(response["utf8_bytes"], limits["source_utf8_bytes"]),
    )


def _validate_detector_response(response: dict, request: dict):
    if set(response) != {
        "collections",
        "detector",
        "ok",
        "records",
        "segments",
        "utf8_bytes",
    } or response.get("ok") is not True:
        raise _ChromaScanError()
    limits = request.get("limits")
    detector_limits = request.get("detector_limits")
    if type(limits) is not dict or type(detector_limits) is not dict:
        raise _ChromaScanError()
    counts = (
        _exact_int(response.get("collections"), limits["collections"]),
        _exact_int(response.get("records"), limits["records"]),
        _exact_int(response.get("segments"), limits["source_segments"]),
        _exact_int(response.get("utf8_bytes"), limits["source_utf8_bytes"]),
    )
    detector = response.get("detector")
    if type(detector) is not dict or set(detector) != {
        "finding_counts_by_type",
        "records_completed",
        "records_with_findings",
        "source_segments_completed",
        "source_utf8_bytes_completed",
        "total_findings",
    }:
        raise _ChromaScanError()
    detector_records = _exact_int(
        detector.get("records_completed"), detector_limits["records"]
    )
    detector_segments = _exact_int(
        detector.get("source_segments_completed"),
        detector_limits["source_segments"],
    )
    detector_bytes = _exact_int(
        detector.get("source_utf8_bytes_completed"),
        detector_limits["source_utf8_bytes"],
    )
    flagged = _exact_int(
        detector.get("records_with_findings"), detector_limits["records"]
    )
    total = _exact_int(
        detector.get("total_findings"), detector_limits["total_findings"]
    )
    by_type = detector.get("finding_counts_by_type")
    if type(by_type) is not dict or len(by_type) > detector_limits["entity_types"]:
        raise _ChromaScanError()
    try:
        from ragleakguard.detect import DEFAULT_ENTITIES, LOCALE_PACKS

        allowed_types = set(DEFAULT_ENTITIES)
        locale = request.get("locale")
        if locale is not None:
            allowed_types.update(LOCALE_PACKS[locale])
    except BaseException:
        raise _ChromaScanError() from None
    if (
        not allowed_types
        or len(allowed_types) > detector_limits["entity_types"]
        or any(
            type(entity_type) is not str
            or _ENTITY_TYPE_RE.fullmatch(entity_type) is None
            for entity_type in allowed_types
        )
    ):
        raise _ChromaScanError()
    validated: Dict[str, int] = {}
    for entity_type, count in by_type.items():
        if (
            type(entity_type) is not str
            or entity_type not in allowed_types
            or _ENTITY_TYPE_RE.fullmatch(entity_type) is None
            or type(count) is not int
            or count <= 0
            or count > detector_limits["total_findings"]
        ):
            raise _ChromaScanError()
        validated[entity_type] = count
    if (
        counts[1:] != (detector_records, detector_segments, detector_bytes)
        or (counts[0] == 0 and counts[1] != 0)
        or flagged > detector_records
        or flagged > total
        or (total > 0 and flagged == 0)
        or (detector_records == 0 and (detector_segments != 0 or detector_bytes != 0))
        or detector_bytes > detector_segments * detector_limits["segment_bytes"]
        or total > detector_segments * detector_limits["findings_per_segment"]
        or sum(validated.values()) != total
        or (total == 0) != (not validated)
    ):
        raise _ChromaScanError()
    return counts, {
        "finding_counts_by_type": dict(sorted(validated.items())),
        "records_completed": detector_records,
        "records_with_findings": flagged,
        "source_segments_completed": detector_segments,
        "source_utf8_bytes_completed": detector_bytes,
        "total_findings": total,
    }


def _run_detection_worker(
    request: dict,
    data: Path,
    deadline: float,
    useful_cutoff: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
):
    response = _run_worker_document(
        request,
        data,
        deadline,
        useful_cutoff,
        clock,
        cancelled,
        _MAX_DETECTOR_RESPONSE_PAYLOAD,
    )
    return _validate_detector_response(response, request)


def _same_borrow(left: _snapshot._BorrowedSnapshot, right: _snapshot._BorrowedSnapshot) -> bool:
    return (
        left.data == right.data
        and left.workspace_id == right.workspace_id
        and left.snapshot_id == right.snapshot_id
        and left.lease_id == right.lease_id
        and hmac.compare_digest(left.key, right.key)
        and hmac.compare_digest(left.data_evidence, right.data_evidence)
        and _snapshot._same_object(left.workspace_identity, right.workspace_identity)
        and _snapshot._same_object(left.snapshot_identity, right.snapshot_identity)
        and _snapshot._same_object(left.data_identity, right.data_identity)
        and _snapshot._same_object(left.lease_identity, right.lease_identity)
    )


def _classify_effects(
    before: Mapping[Tuple[str, ...], Tuple[int, bytes]],
    after: Mapping[Tuple[str, ...], Tuple[int, bytes]],
    version: str,
    environment: Tuple[str, Tuple[int, int], str],
    vector_ids: frozenset,
) -> None:
    before_paths = set(before)
    after_paths = set(after)
    created = after_paths - before_paths
    removed = before_paths - after_paths
    changed = {path for path in before_paths & after_paths if before[path] != after[path]}
    effects = created | removed | changed
    if len(effects) > _MAX_EFFECT_PATHS or created or removed:
        raise _ChromaScanError()
    allowed_names = _EFFECT_ALLOWLIST[(version,) + environment]
    for path in changed:
        if path == ("chroma.sqlite3",):
            continue
        if (
            len(path) != 2
            or path[0] not in vector_ids
            or path[1] not in allowed_names
            or _UUID_RE.fullmatch(path[0]) is None
        ):
            raise _ChromaScanError()


def _scan_prepared_chroma(
    prepared: _snapshot._PreparedSnapshot,
    *,
    limits: _ChromaScanLimits = _DEFAULT_CHROMA_SCAN_LIMITS,
    cancelled: Optional[Callable[[], bool]] = None,
    clock: Callable[[], float] = time.monotonic,
) -> _ChromaCompletionReceipt:
    """Return private enumeration counters or one static, chain-free failure."""
    failure = None
    try:
        borrow = _snapshot._borrow_prepared_snapshot(prepared)
        if type(limits) is not _ChromaScanLimits:
            raise _ChromaScanError()
        start = _safe_clock(clock)
        deadline = start + _GLOBAL_SECONDS
        useful_cutoff = start + _USEFUL_SECONDS
        if not math.isfinite(deadline) or not math.isfinite(useful_cutoff):
            raise _ChromaScanError()
        _check_control(deadline, clock, cancelled)
        version = _candidate_version()
        environment = _environment_gate(version, borrow.data)
        evidence_key = _token(
            borrow.key,
            b"RLG/WP7C/parent/store-evidence-key/v1",
            (
                (b"workspace", borrow.workspace_id.encode("ascii")),
                (b"snapshot", borrow.snapshot_id.encode("ascii")),
                (b"lease", borrow.lease_id.encode("ascii")),
            ),
        )
        before_inventory = _inventory_files(borrow.data, deadline, clock, cancelled)
        if not hmac.compare_digest(
            _inventory_evidence(borrow.key, before_inventory), borrow.data_evidence
        ):
            raise _ChromaScanError()
        before_store = _store_preflight(
            borrow.data, version, evidence_key, limits, deadline, clock, cancelled
        )
        renewed = _snapshot._borrow_prepared_snapshot(prepared)
        if not _same_borrow(borrow, renewed):
            raise _ChromaScanError()
        remaining_useful = min(_USEFUL_SECONDS, useful_cutoff - _safe_clock(clock))
        if remaining_useful <= 0:
            raise _ChromaScanError()
        request = _borrow_request(
            version,
            before_store.algorithm,
            limits,
            remaining_useful,
        )
        counts = _run_worker(
            request, renewed.data, deadline, useful_cutoff, clock, cancelled
        )
        renewed = _snapshot._borrow_prepared_snapshot(prepared)
        if not _same_borrow(borrow, renewed):
            raise _ChromaScanError()
        after_store = _store_preflight(
            borrow.data, version, evidence_key, limits, deadline, clock, cancelled
        )
        after_inventory = _inventory_files(borrow.data, deadline, clock, cancelled)
        if not before_store.same_as(after_store):
            raise _ChromaScanError()
        _classify_effects(
            before_inventory,
            after_inventory,
            version,
            environment,
            before_store.vector_ids,
        )
        final_borrow = _snapshot._borrow_prepared_snapshot(prepared)
        if not _same_borrow(borrow, final_borrow):
            raise _ChromaScanError()
        final_store = _store_preflight(
            borrow.data, version, evidence_key, limits, deadline, clock, cancelled
        )
        final_inventory = _inventory_files(
            borrow.data, deadline, clock, cancelled
        )
        if not before_store.same_as(final_store):
            raise _ChromaScanError()
        _classify_effects(
            before_inventory,
            final_inventory,
            version,
            environment,
            before_store.vector_ids,
        )
        receipt_borrow = _snapshot._borrow_prepared_snapshot(prepared)
        if not _same_borrow(borrow, receipt_borrow):
            raise _ChromaScanError()
        _check_control(deadline, clock, cancelled)
        return _ChromaCompletionReceipt(*counts)
    except (KeyboardInterrupt, SystemExit):
        raise
    except _ChromaScanError as error:
        failure = error
    except BaseException:
        failure = _ChromaScanError()
    raise _scrub(failure)


def _scan_prepared_chroma_with_detection(
    prepared: _snapshot._PreparedSnapshot,
    *,
    locale: Optional[str],
    limits: _ChromaScanLimits = _PUBLIC_CHROMA_SCAN_LIMITS,
    detector_limits: _DetectorLimits = _DEFAULT_DETECTOR_LIMITS,
    cancelled: Optional[Callable[[], bool]] = None,
    clock: Callable[[], float] = time.monotonic,
):
    """Return aggregate-only WP7D evidence after every WP7C gate succeeds."""
    failure = None
    try:
        borrow = _snapshot._borrow_prepared_snapshot(prepared)
        if (
            type(limits) is not _ChromaScanLimits
            or limits != _PUBLIC_CHROMA_SCAN_LIMITS
            or type(detector_limits) is not _DetectorLimits
            or detector_limits != _DEFAULT_DETECTOR_LIMITS
            or (locale is not None and type(locale) is not str)
        ):
            raise _ChromaScanError()
        start = _safe_clock(clock)
        deadline = start + _GLOBAL_SECONDS
        useful_cutoff = start + _USEFUL_SECONDS
        if not math.isfinite(deadline) or not math.isfinite(useful_cutoff):
            raise _ChromaScanError()
        _check_control(deadline, clock, cancelled)
        version = _candidate_version()
        if version != _PUBLIC_ACTIVATION_VERSION:
            raise _ChromaScanError()
        environment = _environment_gate(version, borrow.data)
        evidence_key = _token(
            borrow.key,
            b"RLG/WP7D/parent/store-evidence-key/v1",
            (
                (b"workspace", borrow.workspace_id.encode("ascii")),
                (b"snapshot", borrow.snapshot_id.encode("ascii")),
                (b"lease", borrow.lease_id.encode("ascii")),
            ),
        )
        before_inventory = _inventory_files(borrow.data, deadline, clock, cancelled)
        if not hmac.compare_digest(
            _inventory_evidence(borrow.key, before_inventory), borrow.data_evidence
        ):
            raise _ChromaScanError()
        before_store = _store_preflight(
            borrow.data, version, evidence_key, limits, deadline, clock, cancelled
        )
        renewed = _snapshot._borrow_prepared_snapshot(prepared)
        if not _same_borrow(borrow, renewed):
            raise _ChromaScanError()
        remaining_useful = min(_USEFUL_SECONDS, useful_cutoff - _safe_clock(clock))
        if remaining_useful <= 0:
            raise _ChromaScanError()
        request = _detection_request(
            version,
            before_store.algorithm,
            limits,
            detector_limits,
            locale,
            remaining_useful,
        )
        counts, detector = _run_detection_worker(
            request, renewed.data, deadline, useful_cutoff, clock, cancelled
        )
        renewed = _snapshot._borrow_prepared_snapshot(prepared)
        if not _same_borrow(borrow, renewed):
            raise _ChromaScanError()
        after_store = _store_preflight(
            borrow.data, version, evidence_key, limits, deadline, clock, cancelled
        )
        after_inventory = _inventory_files(borrow.data, deadline, clock, cancelled)
        if not before_store.same_as(after_store):
            raise _ChromaScanError()
        _classify_effects(
            before_inventory,
            after_inventory,
            version,
            environment,
            before_store.vector_ids,
        )
        final_borrow = _snapshot._borrow_prepared_snapshot(prepared)
        if not _same_borrow(borrow, final_borrow):
            raise _ChromaScanError()
        final_store = _store_preflight(
            borrow.data, version, evidence_key, limits, deadline, clock, cancelled
        )
        final_inventory = _inventory_files(borrow.data, deadline, clock, cancelled)
        if not before_store.same_as(final_store):
            raise _ChromaScanError()
        _classify_effects(
            before_inventory,
            final_inventory,
            version,
            environment,
            before_store.vector_ids,
        )
        receipt_borrow = _snapshot._borrow_prepared_snapshot(prepared)
        if not _same_borrow(borrow, receipt_borrow):
            raise _ChromaScanError()
        _check_control(deadline, clock, cancelled)
        return _ChromaCompletionReceipt(*counts), detector
    except (KeyboardInterrupt, SystemExit):
        raise
    except _ChromaScanError as error:
        failure = error
    except BaseException:
        failure = _ChromaScanError()
    raise _scrub(failure)


if __name__ == "__main__":
    sys.modules["ragleakguard._chroma_snapshot"] = sys.modules[__name__]
    if sys.argv == [sys.argv[0], "--worker"]:
        _worker_main()
    os._exit(2)
