"""WP7C private Chroma compatibility, privacy, and enumeration evidence."""
from __future__ import annotations

import dataclasses
import importlib.metadata
import io
import json
import os
import pickle
import platform
import re
import socket
import sqlite3
import subprocess
import sys
import textwrap
import time
import tracemalloc
import traceback
import uuid
from pathlib import Path
from urllib.parse import unquote

import pytest

from ragleakguard import _chroma_snapshot as chroma_private
from ragleakguard import _snapshot as snapshot


STATIC_FAILURE = "Private Chroma enumeration failed closed."
COMPATIBILITY = os.environ.get("RLG_WP7C_COMPATIBILITY") == "1"


def _flatten(value):
    if isinstance(value, dict):
        return [value, *[item for pair in value.items() for item in _flatten(pair)]]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [value, *[item for child in value for item in _flatten(child)]]
    return [value]


def _assert_private_error(error, canaries=()):
    assert type(error) is chroma_private._ChromaScanError
    assert str(error) == STATIC_FAILURE
    assert repr(error) == "_ChromaScanError('Private Chroma enumeration failed closed.')"
    assert error.__cause__ is None
    assert error.__context__ is None
    serialized = "\n".join(
        [
            str(error),
            repr(error),
            repr(error.args),
            "".join(traceback.format_exception(type(error), error, error.__traceback__)),
        ]
    )
    for canary in canaries:
        assert canary not in serialized


def test_private_module_imports_no_chroma_and_exports_nothing():
    assert chroma_private.__all__ == ()
    assert "chromadb" not in sys.modules
    import ragleakguard

    assert not hasattr(ragleakguard, "_scan_prepared_chroma")
    assert not hasattr(ragleakguard, "_ChromaCompletionReceipt")


def test_hostile_capability_rejected_without_evaluation_or_chroma_import():
    calls = []

    class Hostile:
        def __getattribute__(self, name):
            if name == "__class__":
                return object.__getattribute__(self, name)
            calls.append(("attribute", name))
            raise AssertionError

        def __fspath__(self):
            calls.append(("fspath",))
            raise AssertionError

        def __str__(self):
            calls.append(("str",))
            raise AssertionError

        def __repr__(self):
            calls.append(("repr",))
            raise AssertionError

        def __iter__(self):
            calls.append(("iter",))
            raise AssertionError

        def __hash__(self):
            calls.append(("hash",))
            raise AssertionError

        def __eq__(self, other):
            calls.append(("eq",))
            raise AssertionError

    with pytest.raises(chroma_private._ChromaScanError) as raised:
        chroma_private._scan_prepared_chroma(Hostile())
    assert calls == []
    assert "chromadb" not in sys.modules
    _assert_private_error(chroma_private._scrub(raised.value))


@pytest.mark.parametrize("value", ["store", Path("store"), b"store", object(), None, 0, False])
def test_every_non_capability_shape_fails_before_dependency_import(value):
    with pytest.raises(chroma_private._ChromaScanError) as raised:
        chroma_private._scan_prepared_chroma(value)
    _assert_private_error(raised.value)
    assert "chromadb" not in sys.modules


def test_forged_and_subclassed_capabilities_fail_statically():
    forged = object.__new__(snapshot._PreparedSnapshot)

    class Subclass(snapshot._PreparedSnapshot):
        pass

    for value in (forged, object.__new__(Subclass)):
        with pytest.raises(chroma_private._ChromaScanError) as raised:
            chroma_private._scan_prepared_chroma(value)
        _assert_private_error(raised.value)


def test_limits_accept_only_exact_positive_integers_at_or_below_contract():
    defaults = chroma_private._DEFAULT_CHROMA_SCAN_LIMITS
    assert defaults.manifest_entries * defaults.entry_accounting == 25_856_000
    assert defaults.manifest_memory == 32 * 1024**2
    for field in dataclasses.fields(defaults):
        values = dataclasses.asdict(defaults)
        values[field.name] = True
        with pytest.raises(chroma_private._ChromaScanError):
            chroma_private._ChromaScanLimits(**values)
        values[field.name] = 0
        with pytest.raises(chroma_private._ChromaScanError):
            chroma_private._ChromaScanLimits(**values)


def test_numeric_decision_is_exact_and_fully_bounded():
    assert chroma_private._GLOBAL_SECONDS == 1200.0
    assert chroma_private._USEFUL_SECONDS == 1170.0
    assert chroma_private._GRACEFUL_SECONDS == 10.0
    assert chroma_private._TERMINATE_SECONDS == 5.0
    assert chroma_private._KILL_SECONDS == 5.0
    assert chroma_private._SETTLE_SECONDS == 0.1
    assert chroma_private._MAX_IPC_PAYLOAD == 262_144
    assert chroma_private._MAX_RECEIPT_PAYLOAD == 512
    assert chroma_private._MAX_ERROR_PAYLOAD == 256
    assert chroma_private._MAX_EFFECT_PATHS == 4_096
    assert chroma_private._AUTOMATIC_RETRIES == 0
    assert chroma_private._MAX_CHILD_STDERR == 0
    assert 1170.0 + 10.0 + 5.0 + 5.0 + 0.1 == 1190.1


def test_worker_request_contains_only_nonsensitive_fixed_inputs():
    request = chroma_private._borrow_request(
        "1.5.0", "md5", chroma_private._DEFAULT_CHROMA_SCAN_LIMITS, 60.0
    )
    assert set(request) == {"algorithm", "limits", "useful_seconds", "version"}
    encoded = chroma_private._encode_frame(request, chroma_private._MAX_IPC_PAYLOAD)
    for canary in (
        b"source-path-canary",
        b"work-path-canary",
        b"workspace-id-canary",
        b"snapshot-id-canary",
        b"lease-id-canary",
        b"session-key-canary",
    ):
        assert canary not in encoded


def test_worker_environment_drops_proxy_credentials_and_sensitive_paths(monkeypatch):
    for name in (
        "HOME",
        "USERPROFILE",
        "TEMP",
        "TMP",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "CHROMA_SERVER_HOST",
        "CHROMA_CLIENT_AUTH_CREDENTIALS",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    ):
        monkeypatch.setenv(name, "environment-canary")
    environment = chroma_private._worker_environment()
    serialized = json.dumps(environment, sort_keys=True)
    assert "environment-canary" not in serialized
    assert not any("PROXY" in name or name.startswith("CHROMA_") for name in environment)
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in environment
    assert environment["HOME"] == "."


@pytest.mark.parametrize(
    "raw",
    [
        "1.4.9",
        "1.5.1",
        "1.5.8",
        "1.5.10",
        "1.5.0rc1",
        "1.5.0.dev1",
        "1.5.0+local",
        "01.5.0",
        "malformed",
        "",
    ],
)
def test_every_non_candidate_version_fails_before_chroma_import(monkeypatch, raw):
    monkeypatch.setattr(chroma_private.importlib.metadata, "version", lambda name: raw)
    with pytest.raises(chroma_private._ChromaScanError) as raised:
        chroma_private._candidate_version()
    _assert_private_error(raised.value, (raw,) if raw else ())
    assert "chromadb" not in sys.modules


@pytest.mark.parametrize("raw", ["1.5.0", "1.5.9"])
def test_exact_candidate_version_metadata_is_accepted_without_import(monkeypatch, raw):
    monkeypatch.setattr(chroma_private.importlib.metadata, "version", lambda name: raw)
    assert chroma_private._candidate_version() == raw
    assert "chromadb" not in sys.modules


def test_missing_dependency_fails_before_work_payload_inspection(monkeypatch, tmp_path):
    source = tmp_path / "source"
    work = tmp_path / "work"
    source.mkdir()
    work.mkdir()
    (source / "not-a-chroma-store-canary").write_bytes(b"payload-canary")
    lease = snapshot._prepare_snapshot(source, work)

    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(chroma_private.importlib.metadata, "version", missing)
    try:
        with pytest.raises(chroma_private._ChromaScanError) as raised:
            chroma_private._scan_prepared_chroma(lease)
        _assert_private_error(
            raised.value, ("not-a-chroma-store-canary", "payload-canary")
        )
        assert "chromadb" not in sys.modules
    finally:
        lease.cleanup()
    assert list(work.iterdir()) == []


def test_frames_reject_duplicate_partial_extra_and_oversized_payloads():
    frame = chroma_private._encode_frame({"ok": True}, 32)
    assert chroma_private._decode_frame(frame, 32) == {"ok": True}
    malformed = len(b'{"a":1,"a":2}').to_bytes(4, "big") + b'{"a":1,"a":2}'
    for value in (
        b"",
        frame[:3],
        frame[:-1],
        frame + b"x",
        (33).to_bytes(4, "big") + b"x" * 33,
        malformed,
    ):
        with pytest.raises(chroma_private._ChromaScanError):
            chroma_private._decode_frame(value, 32)


def test_receipt_is_opaque_immutable_redacted_and_not_serializable():
    receipt = chroma_private._ChromaCompletionReceipt(1, 2, 3, 4)
    assert (
        receipt.collections_enumerated,
        receipt.records_enumerated,
        receipt.source_segments_enumerated,
        receipt.source_utf8_bytes_enumerated,
    ) == (1, 2, 3, 4)
    assert repr(receipt) == "<RAGLeakGuard private Chroma completion receipt: redacted>"
    with pytest.raises(AttributeError):
        receipt._records_enumerated = 9
    with pytest.raises(TypeError):
        json.dumps(receipt)
    with pytest.raises(TypeError):
        pickle.dumps(receipt)
    with pytest.raises(TypeError):
        dataclasses.asdict(receipt)
    surface = " ".join((type(receipt).__name__, repr(receipt), str(receipt))).lower()
    assert "detector" not in surface
    assert "finding" not in surface
    assert "scan completed" not in surface


@pytest.mark.parametrize(
    "value,expected",
    [(0.0, "0.0"), (-0.0, "-0.0"), (1e20, "1e+20"), (1e-7, "1e-7")],
)
def test_float_canonicalization_is_deterministic(value, expected):
    assert chroma_private._canonical_float(value) == expected


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), True, 1])
def test_float_canonicalization_rejects_ambiguous_values(value):
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._canonical_float(value)


def test_canonical_segments_order_types_arrays_none_and_signed_zero():
    limits = chroma_private._DEFAULT_CHROMA_SCAN_LIMITS
    key = b"k" * 32
    first = chroma_private._canonical_content(
        key,
        "",
        {"z": [1, 2], "a": True, "n": None, "zero": -0.0},
        limits,
    )
    reordered = chroma_private._canonical_content(
        key,
        "",
        {"zero": -0.0, "n": None, "a": True, "z": [1, 2]},
        limits,
    )
    positive_zero = chroma_private._canonical_content(
        key,
        "",
        {"z": [1, 2], "a": True, "n": None, "zero": 0.0},
        limits,
    )
    assert first == reordered
    assert first[:2] != positive_zero[:2]
    assert first[2] == 9
    assert first[3] == 17


@pytest.mark.parametrize(
    "metadata",
    [
        {1: "value"},
        {"x": {}},
        {"x": []},
        {"x": [1, True]},
        {"x": [[1]]},
        {"x": float("nan")},
        {"x": object()},
        {"\ud800": "value"},
    ],
)
def test_unsupported_or_ambiguous_metadata_fails(metadata):
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._canonical_content(
            b"k" * 32, None, metadata, chroma_private._DEFAULT_CHROMA_SCAN_LIMITS
        )


def test_canonicalization_enforces_boundaries_before_retention():
    base = chroma_private._DEFAULT_CHROMA_SCAN_LIMITS
    key = b"k" * 32
    exact = dataclasses.replace(
        base,
        document_bytes=2,
        metadata_key_bytes=2,
        scalar_bytes=2,
        array_elements=2,
        metadata_leaves=2,
        metadata_bytes=4,
        source_segments=5,
        source_utf8_bytes=6,
    )
    assert chroma_private._canonical_content(
        key, "dd", {"k": ["v", "w"]}, exact
    )[2:] == (4, 5)
    adversaries = (
        ("ddd", None),
        (None, {"key": None}),
        (None, {"k": "val"}),
        (None, {"k": [1, 2, 3]}),
        (None, {"aa": None, "bb": None, "cc": None}),
    )
    for document, metadata in adversaries:
        with pytest.raises(chroma_private._ChromaScanError):
            chroma_private._canonical_content(key, document, metadata, exact)


@pytest.mark.parametrize(
    "metadata",
    [
        {"value": "text"},
        {"value": True},
        {"value": 12345678901234567890},
        {"value": -1.25e-7},
        {"value": ["a", "b"]},
        {"value": [True, False]},
        {"value": [1, -2]},
        {"value": [0.0, -0.0]},
    ],
)
def test_every_accepted_scalar_and_homogeneous_array_form_is_canonical(metadata):
    token, witness, segments, source_bytes = chroma_private._canonical_content(
        b"k" * 32,
        None,
        metadata,
        chroma_private._DEFAULT_CHROMA_SCAN_LIMITS,
    )
    assert len(token) == len(witness) == 32
    assert segments >= 2
    assert source_bytes > 0


def test_absent_empty_none_and_signed_content_states_remain_distinct():
    limits = chroma_private._DEFAULT_CHROMA_SCAN_LIMITS
    states = (
        (None, None),
        ("", None),
        (None, {}),
        ("", {}),
        (None, {"value": None}),
        (None, {"value": ""}),
        (None, {"value": 0.0}),
        (None, {"value": -0.0}),
    )
    tokens = {
        chroma_private._canonical_content(b"k" * 32, document, metadata, limits)[:2]
        for document, metadata in states
    }
    assert len(tokens) == len(states)


def test_utf8_and_global_source_bounds_pass_exactly_and_fail_one_over():
    base = chroma_private._DEFAULT_CHROMA_SCAN_LIMITS
    exact = dataclasses.replace(
        base,
        document_bytes=4,
        metadata_key_bytes=2,
        scalar_bytes=2,
        source_segments=3,
        source_utf8_bytes=8,
        metadata_leaves=1,
        metadata_bytes=4,
    )
    assert chroma_private._canonical_content(
        b"k" * 32, "éé", {"é": "é"}, exact
    )[2:] == (3, 8)
    for document, metadata in (("ééé", None), ("éé", {"é": "éé"})):
        with pytest.raises(chroma_private._ChromaScanError):
            chroma_private._canonical_content(b"k" * 32, document, metadata, exact)


def test_canonicalization_checks_cancellation_between_segments():
    checks = 0

    def cancelled():
        nonlocal checks
        checks += 1
        return checks >= 4

    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._canonical_content(
            b"k" * 32,
            "document",
            {"a": ["one", "two", "three"]},
            chroma_private._DEFAULT_CHROMA_SCAN_LIMITS,
            time.monotonic() + 10,
            time.monotonic,
            cancelled,
        )
    assert checks == 4


class _FakeCollection:
    def __init__(self, name, identifier, records, *, count_values=None, page_hook=None):
        self.name = name
        self.id = identifier
        self._records = list(records)
        self._count_values = list(count_values or [len(self._records), len(self._records)])
        self._page_hook = page_hook

    def count(self):
        return self._count_values.pop(0) if len(self._count_values) > 1 else self._count_values[0]

    def get(self, *, limit, offset, include):
        rows = self._records[offset : offset + limit]
        result = {
            "ids": [row[0] for row in rows],
            "embeddings": None,
            "documents": [row[1] for row in rows],
            "uris": None,
            "included": ["documents", "metadatas"],
            "data": None,
            "metadatas": [row[2] for row in rows],
        }
        return self._page_hook(result, limit, offset) if self._page_hook else result


class _FakeCollectionReference:
    def __init__(self, collection):
        self.name = collection.name
        self.id = collection.id


class _FakeClient:
    def __init__(self, collections, *, count_values=None, list_hook=None, open_hook=None):
        self._collections = list(collections)
        self._count_values = list(count_values or [len(self._collections), len(self._collections)])
        self._list_hook = list_hook
        self._open_hook = open_hook

    def count_collections(self):
        return self._count_values.pop(0) if len(self._count_values) > 1 else self._count_values[0]

    def list_collections(self, *, limit, offset):
        page = [_FakeCollectionReference(value) for value in self._collections[offset : offset + limit]]
        return self._list_hook(page, limit, offset) if self._list_hook else page

    def get_collection(self, *, name, embedding_function):
        assert embedding_function is None
        collection = next(value for value in self._collections if value.name == name)
        return self._open_hook(collection) if self._open_hook else collection


def _fake_collections():
    return [
        _FakeCollection(
            "collection-a",
            uuid.UUID("00000000-0000-0000-0000-000000000001"),
            [("record-b", "doc", {"b": 2}), ("record-a", None, {"a": True})],
        ),
        _FakeCollection(
            "collection-b",
            uuid.UUID("00000000-0000-0000-0000-000000000002"),
            [],
        ),
    ]


def test_enumeration_is_complete_bounded_and_order_independent():
    limits = chroma_private._DEFAULT_CHROMA_SCAN_LIMITS
    key = b"k" * 32
    first_manifest, first_counts = chroma_private._enumeration_pass(
        _FakeClient(_fake_collections()), key, limits, time.monotonic() + 10
    )
    reordered_manifest, reordered_counts = chroma_private._enumeration_pass(
        _FakeClient(list(reversed(_fake_collections()))), key, limits, time.monotonic() + 10
    )
    assert first_manifest == reordered_manifest
    assert first_counts == reordered_counts == (2, 2, 5, 10)


@pytest.mark.parametrize(
    "list_hook",
    [
        lambda page, limit, offset: tuple(page),
        lambda page, limit, offset: [] if offset == 0 else page,
        lambda page, limit, offset: page + page[:1] if offset == 0 else page,
        lambda page, limit, offset: [object()] if offset == 0 else page,
        lambda page, limit, offset: [_FakeCollectionReference(_fake_collections()[0])]
        if offset > 0
        else page,
    ],
)
def test_collection_page_shape_short_long_type_and_trailing_adversaries_fail(list_hook):
    with pytest.raises(chroma_private._ChromaScanError) as raised:
        chroma_private._enumeration_pass(
            _FakeClient([_fake_collections()[0]], list_hook=list_hook),
            b"k" * 32,
            chroma_private._DEFAULT_CHROMA_SCAN_LIMITS,
            time.monotonic() + 10,
        )
    _assert_private_error(chroma_private._scrub(raised.value))


def test_collection_and_record_count_bounds_pass_exactly_and_fail_one_over():
    identifier_a = uuid.UUID("00000000-0000-0000-0000-000000000001")
    identifier_b = uuid.UUID("00000000-0000-0000-0000-000000000002")
    limits = dataclasses.replace(
        chroma_private._DEFAULT_CHROMA_SCAN_LIMITS,
        collection_page=1,
        record_page=1,
        collections=2,
        records=2,
    )
    exact = _FakeClient(
        [
            _FakeCollection("a", identifier_a, [("one", "a", None)]),
            _FakeCollection("b", identifier_b, [("two", "b", None)]),
        ]
    )
    assert chroma_private._enumeration_pass(
        exact, b"k" * 32, limits, time.monotonic() + 10
    )[1][:2] == (2, 2)
    too_many_collections = _FakeClient(
        [
            _FakeCollection("a", identifier_a, []),
            _FakeCollection("b", identifier_b, []),
            _FakeCollection("c", uuid.UUID("00000000-0000-0000-0000-000000000003"), []),
        ]
    )
    too_many_records = _FakeClient(
        [
            _FakeCollection(
                "a",
                identifier_a,
                [("one", None, None), ("two", None, None), ("three", None, None)],
            )
        ]
    )
    for client in (too_many_collections, too_many_records):
        with pytest.raises(chroma_private._ChromaScanError):
            chroma_private._enumeration_pass(
                client, b"k" * 32, limits, time.monotonic() + 10
            )


def test_same_count_id_content_metadata_and_collection_move_mutations_change_manifest():
    identifier_a = uuid.UUID("00000000-0000-0000-0000-000000000001")
    identifier_b = uuid.UUID("00000000-0000-0000-0000-000000000002")
    key = b"k" * 32
    limits = chroma_private._DEFAULT_CHROMA_SCAN_LIMITS
    baseline = _FakeClient(
        [
            _FakeCollection("a", identifier_a, [("id", "doc", {"key": "value"})]),
            _FakeCollection("b", identifier_b, []),
        ]
    )
    baseline_manifest, baseline_counts = chroma_private._enumeration_pass(
        baseline, key, limits, time.monotonic() + 10
    )
    mutations = (
        _FakeClient(
            [
                _FakeCollection("a", identifier_a, [("other", "doc", {"key": "value"})]),
                _FakeCollection("b", identifier_b, []),
            ]
        ),
        _FakeClient(
            [
                _FakeCollection("a", identifier_a, [("id", "new", {"key": "value"})]),
                _FakeCollection("b", identifier_b, []),
            ]
        ),
        _FakeClient(
            [
                _FakeCollection("a", identifier_a, [("id", "doc", {"key": "other"})]),
                _FakeCollection("b", identifier_b, []),
            ]
        ),
        _FakeClient(
            [
                _FakeCollection("a", identifier_a, []),
                _FakeCollection("b", identifier_b, [("id", "doc", {"key": "value"})]),
            ]
        ),
    )
    for client in mutations:
        manifest, counts = chroma_private._enumeration_pass(
            client, key, limits, time.monotonic() + 10
        )
        assert counts == baseline_counts
        assert manifest != baseline_manifest


@pytest.mark.parametrize(
    "page_hook",
    [
        lambda result, limit, offset: {key: value for key, value in result.items() if key != "documents"},
        lambda result, limit, offset: {**result, "extra": "nested-canary"},
        lambda result, limit, offset: {**result, "embeddings": [[1.0]]},
        lambda result, limit, offset: {**result, "documents": []},
        lambda result, limit, offset: {**result, "ids": "record-canary"},
        lambda result, limit, offset: {**result, "included": ["documents"]},
    ],
)
def test_record_page_shape_adversaries_fail_statically(page_hook):
    collection = _FakeCollection(
        "collection-a",
        uuid.UUID("00000000-0000-0000-0000-000000000001"),
        [("record-a", "doc-canary", {"metadata-canary": "value-canary"})],
        page_hook=page_hook,
    )
    with pytest.raises(chroma_private._ChromaScanError) as raised:
        chroma_private._enumeration_pass(
            _FakeClient([collection]),
            b"k" * 32,
            chroma_private._DEFAULT_CHROMA_SCAN_LIMITS,
            time.monotonic() + 10,
        )
    _assert_private_error(
        raised.value,
        ("record-canary", "doc-canary", "metadata-canary", "value-canary", "nested-canary"),
    )


def test_duplicate_ids_count_mutation_and_opened_collection_substitution_fail():
    identifier = uuid.UUID("00000000-0000-0000-0000-000000000001")
    duplicate = _FakeCollection(
        "collection-a",
        identifier,
        [("same", "one", None), ("same", "two", None)],
    )
    changing = _FakeCollection(
        "collection-a", identifier, [("record", "doc", None)], count_values=[1, 2]
    )
    substituted = _FakeCollection("collection-a", uuid.uuid4(), [])
    cases = (
        _FakeClient([duplicate]),
        _FakeClient([changing]),
        _FakeClient(
            [_FakeCollection("collection-a", identifier, [])],
            open_hook=lambda collection: substituted,
        ),
        _FakeClient(
            [_FakeCollection("collection-a", identifier, [])], count_values=[1, 2]
        ),
    )
    for client in cases:
        with pytest.raises(chroma_private._ChromaScanError):
            chroma_private._enumeration_pass(
                client,
                b"k" * 32,
                chroma_private._DEFAULT_CHROMA_SCAN_LIMITS,
                time.monotonic() + 10,
            )


def test_forced_token_collision_and_manifest_one_over_fail(monkeypatch):
    collection = _FakeCollection(
        "collection-a",
        uuid.UUID("00000000-0000-0000-0000-000000000001"),
        [("a", "one", None), ("b", "two", None)],
    )
    monkeypatch.setattr(chroma_private, "_token", lambda *args, **kwargs: b"x" * 32)
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._enumeration_pass(
            _FakeClient([collection]),
            b"k" * 32,
            chroma_private._DEFAULT_CHROMA_SCAN_LIMITS,
            time.monotonic() + 10,
        )
    limits = dataclasses.replace(
        chroma_private._DEFAULT_CHROMA_SCAN_LIMITS, manifest_entries=1
    )
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._enumeration_pass(
            _FakeClient([collection]), b"k" * 32, limits, time.monotonic() + 10
        )


def test_manifest_memory_tracemalloc_characterization_stays_below_hard_cap():
    records = [(f"id-{number:04d}", "d", None) for number in range(512)]
    collection = _FakeCollection(
        "collection-a",
        uuid.UUID("00000000-0000-0000-0000-000000000001"),
        records,
    )
    tracemalloc.start()
    try:
        chroma_private._enumeration_pass(
            _FakeClient([collection]),
            b"k" * 32,
            chroma_private._DEFAULT_CHROMA_SCAN_LIMITS,
            time.monotonic() + 10,
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < chroma_private._DEFAULT_CHROMA_SCAN_LIMITS.manifest_memory


def test_effect_inventory_fails_before_scheduling_path_4097(monkeypatch):
    identity = snapshot._Identity(
        device=1,
        inode=1,
        mode=0,
        links=1,
        size=0,
        modified_ns=0,
        changed_ns=0,
        birth_ns=None,
        uid=None,
        gid=None,
        file_attributes=0,
    )

    class Child:
        def __init__(self, name):
            self.name = name

    class Scan:
        def __enter__(self):
            return iter(
                Child(f"entry-{number}")
                for number in range(chroma_private._MAX_EFFECT_PATHS + 1)
            )

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    monkeypatch.setattr(
        snapshot, "_validate_directory", lambda *args, **kwargs: identity
    )
    monkeypatch.setattr(snapshot, "_windows_has_named_streams", lambda path: False)
    monkeypatch.setattr(snapshot, "_assert_restrictive", lambda *args, **kwargs: None)
    monkeypatch.setattr(chroma_private.os, "scandir", lambda path: Scan())
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._inventory_files(
            Path("synthetic-root"), time.monotonic() + 10, time.monotonic, None
        )


def test_created_removed_and_unclassified_effects_fail():
    stable = {("chroma.sqlite3",): (1, b"a" * 32)}
    environment = ("Windows", (3, 12), "ntfs")
    cases = (
        (stable, {**stable, ("created-canary",): (1, b"b" * 32)}),
        (stable, {}),
        (
            {**stable, ("bad",): (1, b"a" * 32)},
            {**stable, ("bad",): (1, b"b" * 32)},
        ),
    )
    for before, after in cases:
        with pytest.raises(chroma_private._ChromaScanError):
            chroma_private._classify_effects(
                before, after, "1.5.0", environment, frozenset()
            )
    oversized_before = {
        (f"path-{number}",): (1, b"a" * 32)
        for number in range(chroma_private._MAX_EFFECT_PATHS + 1)
    }
    oversized_after = {
        path: (1, b"b" * 32) for path in oversized_before
    }
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._classify_effects(
            oversized_before,
            oversized_after,
            "1.5.0",
            environment,
            frozenset(),
        )


def test_exact_migration_manifests_are_complete_ordered_and_dual_hash():
    assert set(chroma_private._MIGRATION_MANIFESTS) == {"1.5.0", "1.5.9"}
    assert chroma_private._MIGRATION_MANIFESTS["1.5.0"] == chroma_private._MIGRATION_MANIFESTS["1.5.9"]
    manifest = chroma_private._MIGRATION_MANIFESTS["1.5.0"]
    assert len(manifest) == 18
    assert [row[:3] for row in manifest] == sorted((row[:3] for row in manifest))
    assert {row[0] for row in manifest} == {"embeddings_queue", "metadb", "sysdb"}
    assert all(chroma_private._MD5_RE.fullmatch(row[3]) for row in manifest)
    assert all(chroma_private._SHA256_RE.fullmatch(row[4]) for row in manifest)
    assert any(row[:3] == ("sysdb", 10, "00010-collection-schema.sqlite.sql") for row in manifest)
    assert any(row[:3] == ("metadb", 6, "00006-metadata-array-support.sqlite.sql") for row in manifest)


def test_unlisted_python_platform_filesystem_tuple_fails_closed(monkeypatch, tmp_path):
    expected = {
        (candidate, system, python, filesystem)
        for candidate in ("1.5.0", "1.5.9")
        for system, python, filesystem in (
            ("Linux", (3, 10), "ext4"),
            ("Linux", (3, 11), "ext4"),
            ("Linux", (3, 12), "ext4"),
            ("Darwin", (3, 12), "apfs"),
            ("Windows", (3, 12), "ntfs"),
        )
    }
    assert set(chroma_private._EFFECT_ALLOWLIST) == expected
    monkeypatch.setattr(chroma_private.platform, "system", lambda: "Linux")
    monkeypatch.setattr(chroma_private.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(chroma_private, "_filesystem_type", lambda path: "ext4")
    fake_version = type("Version", (), {"major": 3, "minor": 9})()
    monkeypatch.setattr(chroma_private.sys, "version_info", fake_version)
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._environment_gate("1.5.0", tmp_path)


def test_static_failure_drops_nested_dependency_canaries():
    canaries = (
        "document-canary",
        "metadata-canary",
        "collection-canary",
        "record-canary",
        "path-canary",
        "sql-canary",
        "settings-canary",
        "worker-crash-canary",
    )
    try:
        try:
            raise RuntimeError(" ".join(canaries))
        except RuntimeError as nested:
            raise chroma_private._ChromaScanError() from nested
    except chroma_private._ChromaScanError as error:
        scrubbed = chroma_private._scrub(error)
    _assert_private_error(scrubbed, canaries)


def test_bounded_termination_ladder_reaches_kill_and_proves_exit(monkeypatch):
    events = []

    class Process:
        killed = False

        def poll(self):
            return 9 if self.killed else None

        def terminate(self):
            events.append("terminate")

        def kill(self):
            events.append("kill")
            self.killed = True

    ticks = iter(float(value) for value in range(100))
    monkeypatch.setattr(chroma_private.time, "sleep", lambda seconds: None)
    assert chroma_private._terminate_process(Process(), 90.0, lambda: next(ticks))
    assert events == ["terminate", "kill"]


def test_wait_fails_immediately_on_cancellation_without_retry(monkeypatch):
    class Process:
        def poll(self):
            raise AssertionError("poll must not run after cancellation")

    monkeypatch.setattr(chroma_private.time, "sleep", lambda seconds: None)
    assert not chroma_private._wait_process(
        Process(),
        10.0,
        20.0,
        lambda: 1.0,
        lambda: True,
        cancellation_fails=True,
    )
    assert chroma_private._AUTOMATIC_RETRIES == 0


@pytest.mark.parametrize("mode", ["exception", "short"])
def test_worker_randomness_failure_is_static_before_capability_or_import(monkeypatch, mode):
    def failed_randomness(size):
        if mode == "exception":
            raise OSError("randomness-canary")
        return b"x" * (size - 1)

    monkeypatch.setattr(chroma_private.secrets, "token_bytes", failed_randomness)
    request = chroma_private._borrow_request(
        "1.5.0", "md5", chroma_private._DEFAULT_CHROMA_SCAN_LIMITS, 60.0
    )
    with pytest.raises(chroma_private._ChromaScanError) as raised:
        chroma_private._worker_scan(request)
    _assert_private_error(
        chroma_private._scrub(raised.value), ("randomness-canary",)
    )
    assert "chromadb" not in sys.modules


class _FakeWorkerProcess:
    def __init__(self, stdout, stderr=b"", returncode=0, *, late=False):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = returncode
        self._late = late
        self._polls = 0

    def poll(self):
        self._polls += 1
        if self._late and self._polls == 1:
            return None
        return self.returncode

    def terminate(self):
        return None

    def kill(self):
        self.returncode = 9


@pytest.mark.parametrize("mode", ["partial", "extra", "oversized", "stderr", "crash"])
def test_worker_partial_extra_oversized_output_stderr_and_crash_fail(monkeypatch, mode):
    valid = chroma_private._encode_frame(
        {"collections": 0, "ok": True, "records": 0, "segments": 0, "utf8_bytes": 0},
        chroma_private._MAX_RECEIPT_PAYLOAD,
    )
    stdout = valid
    stderr = b""
    returncode = 0
    if mode == "partial":
        stdout = valid[:-1]
    elif mode == "extra":
        stdout = valid + b"x"
    elif mode == "oversized":
        stdout = b"x" * (
            chroma_private._FRAME_PREFIX_BYTES
            + chroma_private._MAX_RECEIPT_PAYLOAD
            + 1
        )
    elif mode == "stderr":
        stderr = b"stderr-canary"
    else:
        stdout = b""
        returncode = 9
    process = _FakeWorkerProcess(stdout, stderr, returncode)
    monkeypatch.setattr(chroma_private.subprocess, "Popen", lambda *args, **kwargs: process)
    with pytest.raises(chroma_private._ChromaScanError) as raised:
        chroma_private._run_worker(
            chroma_private._borrow_request(
                "1.5.0", "md5", chroma_private._DEFAULT_CHROMA_SCAN_LIMITS, 60.0
            ),
            Path("unused"),
            100.0,
            90.0,
            lambda: 1.0,
            None,
        )
    _assert_private_error(raised.value, ("stderr-canary",))


def test_valid_late_worker_response_is_rejected_after_confirmed_exit(monkeypatch):
    valid = chroma_private._encode_frame(
        {"collections": 0, "ok": True, "records": 0, "segments": 0, "utf8_bytes": 0},
        chroma_private._MAX_RECEIPT_PAYLOAD,
    )
    process = _FakeWorkerProcess(valid, late=True)
    monkeypatch.setattr(chroma_private.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(chroma_private.time, "sleep", lambda seconds: None)
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._run_worker(
            chroma_private._borrow_request(
                "1.5.0", "md5", chroma_private._DEFAULT_CHROMA_SCAN_LIMITS, 60.0
            ),
            Path("unused"),
            100.0,
            0.0,
            lambda: 1.0,
            None,
        )


def test_private_workflow_has_exact_cells_native_gates_and_no_artifact_upload():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "wp7c-private-chroma.yml").read_text(
        encoding="utf-8"
    )
    assert workflow.count("chroma: \"1.5.0\"") == 5
    assert workflow.count("chroma: \"1.5.9\"") == 5
    assert workflow.count("- os: ubuntu-latest") == 6
    assert workflow.count("- os: macos-15") == 2
    assert workflow.count("- os: windows-latest") == 2
    for exact in (
        "fail-fast: false",
        "chromadb==${{ matrix.chroma }}",
        "pip check",
        "pip list --format=freeze --disable-pip-version-check",
        'df "${RUNNER_TEMP}"',
        "findmnt -n -o FSTYPE",
        "diskutil info",
        "Get-Volume",
        "RLG_REQUIRE_NATIVE_SNAPSHOT_FS",
        "RLG_WP7C_OS_EGRESS_DENIED",
        "RLG_WP7C_TEST_UID",
        "useradd --system --user-group --no-create-home",
        "git archive --format=tar HEAD",
        "test -r /mnt/rlg-wp7c-ext4/repository/pyproject.toml",
        "cd /mnt/rlg-wp7c-ext4/repository",
        "sudo --preserve-env=ANONYMIZED_TELEMETRY",
        "iptables",
        "sandbox-exec",
        "New-NetFirewallRule",
        "if: always()",
    ):
        assert exact in workflow
    assert "upload-artifact" not in workflow
    assert ".[chroma" not in workflow.lower()
    assert "pip install -e" not in workflow
    assert "pip freeze" not in workflow
    assert '--uid-owner "$(id -u)"' not in workflow


def test_all_repository_relative_markdown_links_resolve():
    root = Path(__file__).resolve().parents[1]
    inline = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
    reference = re.compile(r"^\[[^\]]+\]:\s+(\S+)", re.MULTILINE)
    missing = []
    for markdown in sorted(root.rglob("*.md")):
        text = markdown.read_text(encoding="utf-8")
        text = re.sub(r"```.*?```|~~~.*?~~~", "", text, flags=re.DOTALL)
        for raw in (*inline.findall(text), *reference.findall(text)):
            raw = raw.strip()
            if raw.startswith("<") and ">" in raw:
                target = raw[1 : raw.index(">")]
            else:
                target = raw.split(maxsplit=1)[0]
            if (
                not target
                or target.startswith("#")
                or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target)
            ):
                continue
            relative = unquote(target.split("#", 1)[0])
            if relative and not (markdown.parent / relative).resolve().exists():
                missing.append((str(markdown.relative_to(root)), target))
    assert missing == []


_FIXTURE_SCRIPT = textwrap.dedent(
    """
    import sys
    import chromadb
    from chromadb.config import DEFAULT_DATABASE, DEFAULT_TENANT, Settings

    path, shape, algorithm = sys.argv[1:]
    settings = Settings(
        _env_file=None,
        anonymized_telemetry=False,
        is_persistent=True,
        persist_directory=path,
        migrations="apply",
        migrations_hash_algorithm=algorithm,
        allow_reset=False,
        chroma_server_host=None,
        chroma_server_headers=None,
        chroma_server_http_port=None,
        chroma_server_ssl_enabled=False,
        chroma_client_auth_provider=None,
        chroma_client_auth_credentials=None,
        chroma_otel_collection_endpoint="",
        chroma_otel_collection_headers={},
        chroma_otel_granularity=None,
    )
    client = chromadb.PersistentClient(
        path=path, settings=settings, tenant=DEFAULT_TENANT, database=DEFAULT_DATABASE
    )
    if shape == "populated":
        collection = client.create_collection("synthetic-private")
        collection.add(
            ids=["id-b", "id-a"],
            embeddings=[[0.1, 0.2], [0.3, 0.4]],
            documents=["doc-b", ""],
            metadatas=[{"b": 2, "a": True}, {"array": [1, 2], "text": "value"}],
        )
    elif shape == "empty":
        client.create_collection("synthetic-empty")
    elif shape == "zero":
        client.count_collections()
    else:
        raise SystemExit(4)
    """
)


def _tree_hashes(root: Path):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            import hashlib

            result[path.relative_to(root).parts] = hashlib.sha256(path.read_bytes()).digest()
    return result


def _make_fixture(root: Path, shape: str, algorithm: str):
    source = root / "source"
    work = root / "work"
    source.mkdir()
    work.mkdir()
    result = subprocess.run(
        [sys.executable, "-c", _FIXTURE_SCRIPT, str(source), shape, algorithm],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == b""
    assert result.stderr == b""
    return source, work


compatibility = pytest.mark.skipif(
    not COMPATIBILITY, reason="runs only in the explicit exact-candidate WP7C matrix"
)


@compatibility
def test_matrix_environment_is_exact_and_native(tmp_path):
    assert sys.version_info[:2] in {(3, 10), (3, 11), (3, 12)}
    version = importlib.metadata.version("chromadb")
    assert version in {"1.5.0", "1.5.9"}
    system = platform.system()
    machine = platform.machine().lower()
    expected = {"Linux": "ext4", "Darwin": "apfs", "Windows": "ntfs"}[system]
    assert chroma_private._filesystem_type(tmp_path) == expected
    assert machine in {
        "Linux": {"x86_64", "amd64"},
        "Darwin": {"arm64", "aarch64", "x86_64"},
        "Windows": {"amd64", "x86_64"},
    }[system]
    if system == "Darwin":
        assert platform.mac_ver()[0].split(".")[0] == "15"
        assert sys.version_info[:2] == (3, 12)
    if system == "Windows":
        assert sys.version_info[:2] == (3, 12)


@compatibility
@pytest.mark.parametrize(
    "shape,algorithm,expected",
    [
        ("populated", "md5", (1, 2, 11, 28)),
        ("zero", "sha256", (0, 0, 0, 0)),
        ("empty", "md5", (1, 0, 0, 0)),
    ],
)
def test_exact_candidate_enumerates_two_passes_and_cleans_after_exit(
    tmp_path, shape, algorithm, expected
):
    source, work = _make_fixture(tmp_path, shape, algorithm)
    source_before = _tree_hashes(source)
    lease = snapshot._prepare_snapshot(source, work)
    workspace = lease._workspace
    before_inventory = chroma_private._inventory_files(
        lease.data_path, time.monotonic() + 30, time.monotonic, None
    )
    try:
        receipt = chroma_private._scan_prepared_chroma(lease)
        assert (
            receipt.collections_enumerated,
            receipt.records_enumerated,
            receipt.source_segments_enumerated,
            receipt.source_utf8_bytes_enumerated,
        ) == expected
        assert source_before == _tree_hashes(source)
        assert workspace.exists()
        after_inventory = chroma_private._inventory_files(
            lease.data_path, time.monotonic() + 30, time.monotonic, None
        )
        created = set(after_inventory) - set(before_inventory)
        removed = set(before_inventory) - set(after_inventory)
        changed = {
            path
            for path in set(before_inventory) & set(after_inventory)
            if before_inventory[path] != after_inventory[path]
        }
        assert removed == set()
        assert created == set()
        assert ("chroma.sqlite3",) in changed
        assert len(changed) <= chroma_private._MAX_EFFECT_PATHS
        allowed_names = chroma_private._EFFECT_ALLOWLIST[
            (
                importlib.metadata.version("chromadb"),
                platform.system(),
                sys.version_info[:2],
                chroma_private._filesystem_type(lease.data_path),
            )
        ]
        assert all(
            path == ("chroma.sqlite3",)
            or (len(path) == 2 and path[1] in allowed_names)
            for path in changed
        )
    finally:
        lease.cleanup()
    assert source_before == _tree_hashes(source)
    assert not workspace.exists()
    assert list(work.iterdir()) == []


@compatibility
@pytest.mark.parametrize("mode", ["malformed", "oversized"])
def test_worker_request_failure_produces_no_receipt_and_cleans(
    tmp_path, monkeypatch, mode
):
    source, work = _make_fixture(tmp_path, "zero", "md5")
    lease = snapshot._prepare_snapshot(source, work)
    workspace = lease._workspace
    if mode == "malformed":
        monkeypatch.setattr(
            chroma_private,
            "_borrow_request",
            lambda *args, **kwargs: {"unexpected": "worker-crash-canary"},
        )
    else:
        monkeypatch.setattr(
            chroma_private,
            "_borrow_request",
            lambda *args, **kwargs: {"oversized": "x" * chroma_private._MAX_IPC_PAYLOAD},
        )
    try:
        with pytest.raises(chroma_private._ChromaScanError) as raised:
            chroma_private._scan_prepared_chroma(lease)
        _assert_private_error(raised.value, ("worker-crash-canary",))
    finally:
        lease.cleanup()
    assert not workspace.exists()
    assert list(work.iterdir()) == []


@compatibility
def test_parent_cancellation_produces_no_receipt_and_cleans(tmp_path):
    source, work = _make_fixture(tmp_path, "populated", "md5")
    lease = snapshot._prepare_snapshot(source, work)
    workspace = lease._workspace
    started = time.monotonic()
    try:
        with pytest.raises(chroma_private._ChromaScanError) as raised:
            chroma_private._scan_prepared_chroma(
                lease, cancelled=lambda: time.monotonic() - started > 0.5
            )
        _assert_private_error(raised.value)
    finally:
        lease.cleanup()
    assert not workspace.exists()
    assert list(work.iterdir()) == []


@compatibility
@pytest.mark.parametrize("phase", ["after-worker", "before-receipt"])
def test_capability_loss_after_worker_or_before_receipt_fails_and_cleans(
    tmp_path, monkeypatch, phase
):
    source, work = _make_fixture(tmp_path, "zero", "md5")
    lease = snapshot._prepare_snapshot(source, work)
    workspace = lease._workspace
    original_process = lease._process_id
    if phase == "after-worker":
        original = chroma_private._run_worker

        def mutate_after_worker(*args, **kwargs):
            result = original(*args, **kwargs)
            lease._process_id += 1
            return result

        monkeypatch.setattr(chroma_private, "_run_worker", mutate_after_worker)
    else:
        original = chroma_private._classify_effects

        def mutate_before_receipt(*args, **kwargs):
            original(*args, **kwargs)
            lease._process_id += 1

        monkeypatch.setattr(chroma_private, "_classify_effects", mutate_before_receipt)
    try:
        with pytest.raises(chroma_private._ChromaScanError) as raised:
            chroma_private._scan_prepared_chroma(lease)
        _assert_private_error(raised.value)
    finally:
        lease._process_id = original_process
        lease.cleanup()
    assert not workspace.exists()
    assert list(work.iterdir()) == []


@compatibility
def test_ready_copy_record_mutation_fails_before_worker_start(tmp_path, monkeypatch):
    source, work = _make_fixture(tmp_path, "populated", "md5")
    source_before = _tree_hashes(source)
    lease = snapshot._prepare_snapshot(source, work)
    workspace = lease._workspace
    database = lease.data_path / "chroma.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE embeddings_queue SET id='ready-copy-mutation-canary' "
            "WHERE seq_id=(SELECT MIN(seq_id) FROM embeddings_queue)"
        )
        connection.commit()
    finally:
        connection.close()
    worker_calls = []
    monkeypatch.setattr(
        chroma_private,
        "_run_worker",
        lambda *args, **kwargs: worker_calls.append(True) or (1, 2, 11, 28),
    )
    try:
        with pytest.raises(chroma_private._ChromaScanError) as raised:
            chroma_private._scan_prepared_chroma(lease)
        _assert_private_error(raised.value, ("ready-copy-mutation-canary",))
        assert worker_calls == []
        assert source_before == _tree_hashes(source)
    finally:
        lease.cleanup()
    assert not workspace.exists()
    assert list(work.iterdir()) == []


@compatibility
@pytest.mark.parametrize("phase", ["after-worker", "between-final-checks"])
def test_record_mutation_after_enumeration_never_creates_receipt(
    tmp_path, monkeypatch, phase
):
    source, work = _make_fixture(tmp_path, "populated", "md5")
    source_before = _tree_hashes(source)
    lease = snapshot._prepare_snapshot(source, work)
    workspace = lease._workspace

    def mutate_record():
        connection = sqlite3.connect(lease.data_path / "chroma.sqlite3")
        try:
            connection.execute(
                "UPDATE embeddings_queue SET id='post-enumeration-mutation-canary' "
                "WHERE seq_id=(SELECT MIN(seq_id) FROM embeddings_queue)"
            )
            connection.commit()
        finally:
            connection.close()

    if phase == "after-worker":
        original = chroma_private._run_worker

        def mutate_after_worker(*args, **kwargs):
            result = original(*args, **kwargs)
            mutate_record()
            return result

        monkeypatch.setattr(chroma_private, "_run_worker", mutate_after_worker)
    else:
        original = chroma_private._classify_effects
        calls = 0

        def mutate_between_checks(*args, **kwargs):
            nonlocal calls
            calls += 1
            original(*args, **kwargs)
            if calls == 1:
                mutate_record()

        monkeypatch.setattr(chroma_private, "_classify_effects", mutate_between_checks)
    try:
        with pytest.raises(chroma_private._ChromaScanError) as raised:
            chroma_private._scan_prepared_chroma(lease)
        _assert_private_error(raised.value, ("post-enumeration-mutation-canary",))
        assert source_before == _tree_hashes(source)
    finally:
        lease.cleanup()
    assert not workspace.exists()
    assert list(work.iterdir()) == []


@compatibility
def test_hostile_environment_and_dotenv_cannot_redirect_local_settings(tmp_path, monkeypatch):
    source, work = _make_fixture(tmp_path, "empty", "md5")
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    dotenv = hostile / ".env"
    dotenv.write_text(
        "CHROMA_SERVER_HOST=privacy-canary.invalid\n"
        "ANONYMIZED_TELEMETRY=TRUE\n"
        "MIGRATIONS=apply\n"
        "ALLOW_RESET=TRUE\n",
        encoding="utf-8",
    )
    for name, value in {
        "CHROMA_SERVER_HOST": "privacy-canary.invalid",
        "HTTP_PROXY": "http://proxy-canary.invalid",
        "HTTPS_PROXY": "http://proxy-canary.invalid",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel-canary.invalid",
        "ANONYMIZED_TELEMETRY": "TRUE",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(hostile)
    lease = snapshot._prepare_snapshot(source, work)
    try:
        receipt = chroma_private._scan_prepared_chroma(lease)
        assert receipt.collections_enumerated == 1
    finally:
        lease.cleanup()
    assert list(work.iterdir()) == []


@compatibility
def test_only_worker_generates_the_random_session_key(tmp_path, monkeypatch):
    source, work = _make_fixture(tmp_path, "zero", "md5")
    lease = snapshot._prepare_snapshot(source, work)

    def parent_randomness_must_not_run(size):
        raise AssertionError("second-session-key-canary")

    monkeypatch.setattr(
        chroma_private.secrets, "token_bytes", parent_randomness_must_not_run
    )
    try:
        receipt = chroma_private._scan_prepared_chroma(lease)
        assert receipt.collections_enumerated == 0
        assert receipt.records_enumerated == 0
    finally:
        lease.cleanup()
    assert list(work.iterdir()) == []


@compatibility
def test_worker_argv_environment_console_and_logging_are_privacy_minimal(
    tmp_path, monkeypatch, capsys, caplog
):
    source, work = _make_fixture(tmp_path, "populated", "md5")
    lease = snapshot._prepare_snapshot(source, work)
    observed = {}
    original = chroma_private.subprocess.Popen

    def capture(command, *args, **kwargs):
        observed["command"] = command
        observed["environment"] = kwargs.get("env")
        observed["cwd"] = kwargs.get("cwd")
        return original(command, *args, **kwargs)

    monkeypatch.setattr(chroma_private.subprocess, "Popen", capture)
    try:
        receipt = chroma_private._scan_prepared_chroma(lease)
        assert receipt.records_enumerated == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""
        assert caplog.records == []
        assert observed["cwd"] == lease.data_path
        assert observed["command"] == [
            sys.executable,
            "-I",
            "-m",
            "ragleakguard._chroma_snapshot",
            "--worker",
        ]
        serialized = json.dumps(
            [observed["command"], observed["environment"]], sort_keys=True
        )
        for canary in (
            str(source),
            str(work),
            str(lease.data_path),
            lease._workspace_id,
            lease._snapshot_id,
            lease._lease_id,
            "synthetic-private",
            "doc-b",
            "id-b",
            "value",
        ):
            assert canary not in serialized
    finally:
        lease.cleanup()
    assert list(work.iterdir()) == []


@compatibility
@pytest.mark.parametrize(
    "mutation",
    [
        "uppercase",
        "missing",
        "extra",
        "renamed",
        "mixed",
        "malformed",
        "reordered",
        "duplicate",
    ],
)
def test_migration_adversaries_fail_without_repair_or_source_change(tmp_path, mutation):
    source, work = _make_fixture(tmp_path, "zero", "md5")
    database = source / "chroma.sqlite3"
    connection = sqlite3.connect(database)
    try:
        if mutation == "uppercase":
            connection.execute("UPDATE migrations SET hash=upper(hash) WHERE dir='sysdb' AND version=1")
        elif mutation == "missing":
            connection.execute("DELETE FROM migrations WHERE dir='sysdb' AND version=10")
        elif mutation == "extra":
            connection.execute(
                "INSERT INTO migrations VALUES ('unknown',1,'00001-x.sqlite.sql','select 1','c4ca4238a0b923820dcc509a6f75849b')"
            )
        elif mutation == "renamed":
            connection.execute("UPDATE migrations SET filename='renamed.sqlite.sql' WHERE dir='sysdb' AND version=1")
        elif mutation == "mixed":
            connection.execute("UPDATE migrations SET hash=? WHERE dir='sysdb' AND version=1", ("0" * 64,))
        elif mutation == "malformed":
            connection.execute("UPDATE migrations SET hash=? WHERE dir='sysdb' AND version=1", ("g" * 32,))
        elif mutation == "reordered":
            connection.execute("UPDATE migrations SET version=11 WHERE dir='sysdb' AND version=10")
        elif mutation == "duplicate":
            connection.execute("ALTER TABLE migrations RENAME TO migrations_original")
            connection.execute(
                "CREATE TABLE migrations(dir TEXT NOT NULL,version INTEGER NOT NULL,"
                "filename TEXT NOT NULL,sql TEXT NOT NULL,hash TEXT NOT NULL)"
            )
            connection.execute("INSERT INTO migrations SELECT * FROM migrations_original")
            connection.execute(
                "INSERT INTO migrations SELECT * FROM migrations_original "
                "WHERE dir='sysdb' AND version=1"
            )
            connection.execute("DROP TABLE migrations_original")
        connection.commit()
    finally:
        connection.close()
    source_before = _tree_hashes(source)
    lease = snapshot._prepare_snapshot(source, work)
    try:
        with pytest.raises(chroma_private._ChromaScanError) as raised:
            chroma_private._scan_prepared_chroma(lease)
        _assert_private_error(raised.value)
        assert source_before == _tree_hashes(source)
    finally:
        lease.cleanup()
    assert list(work.iterdir()) == []


@compatibility
@pytest.mark.parametrize(
    "mutation",
    [
        "missing-sqlite",
        "invalid-header",
        "uninitialized",
        "wrong-tenant",
        "wrong-database",
        "extra-schema",
    ],
)
def test_store_preflight_adversaries_fail_without_source_change(tmp_path, mutation):
    source, work = _make_fixture(tmp_path, "zero", "md5")
    database = source / "chroma.sqlite3"
    if mutation == "missing-sqlite":
        database.unlink()
    elif mutation == "invalid-header":
        saved = database.read_bytes()
        database.write_bytes(b"invalid-header-canary" + saved[21:])
    elif mutation == "uninitialized":
        database.unlink()
        connection = sqlite3.connect(database)
        try:
            connection.execute("VACUUM")
        finally:
            connection.close()
    else:
        connection = sqlite3.connect(database)
        try:
            if mutation == "wrong-tenant":
                connection.execute(
                    "UPDATE tenants SET id='tenant-canary' WHERE id='default_tenant'"
                )
            elif mutation == "wrong-database":
                connection.execute(
                    "UPDATE databases SET name='database-canary' "
                    "WHERE name='default_database'"
                )
            else:
                connection.execute("CREATE TABLE extra_schema_canary(value TEXT)")
            connection.commit()
        finally:
            connection.close()
    source_before = _tree_hashes(source)
    lease = snapshot._prepare_snapshot(source, work)
    workspace = lease._workspace
    try:
        with pytest.raises(chroma_private._ChromaScanError) as raised:
            chroma_private._scan_prepared_chroma(lease)
        _assert_private_error(
            raised.value,
            (
                "missing-sqlite-canary",
                "invalid-header-canary",
                "tenant-canary",
                "database-canary",
                "extra_schema_canary",
            ),
        )
        assert source_before == _tree_hashes(source)
    finally:
        lease.cleanup()
    assert source_before == _tree_hashes(source)
    assert not workspace.exists()
    assert list(work.iterdir()) == []


@compatibility
@pytest.mark.parametrize(
    "mutation", ["moved-data", "unauthenticated-marker", "non-ready-marker"]
)
def test_moved_or_unauthenticated_capability_fails_before_dependency_use_and_recovers(
    tmp_path, mutation
):
    source, work = _make_fixture(tmp_path, "zero", "md5")
    lease = snapshot._prepare_snapshot(source, work)
    workspace = lease._workspace
    data = lease.data_path
    moved = data.with_name("moved-data-canary")
    marker = lease._snapshot / snapshot._SNAPSHOT_MARKER
    saved_marker = snapshot._read_bounded(marker, 4_096, snapshot._SnapshotBorrowError)
    try:
        if mutation == "moved-data":
            data.rename(moved)
        elif mutation == "unauthenticated-marker":
            snapshot._replace_control(marker, b'{"path":"marker-canary"}')
        else:
            snapshot._replace_control(
                marker,
                snapshot._authenticated_document(
                    lease._key,
                    snapshot._snapshot_body(
                        lease._workspace_id,
                        lease._snapshot_id,
                        lease._lease_id,
                        "preparing",
                    ),
                ),
            )
        with pytest.raises(chroma_private._ChromaScanError) as raised:
            chroma_private._scan_prepared_chroma(lease)
        _assert_private_error(raised.value, ("moved-data-canary", "marker-canary"))
    finally:
        if moved.exists():
            moved.rename(data)
        snapshot._replace_control(marker, saved_marker)
        lease.cleanup()
    assert not workspace.exists()
    assert list(work.iterdir()) == []


@compatibility
def test_lost_lease_fails_before_dependency_and_is_recoverable(tmp_path):
    source, work = _make_fixture(tmp_path, "zero", "md5")
    lease = snapshot._prepare_snapshot(source, work)
    workspace = lease._workspace
    lease._lock.close()
    with pytest.raises(chroma_private._ChromaScanError) as raised:
        chroma_private._scan_prepared_chroma(lease)
    _assert_private_error(raised.value)
    assert snapshot._recover_snapshots(work) == 1
    assert not workspace.exists()
    assert list(work.iterdir()) == []


@compatibility
def test_closed_lost_and_wrong_process_capabilities_fail(tmp_path):
    source, work = _make_fixture(tmp_path, "zero", "md5")
    lease = snapshot._prepare_snapshot(source, work)
    original_process = lease._process_id
    lease._process_id = original_process + 1
    with pytest.raises(chroma_private._ChromaScanError) as raised:
        chroma_private._scan_prepared_chroma(lease)
    _assert_private_error(raised.value)
    lease._process_id = original_process
    lease.cleanup()
    with pytest.raises(chroma_private._ChromaScanError) as raised:
        chroma_private._scan_prepared_chroma(lease)
    _assert_private_error(raised.value)
    assert list(work.iterdir()) == []


@compatibility
def test_os_level_egress_denial_probe_is_mandatory():
    assert os.environ.get("RLG_WP7C_OS_EGRESS_DENIED") == "1"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(2.0)
        with pytest.raises(OSError):
            probe.connect(("1.1.1.1", 443))
