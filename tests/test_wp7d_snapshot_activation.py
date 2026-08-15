"""WP7D public operator-snapshot activation and finalization regressions."""
from __future__ import annotations

import dataclasses
import hashlib
import importlib.metadata
import os
import platform
import socket
import subprocess
import sys
import textwrap
import traceback
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
from typer.testing import CliRunner

from ragleakguard import _chroma_snapshot as chroma_private
from ragleakguard import cli
from ragleakguard import connectors
from ragleakguard import report as reporting


SOURCE_PATH_CANARY = "operator-snapshot-path-canary"
WORK_PATH_CANARY = "private-work-parent-path-canary"
REPORT_PATH_CANARY = "private-report-path-canary"
RAW_CANARIES = (
    "document-text-canary",
    "metadata-value-canary",
    "collection-name-canary",
    "record-id-canary",
    SOURCE_PATH_CANARY,
    WORK_PATH_CANARY,
    REPORT_PATH_CANARY,
    "dependency-exception-canary",
    "secret-token-canary",
)


def _detector_aggregate(**overrides):
    values = {
        "records_completed": 2,
        "source_segments_completed": 3,
        "source_utf8_bytes_completed": 12,
        "records_with_findings": 1,
        "total_findings": 2,
        "finding_counts_by_type": {"EMAIL_ADDRESS": 2},
    }
    values.update(overrides)
    return connectors.DetectorAggregate(**values)


def _scan_result(**overrides):
    values = {
        "collections_completed": 1,
        "records_completed": 2,
        "source_segments_completed": 3,
        "source_utf8_bytes_completed": 12,
        "detector": _detector_aggregate(),
    }
    values.update(overrides)
    return connectors.ChromaSnapshotScanResult(**values)


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "a/b",
        r"a\b",
        ".leading",
        "customer name",
        "name\nforged",
        "Ã©",
        "a" * 65,
        None,
        1,
        True,
    ],
)
def test_source_id_grammar_rejects_paths_controls_non_ascii_and_bad_types(value):
    with pytest.raises(connectors.InvalidChromaSnapshotRequest):
        connectors.validate_chroma_source_id(value)


@pytest.mark.parametrize(
    "value", ["a", "A0", "source-1", "source_1", "source.1", "a" * 64]
)
def test_source_id_grammar_accepts_only_the_narrow_ascii_contract(value):
    assert connectors.validate_chroma_source_id(value) == value


def test_read_chroma_remains_synchronous_and_argument_opaque():
    events = []

    class Hostile:
        def __getattribute__(self, name):
            if name == "__class__":
                return object.__getattribute__(self, name)
            events.append(name)
            raise AssertionError

        def __fspath__(self):
            events.append("fspath")
            raise AssertionError

        def __str__(self):
            events.append("str")
            raise AssertionError

    with pytest.raises(connectors.ChromaConnectorUnavailableError):
        connectors.read_chroma(Hostile(), Hostile())
    assert events == []


@pytest.mark.parametrize(
    "stage",
    ["acknowledgement", "source-id", "locale", "runtime", "version", "platform"],
)
def test_every_public_preflight_gate_fails_before_snapshot_preparation(
    monkeypatch, stage
):
    prepared = []
    monkeypatch.setattr(
        connectors._snapshot,
        "_prepare_snapshot",
        lambda *args, **kwargs: prepared.append((args, kwargs)),
    )
    monkeypatch.setattr(connectors, "validate_detection_runtime", lambda locale: locale)
    monkeypatch.setattr(
        connectors._chroma_snapshot, "_public_activation_gate", lambda: "1.5.9"
    )
    kwargs = {
        "source_id": "source-1",
        "acknowledge_offline_complete_snapshot": True,
        "locale": None,
    }
    if stage == "acknowledgement":
        kwargs["acknowledge_offline_complete_snapshot"] = False
    elif stage == "source-id":
        kwargs["source_id"] = "bad/path"
    elif stage == "locale":
        monkeypatch.setattr(
            connectors,
            "normalize_locale",
            lambda value: (_ for _ in ()).throw(connectors.UnsupportedLocaleError()),
        )
        kwargs["locale"] = "uk"
    elif stage == "runtime":
        monkeypatch.setattr(
            connectors,
            "validate_detection_runtime",
            lambda value: (_ for _ in ()).throw(
                connectors.MissingDetectionModelError()
            ),
        )
    elif stage in {"version", "platform"}:
        monkeypatch.setattr(
            connectors._chroma_snapshot,
            "_public_activation_gate",
            lambda: (_ for _ in ()).throw(chroma_private._ChromaScanError()),
        )

    expected = connectors.InvalidChromaSnapshotRequest if stage in {
        "acknowledgement",
        "source-id",
    } else Exception
    with pytest.raises(expected):
        connectors.scan_chroma_snapshot(
            SOURCE_PATH_CANARY,
            WORK_PATH_CANARY,
            **kwargs,
        )
    assert prepared == []


def test_public_result_is_immutable_bounded_and_mapping_is_read_only():
    result = _scan_result()
    assert isinstance(result.detector.finding_counts_by_type, MappingProxyType)
    assert result.detector.finding_counts_by_type == {"EMAIL_ADDRESS": 2}
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.records_completed = 3
    with pytest.raises(TypeError):
        result.detector.finding_counts_by_type["EMAIL_ADDRESS"] = 3
    assert SOURCE_PATH_CANARY not in repr(result)
    assert WORK_PATH_CANARY not in repr(result)


@pytest.mark.parametrize(
    "overrides",
    [
        {"records_completed": True},
        {"records_completed": -1},
        {"records_completed": 10_001},
        {"source_segments_completed": 100_001},
        {"source_utf8_bytes_completed": 268_435_457},
        {"records_with_findings": 3},
        {"total_findings": -1},
        {"total_findings": 1_000_001},
        {"finding_counts_by_type": {"EMAIL_ADDRESS": True}},
        {"finding_counts_by_type": {"bad/type": 1}},
        {"finding_counts_by_type": {f"TYPE_{n}": 1 for n in range(65)}},
        {"finding_counts_by_type": {"EMAIL_ADDRESS": 1}},
        {"finding_counts_by_type": {}, "total_findings": 2},
    ],
)
def test_detector_aggregate_rejects_boolean_negative_oversized_and_inconsistent_values(
    overrides,
):
    with pytest.raises(ValueError):
        _detector_aggregate(**overrides)


def test_connector_and_detector_counter_mismatch_is_rejected():
    with pytest.raises(ValueError):
        _scan_result(detector=_detector_aggregate(records_completed=1))
    with pytest.raises(ValueError):
        _scan_result(detector=_detector_aggregate(source_segments_completed=2))
    with pytest.raises(ValueError):
        _scan_result(detector=_detector_aggregate(source_utf8_bytes_completed=11))


def test_zero_record_zero_segment_zero_finding_result_is_valid():
    detector = connectors.DetectorAggregate(
        records_completed=0,
        source_segments_completed=0,
        source_utf8_bytes_completed=0,
        records_with_findings=0,
        total_findings=0,
        finding_counts_by_type={},
    )
    result = connectors.ChromaSnapshotScanResult(
        collections_completed=0,
        records_completed=0,
        source_segments_completed=0,
        source_utf8_bytes_completed=0,
        detector=detector,
    )
    assert result.detector.total_findings == 0


def _successful_public_preflight(monkeypatch):
    monkeypatch.setattr(connectors, "normalize_locale", lambda locale: locale)
    monkeypatch.setattr(connectors, "validate_detection_runtime", lambda locale: locale)
    monkeypatch.setattr(
        connectors._chroma_snapshot, "_public_activation_gate", lambda: "1.5.9"
    )


@pytest.mark.parametrize("failure", ["scan", "cancellation", "cleanup"])
def test_scan_cancellation_or_cleanup_uncertainty_returns_no_result_and_cleans(
    monkeypatch, failure
):
    _successful_public_preflight(monkeypatch)
    events = []

    class Prepared:
        def cleanup(self):
            events.append("cleanup")
            if failure == "cleanup":
                raise OSError("cleanup-path-canary")

    prepared = Prepared()
    monkeypatch.setattr(
        connectors._snapshot, "_prepare_snapshot", lambda *args, **kwargs: prepared
    )

    def scan(*args, **kwargs):
        events.append("scan")
        if failure == "cancellation":
            assert kwargs["cancelled"]() is True
        if failure in {"scan", "cancellation"}:
            raise chroma_private._ChromaScanError("detector-exception-canary")
        return (
            SimpleNamespace(
                collections_enumerated=1,
                records_enumerated=2,
                source_segments_enumerated=3,
                source_utf8_bytes_enumerated=12,
            ),
            {
                "finding_counts_by_type": {"EMAIL_ADDRESS": 2},
                "records_completed": 2,
                "records_with_findings": 1,
                "source_segments_completed": 3,
                "source_utf8_bytes_completed": 12,
                "total_findings": 2,
            },
        )

    monkeypatch.setattr(
        connectors._chroma_snapshot,
        "_scan_prepared_chroma_with_detection",
        scan,
    )
    cancelled = (lambda: True) if failure == "cancellation" else None
    with pytest.raises(connectors.ChromaSnapshotScanError) as caught:
        connectors.scan_chroma_snapshot(
            SOURCE_PATH_CANARY,
            WORK_PATH_CANARY,
            source_id="source-1",
            acknowledge_offline_complete_snapshot=True,
            cancelled=cancelled,
        )
    assert events == ["scan", "cleanup"]
    rendered = "".join(
        traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__)
    )
    for canary in RAW_CANARIES + ("cleanup-path-canary", "detector-exception-canary"):
        assert canary not in rendered


def test_detector_invoked_once_per_first_pass_segment_and_not_on_second_pass():
    calls = []

    def fake_detect(text, locale=None):
        calls.append((text, locale))
        if "email" in text:
            start = text.index("email")
            return [{
                "type": "EMAIL_ADDRESS",
                "start": start,
                "end": start + 5,
                "score": 0.9,
                "text": "email",
            }]
        return []

    accumulator = chroma_private._DetectorAccumulator(
        None,
        chroma_private._DEFAULT_DETECTOR_LIMITS,
        fake_detect,
        frozenset({"EMAIL_ADDRESS"}),
    )
    accumulator.start_record()
    first = chroma_private._canonical_content(
        b"k" * 32,
        "email document",
        {"zeta": ["one", "two"], "metadata": "value"},
        chroma_private._PUBLIC_CHROMA_SCAN_LIMITS,
        segment_consumer=accumulator.consume,
    )
    accumulator.finish_record()
    second = chroma_private._canonical_content(
        b"k" * 32,
        "email document",
        {"zeta": ["one", "two"], "metadata": "value"},
        chroma_private._PUBLIC_CHROMA_SCAN_LIMITS,
    )
    assert first == second
    assert calls == [
        ("email document", None),
        ("metadata", None),
        ("value", None),
        ("zeta", None),
        ("one", None),
        ("two", None),
    ]
    assert accumulator.result() == {
        "finding_counts_by_type": {"EMAIL_ADDRESS": 1},
        "records_completed": 1,
        "records_with_findings": 1,
        "source_segments_completed": 6,
        "source_utf8_bytes_completed": 37,
        "total_findings": 1,
    }


def test_offline_suffix_import_allows_no_real_socket_or_general_probe():
    previous = chroma_private._ATTEMPTED_EGRESS_OR_PROCESS
    chroma_private._ATTEMPTED_EGRESS_OR_PROCESS = False
    try:
        with pytest.raises(OSError):
            chroma_private._UnavailableIPv6Probe(socket.AF_INET6)
        assert chroma_private._ATTEMPTED_EGRESS_OR_PROCESS is False
        with pytest.raises(chroma_private._ChromaScanError):
            chroma_private._UnavailableIPv6Probe(socket.AF_INET)
        assert chroma_private._ATTEMPTED_EGRESS_OR_PROCESS is True
    finally:
        chroma_private._ATTEMPTED_EGRESS_OR_PROCESS = previous


@pytest.mark.parametrize(
    "findings",
    [
        None,
        {},
        [{"type": "EMAIL_ADDRESS"}],
        [{
            "type": "bad/type", "start": 0, "end": 1, "score": 0.5, "text": "x"
        }],
        [{
            "type": "EMAIL_ADDRESS", "start": True, "end": 1,
            "score": 0.5, "text": "x"
        }],
        [{
            "type": "EMAIL_ADDRESS", "start": 0, "end": 2,
            "score": 0.5, "text": "x"
        }],
        [{
            "type": "EMAIL_ADDRESS", "start": 0, "end": 1,
            "score": float("nan"), "text": "x"
        }],
    ],
)
def test_malformed_detector_output_fails_closed(findings):
    accumulator = chroma_private._DetectorAccumulator(
        None,
        chroma_private._DEFAULT_DETECTOR_LIMITS,
        lambda text, locale=None: findings,
        frozenset({"EMAIL_ADDRESS"}),
    )
    accumulator.start_record()
    with pytest.raises(chroma_private._ChromaScanError):
        accumulator.consume("x", 1)


def test_detector_segment_bound_is_enforced_before_detection():
    calls = []
    limits = chroma_private._DetectorLimits(source_segments=1)
    accumulator = chroma_private._DetectorAccumulator(
        None,
        limits,
        lambda text, locale=None: calls.append(text) or [],
        frozenset({"EMAIL_ADDRESS"}),
    )
    accumulator.start_record()
    accumulator.consume("first", 5)
    with pytest.raises(chroma_private._ChromaScanError):
        accumulator.consume("second", 6)
    assert calls == ["first"]


def test_detection_request_and_response_are_bounded_and_privacy_minimal():
    request = chroma_private._detection_request(
        "1.5.9",
        "md5",
        chroma_private._PUBLIC_CHROMA_SCAN_LIMITS,
        chroma_private._DEFAULT_DETECTOR_LIMITS,
        None,
        60.0,
    )
    encoded = chroma_private._encode_frame(request, chroma_private._MAX_IPC_PAYLOAD)
    serialized = encoded.decode("ascii", errors="ignore")
    for canary in RAW_CANARIES:
        assert canary not in serialized
    assert len(encoded) <= chroma_private._MAX_IPC_PAYLOAD + 4

    response = {
        "collections": 1,
        "detector": {
            "finding_counts_by_type": {"EMAIL_ADDRESS": 2},
            "records_completed": 2,
            "records_with_findings": 1,
            "source_segments_completed": 3,
            "source_utf8_bytes_completed": 12,
            "total_findings": 2,
        },
        "ok": True,
        "records": 2,
        "segments": 3,
        "utf8_bytes": 12,
    }
    framed = chroma_private._encode_frame(
        response, chroma_private._MAX_DETECTOR_RESPONSE_PAYLOAD
    )
    assert len(framed) <= 16_388


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("detector"),
        lambda value: value["detector"].pop("records_completed"),
        lambda value: value["detector"].__setitem__("records_completed", True),
        lambda value: value["detector"].__setitem__("records_completed", -1),
        lambda value: value["detector"].__setitem__("records_completed", 10_001),
        lambda value: value["detector"].__setitem__("total_findings", 1_000_001),
        lambda value: value["detector"].__setitem__("records_with_findings", 0),
        lambda value: value["detector"].__setitem__(
            "finding_counts_by_type", {"bad/type": 2}
        ),
        lambda value: value["detector"].__setitem__(
            "finding_counts_by_type", {"UNKNOWN_ENTITY": 2}
        ),
        lambda value: value["detector"].__setitem__(
            "finding_counts_by_type", {"EMAIL_ADDRESS": 1}
        ),
        lambda value: value["detector"].__setitem__("source_segments_completed", 2),
    ],
)
def test_missing_boolean_negative_oversized_malformed_and_inconsistent_worker_aggregate_fails(
    mutate,
):
    request = chroma_private._detection_request(
        "1.5.9",
        "md5",
        chroma_private._PUBLIC_CHROMA_SCAN_LIMITS,
        chroma_private._DEFAULT_DETECTOR_LIMITS,
        None,
        60.0,
    )
    response = {
        "collections": 1,
        "detector": {
            "finding_counts_by_type": {"EMAIL_ADDRESS": 2},
            "records_completed": 2,
            "records_with_findings": 1,
            "source_segments_completed": 3,
            "source_utf8_bytes_completed": 12,
            "total_findings": 2,
        },
        "ok": True,
        "records": 2,
        "segments": 3,
        "utf8_bytes": 12,
    }
    mutate(response)
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._validate_detector_response(response, request)


def test_duplicate_worker_aggregate_key_is_rejected_during_frame_decode():
    payload = b'{"detector":{},"detector":{},"ok":true}'
    framed = len(payload).to_bytes(4, "big") + payload
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._decode_frame(
            framed, chroma_private._MAX_DETECTOR_RESPONSE_PAYLOAD
        )


def test_report_finalization_is_atomic_restrictive_bounded_and_path_free(tmp_path):
    target = tmp_path / REPORT_PATH_CANARY
    reporting._finalize_report("synthetic report", target)
    assert target.read_text(encoding="utf-8") == "synthetic report"
    if os.name != "nt":
        assert target.stat().st_mode & 0o077 == 0
    assert not list(tmp_path.glob(".rlg-report-*.tmp"))


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate data streams are Windows-only")
def test_report_finalization_rejects_ntfs_alternate_data_stream_target(tmp_path):
    target = tmp_path / "report.md:untrusted-stream"
    with pytest.raises(reporting.ReportFinalizationError):
        reporting._finalize_report("synthetic report", target)
    assert not os.path.lexists(target)
    assert not list(tmp_path.glob(".rlg-report-*.tmp"))


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("failure", ["write", "fsync", "replace", "directory-sync"])
def test_report_finalization_failure_preserves_existing_or_absent_target(
    tmp_path, monkeypatch, existing, failure
):
    target = tmp_path / REPORT_PATH_CANARY
    if existing:
        target.write_bytes(b"existing-report\x00\xff")
        before = target.read_bytes()
    else:
        before = None

    if failure == "write":
        monkeypatch.setattr(
            reporting, "_write_all", lambda *args: (_ for _ in ()).throw(OSError())
        )
    elif failure == "fsync":
        monkeypatch.setattr(
            reporting.os, "fsync", lambda *args: (_ for _ in ()).throw(OSError())
        )
    else:
        target_object = reporting.os if failure == "replace" else reporting
        attribute = "replace" if failure == "replace" else "_sync_report_directory"
        monkeypatch.setattr(
            target_object, attribute, lambda *args: (_ for _ in ()).throw(OSError())
        )

    with pytest.raises(reporting.ReportFinalizationError) as caught:
        reporting._finalize_report("replacement", target)
    rendered = "".join(
        traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__)
    )
    for canary in RAW_CANARIES:
        assert canary not in rendered
    if existing:
        assert target.read_bytes() == before
    else:
        assert not target.exists()
    assert not list(tmp_path.glob(".rlg-report-*.tmp"))


def test_report_finalization_interrupt_is_scrubbed_and_preserves_target(
    tmp_path, monkeypatch
):
    target = tmp_path / REPORT_PATH_CANARY
    target.write_bytes(b"existing")
    monkeypatch.setattr(
        reporting, "_write_all", lambda *args: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    with pytest.raises(reporting.ReportFinalizationError):
        reporting._finalize_report("replacement", target)
    assert target.read_bytes() == b"existing"
    assert not list(tmp_path.glob(".rlg-report-*.tmp"))


def test_report_finalization_detects_post_replace_swap_without_clobbering_it(
    tmp_path, monkeypatch
):
    target = tmp_path / REPORT_PATH_CANARY
    target.write_bytes(b"existing")

    def swap_target(_parent):
        target.unlink()
        target.write_bytes(b"unowned-replacement")
        return True

    monkeypatch.setattr(reporting, "_sync_report_directory", swap_target)
    with pytest.raises(reporting.ReportFinalizationError):
        reporting._finalize_report("replacement", target)
    assert target.read_bytes() == b"unowned-replacement"
    assert not list(tmp_path.glob(".rlg-report-*.tmp"))


def test_snapshot_report_contains_only_escaped_pseudonymous_identity():
    rendered = reporting.build_report(
        {"EMAIL_ADDRESS": 1},
        n_records=1,
        n_flagged=1,
        source="chroma-snapshot",
        path="source-1",
    )
    assert "`chroma-snapshot` `source-1`" in rendered
    for canary in RAW_CANARIES:
        assert canary not in rendered


def test_report_finalization_rejects_oversize_symlink_and_directory(tmp_path):
    target = tmp_path / "report.md"
    with pytest.raises(reporting.ReportFinalizationError):
        reporting._finalize_report("x" * (1_048_576 + 1), target)
    target.mkdir()
    with pytest.raises(reporting.ReportFinalizationError):
        reporting._finalize_report("x", target)
    target.rmdir()
    actual = tmp_path / "actual.md"
    actual.write_text("preserve", encoding="utf-8")
    try:
        target.symlink_to(actual)
    except (OSError, NotImplementedError):
        os.link(actual, target)
    with pytest.raises(reporting.ReportFinalizationError):
        reporting._finalize_report("x", target)
    assert actual.read_text(encoding="utf-8") == "preserve"
    if target.is_symlink():
        target.unlink()
    hard_link = tmp_path / "hard-link.md"
    try:
        os.link(actual, hard_link)
    except OSError:
        pytest.skip("hard links are unavailable on this test filesystem")
    with pytest.raises(reporting.ReportFinalizationError):
        reporting._finalize_report("x", hard_link)
    assert actual.read_text(encoding="utf-8") == "preserve"


def test_cli_success_occurs_only_after_cleanup_result_and_atomic_report(monkeypatch, tmp_path):
    events = []
    result = _scan_result()
    monkeypatch.setattr(
        connectors,
        "scan_chroma_snapshot",
        lambda *args, **kwargs: events.append("scan-cleaned") or result,
    )
    monkeypatch.setattr(
        reporting,
        "build_report",
        lambda *args, **kwargs: events.append("report-built") or "aggregate-report",
    )
    monkeypatch.setattr(
        reporting,
        "_finalize_report",
        lambda *args, **kwargs: events.append("report-finalized"),
    )
    response = CliRunner().invoke(
        cli.app,
        [
            "scan", "--source", "chroma", "--snapshot", str(tmp_path / SOURCE_PATH_CANARY),
            "--work-parent", str(tmp_path / WORK_PATH_CANARY), "--source-id", "source-1",
            "--acknowledge-offline-complete-snapshot", "--report", str(tmp_path / REPORT_PATH_CANARY),
        ],
    )
    assert response.exit_code == 0
    assert events == ["scan-cleaned", "report-built", "report-finalized"]
    assert "completed" in response.output.lower()
    for canary in RAW_CANARIES:
        assert canary not in response.output


def test_cli_rejects_legacy_path_without_source_or_report_access(tmp_path):
    response = CliRunner().invoke(
        cli.app,
        ["scan", "--source", "chroma", "--path", str(tmp_path / SOURCE_PATH_CANARY)],
    )
    assert response.exit_code == cli.EXIT_USAGE
    assert "legacy --path" in response.output.lower()
    assert SOURCE_PATH_CANARY not in response.output
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("failure", ["scan", "build", "finalize"])
def test_cli_failure_creates_no_report_state_webhook_or_success_signal(
    monkeypatch, tmp_path, failure
):
    report_path = tmp_path / REPORT_PATH_CANARY
    if failure == "scan":
        monkeypatch.setattr(
            connectors,
            "scan_chroma_snapshot",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                connectors.ChromaSnapshotScanError()
            ),
        )
    else:
        monkeypatch.setattr(
            connectors, "scan_chroma_snapshot", lambda *args, **kwargs: _scan_result()
        )
        if failure == "build":
            monkeypatch.setattr(
                reporting,
                "build_report",
                lambda *args, **kwargs: (_ for _ in ()).throw(
                    RuntimeError("document-text-canary")
                ),
            )
        else:
            monkeypatch.setattr(reporting, "build_report", lambda *args, **kwargs: "x")
            monkeypatch.setattr(
                reporting,
                "_finalize_report",
                lambda *args, **kwargs: (_ for _ in ()).throw(
                    reporting.ReportFinalizationError()
                ),
            )
    response = CliRunner().invoke(
        cli.app,
        [
            "scan",
            "--source",
            "chroma",
            "--snapshot",
            str(tmp_path / SOURCE_PATH_CANARY),
            "--work-parent",
            str(tmp_path / WORK_PATH_CANARY),
            "--source-id",
            "source-1",
            "--acknowledge-offline-complete-snapshot",
            "--report",
            str(report_path),
        ],
    )
    assert response.exit_code == cli.EXIT_SCAN_FAILURE
    assert "completed" not in response.output.lower()
    assert not report_path.exists()
    assert not (tmp_path / ".rlg-state.json").exists()
    assert not list(tmp_path.glob(".rlg-report-*.tmp"))
    for canary in RAW_CANARIES:
        assert canary not in response.output


def test_monitor_new_scan_boundary_remains_disabled_and_unchanged():
    result = CliRunner().invoke(cli.app, ["monitor", "--help"])
    assert result.exit_code == 0
    assert "new scans are disabled" in result.output.lower()
    assert "--snapshot" not in result.output


def test_numeric_contract_is_exact_and_narrower_than_wp7c():
    limits = chroma_private._PUBLIC_CHROMA_SCAN_LIMITS
    detector = chroma_private._DEFAULT_DETECTOR_LIMITS
    assert limits.collections == 1_000
    assert limits.records == 10_000
    assert limits.source_segments == 100_000
    assert limits.source_utf8_bytes == 268_435_456
    assert limits.document_bytes == 65_536
    assert detector.segment_bytes == 65_536
    assert detector.findings_per_segment == 4_096
    assert detector.total_findings == 1_000_000
    assert detector.entity_types == 64
    assert chroma_private._MAX_DETECTOR_RESPONSE_PAYLOAD == 16_384
    assert reporting._MAX_FINAL_REPORT_BYTES == 1_048_576
    assert reporting._REPORT_FINALIZATION_SECONDS == 30.0
    assert chroma_private._GLOBAL_SECONDS == 1_200.0
    assert chroma_private._AUTOMATIC_RETRIES == 0


def test_public_activation_gate_accepts_only_exact_159_on_five_tuples(monkeypatch):
    monkeypatch.setattr(chroma_private.importlib.metadata, "version", lambda name: "1.5.9")
    allowed = {
        ("Linux", (3, 10)), ("Linux", (3, 11)), ("Linux", (3, 12)),
        ("Darwin", (3, 12)), ("Windows", (3, 12)),
    }
    assert chroma_private._PUBLIC_ACTIVATION_ENVIRONMENTS == allowed


@pytest.mark.parametrize("version", ["1.5.0", "1.5.8", "1.5.10", "1.5.9rc1", "malformed"])
def test_public_activation_rejects_every_non_159_version(monkeypatch, version):
    monkeypatch.setattr(chroma_private.importlib.metadata, "version", lambda name: version)
    with pytest.raises(chroma_private._ChromaScanError):
        chroma_private._public_activation_gate()


def test_public_connector_rejects_private_150_candidate_before_snapshot_access(
    monkeypatch,
):
    prepared = []
    monkeypatch.setattr(connectors, "normalize_locale", lambda locale: locale)
    monkeypatch.setattr(connectors, "validate_detection_runtime", lambda locale: locale)
    monkeypatch.setattr(
        chroma_private.importlib.metadata, "version", lambda name: "1.5.0"
    )
    monkeypatch.setattr(
        connectors._snapshot,
        "_prepare_snapshot",
        lambda *args, **kwargs: prepared.append((args, kwargs)),
    )
    with pytest.raises(connectors.ChromaSnapshotUnavailableError):
        connectors.scan_chroma_snapshot(
            SOURCE_PATH_CANARY,
            WORK_PATH_CANARY,
            source_id="source-1",
            acknowledge_offline_complete_snapshot=True,
        )
    assert prepared == []


@pytest.mark.parametrize(
    "system,python,machine",
    [
        ("Linux", (3, 9), "x86_64"),
        ("Windows", (3, 11), "AMD64"),
        ("Darwin", (3, 11), "arm64"),
        ("FreeBSD", (3, 12), "amd64"),
    ],
)
def test_every_unlisted_public_host_tuple_fails_before_snapshot_access(
    monkeypatch, system, python, machine
):
    prepared = []
    monkeypatch.setattr(connectors, "normalize_locale", lambda locale: locale)
    monkeypatch.setattr(connectors, "validate_detection_runtime", lambda locale: locale)
    monkeypatch.setattr(
        chroma_private.importlib.metadata, "version", lambda name: "1.5.9"
    )
    monkeypatch.setattr(chroma_private.platform, "system", lambda: system)
    monkeypatch.setattr(chroma_private.platform, "machine", lambda: machine)
    monkeypatch.setattr(chroma_private.platform, "mac_ver", lambda: ("15.0", (), ()))
    monkeypatch.setattr(
        chroma_private.sys,
        "version_info",
        SimpleNamespace(major=python[0], minor=python[1]),
    )
    monkeypatch.setattr(
        connectors._snapshot,
        "_prepare_snapshot",
        lambda *args, **kwargs: prepared.append((args, kwargs)),
    )
    with pytest.raises(connectors.ChromaSnapshotUnavailableError):
        connectors.scan_chroma_snapshot(
            SOURCE_PATH_CANARY,
            WORK_PATH_CANARY,
            source_id="source-1",
            acknowledge_offline_complete_snapshot=True,
        )
    assert prepared == []


def test_wp7c_private_candidates_and_ten_cell_matrix_remain_intact():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "wp7c-private-chroma.yml").read_text(
        encoding="utf-8"
    )
    assert chroma_private._CANDIDATES == frozenset({"1.5.0", "1.5.9"})
    assert workflow.count('chroma: "1.5.0"') == 5
    assert workflow.count('chroma: "1.5.9"') == 5


def test_wp7d_workflow_has_five_exact_cells_and_mandatory_evidence():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "wp7d-snapshot-chroma.yml").read_text(
        encoding="utf-8"
    )
    assert workflow.count('chroma: "1.5.9"') == 5
    assert workflow.count("- os: ubuntu-latest") == 3
    assert workflow.count("- os: macos-15") == 1
    assert workflow.count("- os: windows-latest") == 1
    for exact in (
        "chromadb==${{ matrix.chroma }}",
        ".[chroma-snapshot,detect,dev]",
        "pip check",
        "pip list --format=freeze --disable-pip-version-check",
        "RLG_WP7D_ACTIVATION",
        "RLG_WP7D_MANDATORY",
        "RLG_WP7D_OS_EGRESS_DENIED",
        "RLG_WP7C_OS_EGRESS_DENIED",
        "RLG_REQUIRE_NATIVE_SNAPSHOT_FS",
        "iptables",
        "sandbox-exec",
        "New-NetFirewallRule",
        "tests/test_wp7d_snapshot_activation.py",
        "if: always()",
    ):
        assert exact in workflow
    assert "upload-artifact" not in workflow


_ACTIVATION = os.environ.get("RLG_WP7D_ACTIVATION") == "1"
_MANDATORY_MATRIX = os.environ.get("RLG_WP7D_MANDATORY") == "1"
_activation = pytest.mark.skipif(
    not _ACTIVATION and not _MANDATORY_MATRIX,
    reason="runs only in the exact five-cell WP7D activation matrix",
)
_PUBLIC_FIXTURE_SCRIPT = textwrap.dedent(
    """
    import sys
    import chromadb
    from chromadb.config import DEFAULT_DATABASE, DEFAULT_TENANT, Settings

    path = sys.argv[1]
    settings = Settings(
        _env_file=None,
        anonymized_telemetry=False,
        is_persistent=True,
        persist_directory=path,
        migrations="apply",
        migrations_hash_algorithm="md5",
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
    collection = client.create_collection("synthetic-public")
    collection.add(
        ids=["synthetic-a", "synthetic-b"],
        embeddings=[[0.1, 0.2], [0.3, 0.4]],
        documents=["alice@example.com", "plain"],
        metadatas=[{"kind": "alpha"}, {"kind": "beta"}],
    )
    """
)


def _tree_hashes(root: Path):
    return {
        path.relative_to(root).parts: hashlib.sha256(path.read_bytes()).digest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


@_activation
def test_activation_environment_is_exact_native_and_os_egress_denied(tmp_path):
    assert _ACTIVATION
    assert _MANDATORY_MATRIX
    assert os.environ.get("RLG_WP7D_OS_EGRESS_DENIED") == "1"
    assert importlib.metadata.version("chromadb") == "1.5.9"
    assert (platform.system(), sys.version_info[:2]) in (
        chroma_private._PUBLIC_ACTIVATION_ENVIRONMENTS
    )
    assert chroma_private._filesystem_type(tmp_path) == {
        "Linux": "ext4",
        "Darwin": "apfs",
        "Windows": "ntfs",
    }[platform.system()]
    assert chroma_private._public_activation_gate() == "1.5.9"


@_activation
def test_exact_candidate_public_scan_detects_aggregates_preserves_source_and_cleans(
    tmp_path,
):
    source = tmp_path / "source"
    work = tmp_path / "work"
    source.mkdir()
    work.mkdir()
    created = subprocess.run(
        [sys.executable, "-c", _PUBLIC_FIXTURE_SCRIPT, str(source)],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert created.returncode == 0
    assert created.stdout == b""
    assert created.stderr == b""
    source_before = _tree_hashes(source)

    result = connectors.scan_chroma_snapshot(
        source,
        work,
        source_id="synthetic-source",
        acknowledge_offline_complete_snapshot=True,
    )

    assert (
        result.collections_completed,
        result.records_completed,
        result.source_segments_completed,
        result.source_utf8_bytes_completed,
        result.detector.records_with_findings,
        result.detector.total_findings,
        dict(result.detector.finding_counts_by_type),
    ) == (1, 2, 6, 39, 1, 1, {"EMAIL_ADDRESS": 1})
    assert _tree_hashes(source) == source_before
    assert list(work.iterdir()) == []
