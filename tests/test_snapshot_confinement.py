"""WP7B private, bounded operator-snapshot confinement evidence."""
import builtins
import json
import inspect
import os
import plistlib
import socket
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from click import unstyle
from typer.testing import CliRunner

from ragleakguard import _snapshot as snap
from ragleakguard import cli, connectors


SOURCE_CANARY = "operator-source-path-canary"
CONTENT_CANARY = b"synthetic-private-content-canary"
STATIC_PREPARATION = "Snapshot confinement preparation failed."
STATIC_CLEANUP = "Snapshot confinement cleanup failed; residue may remain."
STATIC_RECOVERY = "Snapshot confinement recovery failed closed."


def _tree(tmp_path):
    source = tmp_path / SOURCE_CANARY
    work = tmp_path / "work-parent"
    source.mkdir()
    work.mkdir()
    (source / "nested").mkdir()
    (source / "nested" / "record.bin").write_bytes(CONTENT_CANARY)
    (source / "empty").write_bytes(b"")
    return source, work


def _assert_no_workspace(work):
    assert not any(path.name.startswith(snap._WORKSPACE_PREFIX) for path in work.iterdir())


def test_hard_maxima_are_exact_and_defaults_do_not_exceed_them():
    assert snap._MAX_SOURCE_FILES == 20_000
    assert snap._MAX_SOURCE_DIRECTORIES == 10_000
    assert snap._MAX_RELATIVE_DEPTH == 16
    assert snap._MAX_SINGLE_FILE_BYTES == 16 * 1024**3
    assert snap._MAX_SOURCE_BYTES == 64 * 1024**3
    assert snap._MAX_WORK_FILES == 21_000
    assert snap._MAX_WORK_BYTES == 72 * 1024**3
    assert snap._COPY_CHUNK_BYTES == 1024**2
    assert snap._PREPARE_DEADLINE_SECONDS == 1_800
    assert snap._CLEANUP_DEADLINE_SECONDS == 600
    assert snap._DEFAULT_LIMITS == snap._Limits()


@pytest.mark.parametrize(
    "field",
    [
        "source_files",
        "source_directories",
        "relative_depth",
        "single_file_bytes",
        "source_bytes",
        "work_files",
        "work_bytes",
        "chunk_bytes",
        "prepare_seconds",
        "cleanup_seconds",
    ],
)
def test_limits_may_only_narrow_hard_maxima(field):
    maximum = getattr(snap._DEFAULT_LIMITS, field)
    with pytest.raises(snap._SnapshotPreparationError) as caught:
        snap._Limits(**{field: maximum + 1})
    assert str(caught.value) == STATIC_PREPARATION
    with pytest.raises(snap._SnapshotPreparationError):
        snap._Limits(**{field: True})


def test_successful_copy_is_private_exact_restrictive_and_fully_cleaned(tmp_path):
    source, work = _tree(tmp_path)
    source_before = {
        path.relative_to(source): (path.stat().st_size, path.read_bytes())
        for path in source.rglob("*")
        if path.is_file()
    }

    lease = snap._prepare_snapshot(source, work)

    assert repr(lease) == "<RAGLeakGuard private prepared snapshot: redacted>"
    assert SOURCE_CANARY not in repr(lease)
    assert lease.data_path.joinpath("nested", "record.bin").read_bytes() == CONTENT_CANARY
    assert lease.data_path.joinpath("empty").read_bytes() == b""
    if os.name != "nt":
        assert stat.S_IMODE(lease.data_path.stat().st_mode) == 0o700
        assert stat.S_IMODE(lease.data_path.joinpath("nested").stat().st_mode) == 0o700
        assert stat.S_IMODE(lease.data_path.joinpath("empty").stat().st_mode) == 0o600
    source_after = {
        path.relative_to(source): (path.stat().st_size, path.read_bytes())
        for path in source.rglob("*")
        if path.is_file()
    }
    assert source_after == source_before

    lease.cleanup()
    lease.cleanup()
    _assert_no_workspace(work)


def test_context_manager_cleans_after_consumer_failure(tmp_path):
    source, work = _tree(tmp_path)
    with pytest.raises(RuntimeError, match="synthetic consumer"):
        with snap._prepare_snapshot(source, work) as lease:
            assert lease.data_path.exists()
            raise RuntimeError("synthetic consumer")
    _assert_no_workspace(work)


def test_control_documents_are_authenticated_and_contain_no_source_canaries(tmp_path):
    source, work = _tree(tmp_path)
    lease = snap._prepare_snapshot(source, work)
    workspace = lease._workspace
    snapshot = lease._snapshot
    controls = (
        workspace / snap._WORKSPACE_KEY,
        workspace / snap._WORKSPACE_MARKER,
        snapshot / snap._SNAPSHOT_MARKER,
    )
    lease_encoded = snap._read_locked_lease(
        lease._lock, 4096, snap._SnapshotCleanupError
    )
    serialized = b"".join(path.read_bytes() for path in controls) + lease_encoded
    assert SOURCE_CANARY.encode() not in serialized
    assert CONTENT_CANARY not in serialized
    assert b"record.bin" not in serialized
    assert b"nested" not in serialized
    for path in controls:
        assert json.loads(path.read_text(encoding="ascii"))
        if os.name != "nt":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(lease_encoded.decode("ascii"))
    if os.name != "nt":
        assert stat.S_IMODE((snapshot / snap._LEASE_FILE).stat().st_mode) == 0o600
    lease.cleanup()


@pytest.mark.parametrize("relation", ["same", "source-under-work", "work-under-source"])
def test_source_and_work_containment_overlap_is_rejected_without_residue(tmp_path, relation):
    root = tmp_path / "root"
    root.mkdir()
    if relation == "same":
        source = work = root
    elif relation == "source-under-work":
        work = root
        source = root / "source"
        source.mkdir()
    else:
        source = root
        work = root / "work"
        work.mkdir()
    before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
    with pytest.raises(snap._SnapshotPreparationError) as caught:
        snap._prepare_snapshot(source, work)
    assert str(caught.value) == STATIC_PREPARATION
    assert sorted(str(path.relative_to(root)) for path in root.rglob("*")) == before


def test_symlink_and_hardlink_sources_fail_before_work_creation(tmp_path):
    source, work = _tree(tmp_path)
    target = source / "target"
    target.write_bytes(b"synthetic")
    hardlink = source / "hardlink"
    try:
        os.link(target, hardlink)
    except (OSError, NotImplementedError):
        pytest.skip("native filesystem does not permit hard links")
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)

    hardlink.unlink()
    link = source / "link"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("native filesystem does not permit symbolic links")
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)


def test_symlinked_source_root_and_work_parent_are_rejected(tmp_path):
    source, work = _tree(tmp_path)
    source_link = tmp_path / "source-link"
    work_link = tmp_path / "work-link"
    try:
        source_link.symlink_to(source, target_is_directory=True)
        work_link.symlink_to(work, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("native filesystem does not permit directory symbolic links")
    for source_value, work_value in ((source_link, work), (source, work_link)):
        with pytest.raises(snap._SnapshotPreparationError):
            snap._prepare_snapshot(source_value, work_value)
    _assert_no_workspace(work)


@pytest.mark.skipif(os.name == "nt", reason="FIFO object type is POSIX-specific")
def test_unsupported_fifo_object_fails_closed(tmp_path):
    source, work = _tree(tmp_path)
    os.mkfifo(source / "unsupported-fifo")
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)


def test_sparse_source_is_rejected_without_materializing_it(tmp_path):
    source, work = _tree(tmp_path)
    sparse = source / "sparse.bin"
    with sparse.open("wb") as handle:
        handle.seek(8 * 1024**2)
        handle.write(b"x")
    raw = sparse.stat()
    sparse_evidence = bool(
        getattr(raw, "st_file_attributes", 0)
        & int(getattr(stat, "FILE_ATTRIBUTE_SPARSE_FILE", 0x200))
    ) or bool(getattr(raw, "st_blocks", raw.st_size * 2) * 512 < raw.st_size)
    if not sparse_evidence:
        pytest.skip("native filesystem did not create a sparse file")
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate data streams are Windows-specific")
def test_ntfs_alternate_data_stream_is_rejected(tmp_path):
    source, work = _tree(tmp_path)
    target = source / "streamed.bin"
    target.write_bytes(b"main")
    try:
        with open(str(target) + ":private-stream", "wb") as stream:
            stream.write(b"hidden")
    except OSError:
        pytest.skip("native volume does not support alternate data streams")
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)


@pytest.mark.skipif(os.name != "nt", reason="directory reparse evidence is Windows-specific")
def test_windows_directory_reparse_point_is_rejected(tmp_path):
    source, work = _tree(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    junction = source / "junction"
    try:
        os.symlink(outside, junction, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("runner does not permit directory reparse-point creation")
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)


def test_cross_device_entry_is_rejected(monkeypatch, tmp_path):
    source, work = _tree(tmp_path)
    target = source / "nested" / "record.bin"
    real_lstat = snap._lstat

    def cross_device(path, error_type=snap._SnapshotPreparationError):
        raw = real_lstat(path, error_type)
        if Path(path) == target:
            return SimpleNamespace(
                st_dev=raw.st_dev + 1,
                st_ino=raw.st_ino,
                st_mode=raw.st_mode,
                st_nlink=raw.st_nlink,
                st_size=raw.st_size,
                st_mtime_ns=raw.st_mtime_ns,
                st_ctime_ns=raw.st_ctime_ns,
                st_uid=getattr(raw, "st_uid", None),
                st_gid=getattr(raw, "st_gid", None),
                st_blocks=getattr(raw, "st_blocks", None),
                st_file_attributes=getattr(raw, "st_file_attributes", 0),
            )
        return raw

    monkeypatch.setattr(snap, "_lstat", cross_device)
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)


@pytest.mark.parametrize(
    ("limits", "builder"),
    [
        (snap._Limits(source_files=1), lambda source: (source / "second").write_bytes(b"x")),
        (snap._Limits(source_directories=1), lambda source: (source / "second-dir").mkdir()),
        (
            snap._Limits(relative_depth=1),
            lambda source: ((source / "level").mkdir(), (source / "level" / "too-deep").write_bytes(b"x")),
        ),
        (
            snap._Limits(single_file_bytes=1),
            lambda source: (source / "oversized").write_bytes(b"xx"),
        ),
        (
            snap._Limits(single_file_bytes=2, source_bytes=2),
            lambda source: (source / "aggregate").write_bytes(b"xx"),
        ),
    ],
    ids=["files", "directories", "depth", "single-file", "aggregate-bytes"],
)
def test_source_bounds_fail_closed(limits, builder, tmp_path):
    source = tmp_path / SOURCE_CANARY
    work = tmp_path / "work"
    source.mkdir()
    work.mkdir()
    (source / "first").write_bytes(b"x")
    builder(source)
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work, limits=limits)
    _assert_no_workspace(work)


def test_work_file_and_byte_bounds_fail_closed(monkeypatch, tmp_path):
    source = tmp_path / SOURCE_CANARY
    work = tmp_path / "work"
    source.mkdir()
    work.mkdir()
    (source / "one").write_bytes(b"x")
    (source / "two").write_bytes(b"y")
    with pytest.raises(snap._SnapshotPreparationError):
        snap._Limits(source_files=2, work_files=5)
    _assert_no_workspace(work)

    limits = snap._Limits(
        source_files=2,
        single_file_bytes=1,
        source_bytes=2,
        work_files=7,
        work_bytes=snap._CONTROL_BYTE_ALLOWANCE + 2,
    )
    monkeypatch.setattr(snap, "_CONTROL_BYTE_ALLOWANCE", 1)
    object.__setattr__(limits, "work_bytes", 3)
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work, limits=limits)
    _assert_no_workspace(work)


def test_insufficient_free_space_fails_before_workspace_creation(monkeypatch, tmp_path):
    source, work = _tree(tmp_path)
    monkeypatch.setattr(snap, "_disk_free_bytes", lambda path: 0)
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)


def test_deadline_and_cancellation_are_static_and_leave_no_residue(tmp_path):
    source, work = _tree(tmp_path)
    ticks = iter((0.0, 2.0))
    with pytest.raises(snap._SnapshotPreparationError) as caught:
        snap._prepare_snapshot(
            source,
            work,
            limits=snap._Limits(prepare_seconds=1),
            clock=lambda: next(ticks),
        )
    assert str(caught.value) == STATIC_PREPARATION
    _assert_no_workspace(work)


def test_bad_randomness_and_injected_io_fsync_replace_failures_are_static(
    monkeypatch, tmp_path
):
    source, work = _tree(tmp_path)
    for token_source in (
        lambda size: b"short",
        lambda size: (_ for _ in ()).throw(RuntimeError("randomness-canary")),
    ):
        with pytest.raises(snap._SnapshotPreparationError) as caught:
            snap._prepare_snapshot(source, work, token_source=token_source)
        assert str(caught.value) == STATIC_PREPARATION
        assert "randomness-canary" not in str(caught.value)
        _assert_no_workspace(work)

    real_fsync = snap.os.fsync
    fsync_calls = 0

    def fail_one_fsync(descriptor):
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 1:
            raise OSError("fsync-exception-canary")
        return real_fsync(descriptor)

    monkeypatch.setattr(snap.os, "fsync", fail_one_fsync)
    with pytest.raises(snap._SnapshotPreparationError) as caught:
        snap._prepare_snapshot(source, work)
    assert "fsync-exception-canary" not in str(caught.value)
    _assert_no_workspace(work)
    monkeypatch.setattr(snap.os, "fsync", real_fsync)

    real_replace = snap.os.replace
    replace_calls = 0

    def fail_one_replace(source_path, destination_path):
        nonlocal replace_calls
        replace_calls += 1
        if replace_calls == 1:
            raise OSError("replace-exception-canary")
        return real_replace(source_path, destination_path)

    monkeypatch.setattr(snap.os, "replace", fail_one_replace)
    with pytest.raises(snap._SnapshotPreparationError) as caught:
        snap._prepare_snapshot(source, work)
    assert "replace-exception-canary" not in str(caught.value)
    _assert_no_workspace(work)

    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work, cancelled=lambda: True)
    _assert_no_workspace(work)


def test_source_replacement_race_is_detected_before_read(monkeypatch, tmp_path):
    source, work = _tree(tmp_path)
    target = source / "nested" / "record.bin"
    real_open = snap._open_source_file
    replaced = False

    def racing_open(path, expected):
        nonlocal replaced
        if Path(path) == target and not replaced:
            replaced = True
            target.unlink()
            target.write_bytes(b"replacement-content")
        return real_open(path, expected)

    monkeypatch.setattr(snap, "_open_source_file", racing_open)
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)


def test_source_mutation_and_torn_work_copy_are_detected(monkeypatch, tmp_path):
    source, work = _tree(tmp_path)
    target = source / "nested" / "record.bin"
    real_copy = snap._copy_file

    def mutate_source(*args, **kwargs):
        digest = real_copy(*args, **kwargs)
        target.write_bytes(b"changed-source-content")
        return digest

    monkeypatch.setattr(snap, "_copy_file", mutate_source)
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)

    target.write_bytes(CONTENT_CANARY)

    def tear_copy(source_path, destination, *args, **kwargs):
        digest = real_copy(source_path, destination, *args, **kwargs)
        destination.write_bytes(b"torn-work-copy")
        return digest

    monkeypatch.setattr(snap, "_copy_file", tear_copy)
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)


def test_permission_establishment_failure_cleans_created_workspace(monkeypatch, tmp_path):
    source, work = _tree(tmp_path)
    real_harden = snap._harden

    def fail_payload(path, directory):
        if Path(path).name == snap._PAYLOAD_DIRECTORY:
            raise snap._SnapshotPreparationError()
        return real_harden(path, directory)

    monkeypatch.setattr(snap, "_harden", fail_payload)
    with pytest.raises(snap._SnapshotPreparationError):
        snap._prepare_snapshot(source, work)
    _assert_no_workspace(work)


def test_cleanup_requires_intact_authenticated_ownership_and_never_touches_siblings(tmp_path):
    source, work = _tree(tmp_path)
    sibling = work / "operator-owned-sibling"
    sibling.write_bytes(b"preserve")
    lease = snap._prepare_snapshot(source, work)
    marker = lease._snapshot / snap._SNAPSHOT_MARKER
    marker.write_text("{}", encoding="ascii")
    with pytest.raises(snap._SnapshotCleanupError) as caught:
        lease.cleanup()
    assert str(caught.value) == STATIC_CLEANUP
    assert sibling.read_bytes() == b"preserve"
    assert lease._workspace.exists()


def test_cleanup_cancellation_and_injected_failure_leave_recoverable_ownership(tmp_path, monkeypatch):
    source, work = _tree(tmp_path)
    lease = snap._prepare_snapshot(source, work)
    with pytest.raises(snap._SnapshotCleanupError):
        lease.cleanup(cancelled=lambda: True)
    assert lease._workspace.exists()

    real_remove = snap._safe_remove_tree
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise snap._SnapshotCleanupError()
        return real_remove(*args, **kwargs)

    monkeypatch.setattr(snap, "_safe_remove_tree", fail_once)
    with pytest.raises(snap._SnapshotCleanupError):
        lease.cleanup()
    assert lease._workspace.exists()
    monkeypatch.setattr(snap, "_safe_remove_tree", real_remove)
    lease.cleanup()
    _assert_no_workspace(work)


def test_cleanup_deadline_expiry_retains_owned_residue_then_retry_succeeds(tmp_path):
    source, work = _tree(tmp_path)
    lease = snap._prepare_snapshot(
        source,
        work,
        limits=snap._Limits(cleanup_seconds=1),
    )
    ticks = iter((0.0, 2.0))
    with pytest.raises(snap._SnapshotCleanupError) as caught:
        lease.cleanup(
            clock=lambda: next(ticks),
        )
    assert str(caught.value) == STATIC_CLEANUP
    assert lease._workspace.exists()
    lease.cleanup()
    _assert_no_workspace(work)


def test_recovery_refuses_active_lease_then_removes_inactive_owned_residue(tmp_path):
    source, work = _tree(tmp_path)
    lease = snap._prepare_snapshot(source, work)
    with pytest.raises(snap._SnapshotRecoveryError) as caught:
        snap._recover_snapshots(work)
    assert str(caught.value) == STATIC_RECOVERY
    assert lease._workspace.exists()

    lease._lock.close()
    lease._closed = True
    assert snap._recover_snapshots(work) == 1
    _assert_no_workspace(work)
    assert snap._recover_snapshots(work) == 0


def test_recovery_refuses_forged_or_corrupt_matching_workspace(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    forged = work / (snap._WORKSPACE_PREFIX + "0" * 32)
    forged.mkdir()
    (forged / "important").write_bytes(b"do-not-delete")
    with pytest.raises(snap._SnapshotRecoveryError):
        snap._recover_snapshots(work)
    assert forged.joinpath("important").read_bytes() == b"do-not-delete"


@pytest.mark.parametrize("control", ["workspace", "snapshot", "lease"])
def test_authenticated_control_schema_rejects_boolean_versions(tmp_path, control):
    source, work = _tree(tmp_path)
    lease = snap._prepare_snapshot(source, work)
    paths = {
        "workspace": lease._workspace / snap._WORKSPACE_MARKER,
        "snapshot": lease._snapshot / snap._SNAPSHOT_MARKER,
        "lease": lease._snapshot / snap._LEASE_FILE,
    }
    path = paths[control]
    lease._lock.close()
    lease._closed = True
    document = json.loads(path.read_text(encoding="ascii"))
    document.pop("authentication")
    document["version"] = True
    encoded = snap._authenticated_document(lease._key, document)
    path.write_bytes(encoded)
    with pytest.raises(snap._SnapshotRecoveryError):
        snap._recover_snapshots(work)
    assert lease._workspace.exists()


def test_process_termination_leaves_authenticated_residue_that_recovery_can_remove(tmp_path):
    source, work = _tree(tmp_path)
    code = (
        "import os,sys; from ragleakguard import _snapshot as s; "
        "s._prepare_snapshot(sys.argv[1], sys.argv[2]); os._exit(0)"
    )
    environment = dict(os.environ)
    package_root = str(Path(__file__).resolve().parents[1] / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        value for value in (package_root, environment.get("PYTHONPATH")) if value
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(source), str(work)],
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == b"" and result.stderr == b""
    assert snap._recover_snapshots(work) == 1
    _assert_no_workspace(work)


def test_private_lifecycle_imports_no_chroma_opens_no_socket_and_emits_no_output(
    monkeypatch, tmp_path, capsys
):
    source, work = _tree(tmp_path)
    real_import = builtins.__import__
    imports = []
    network = []

    def guarded_import(name, *args, **kwargs):
        if name == "chromadb" or name.startswith("chromadb."):
            imports.append(name)
            raise AssertionError("Chroma import attempted")
        return real_import(name, *args, **kwargs)

    def forbidden_network(*args, **kwargs):
        network.append((args, kwargs))
        raise AssertionError("network attempted")

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(socket, "socket", forbidden_network)
    monkeypatch.setattr(socket, "create_connection", forbidden_network)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden_network)
    lease = snap._prepare_snapshot(source, work)
    lease.cleanup()
    assert imports == [] and network == []
    assert capsys.readouterr() == ("", "")


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL inspection is Windows-specific")
def test_windows_work_copy_dacl_is_protected_and_identity_allowlisted(tmp_path):
    source, work = _tree(tmp_path)
    lease = snap._prepare_snapshot(source, work)
    script = r"""
$ErrorActionPreference = 'Stop'
$acl = Get-Acl -LiteralPath $args[0]
if (-not $acl.AreAccessRulesProtected) { exit 10 }
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($current, 'S-1-5-18', 'S-1-5-32-544')
foreach ($rule in $acl.Access) {
  $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
  if ($rule.AccessControlType -ne 'Allow' -or $allowed -notcontains $sid) { exit 11 }
}
"""
    script_path = tmp_path / "inspect-dacl.ps1"
    script_path.write_text(script, encoding="utf-8")
    for path in (
        lease._workspace,
        lease._snapshot,
        lease.data_path,
        lease.data_path / "nested" / "record.bin",
    ):
        result = subprocess.run(
            [
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(script_path),
                str(path),
            ],
            capture_output=True,
            timeout=20,
            check=False,
        )
        assert result.returncode == 0
        assert result.stdout == b"" and result.stderr == b""
    lease.cleanup()


def test_all_failure_surfaces_are_static_and_exclude_paths_exception_and_content(tmp_path):
    source, work = _tree(tmp_path)
    hostile = work / SOURCE_CANARY
    with pytest.raises(snap._SnapshotPreparationError) as caught:
        snap._prepare_snapshot(hostile, work)
    rendered = "".join(
        (str(caught.value), repr(caught.value), " ".join(map(str, caught.value.args)))
    )
    assert str(caught.value) == STATIC_PREPARATION
    assert SOURCE_CANARY not in rendered
    assert CONTENT_CANARY.decode() not in rendered


def test_no_public_connector_cli_or_package_surface_uses_snapshot_primitives(tmp_path):
    import ragleakguard

    assert snap.__all__ == ()
    assert not any(
        "snapshot" in name.lower() and not name.startswith("_")
        for name in vars(ragleakguard)
    )
    assert connectors.read_chroma.__module__ == "ragleakguard.connectors"
    with pytest.raises(connectors.ChromaConnectorUnavailableError):
        connectors.read_chroma(object())
    for command in ("scan", "monitor"):
        result = CliRunner().invoke(cli.app, [command, "--help"])
        output = " ".join(unstyle(result.output).split()).lower()
        assert result.exit_code == 0
        assert "snapshot" not in output
        assert "6 = direct chroma scanning disabled" in output


def test_private_module_exports_no_public_callable_or_class():
    assert snap.__all__ == ()
    exposed = {
        name
        for name, value in vars(snap).items()
        if getattr(value, "__module__", None) == snap.__name__
        and (inspect.isfunction(value) or inspect.isclass(value))
        and not name.startswith("_")
    }
    assert exposed == set()


def test_wp7b_docs_preserve_activation_gate_bounds_and_nonclaims():
    root = Path(__file__).resolve().parents[1]
    architecture = (root / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    threat = (root / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    contributing = (root / "CONTRIBUTING.md").read_text(encoding="utf-8")
    combined = "\n".join((architecture, threat, contributing))

    for exact in (
        "20,000",
        "10,000",
        "16 GiB",
        "64 GiB",
        "21,000",
        "72 GiB",
        "1 MiB",
        "1,800 seconds",
        "600 seconds",
        "No source-scanning connector is currently available",
        "does not import or construct Chroma",
        "do not create or prove transactionally atomic multi-file snapshot isolation",
        "Cleanup is deletion, not certified erasure",
        "separate issue",
        "independent review",
        "human authorization",
    ):
        assert exact in combined
    assert "private WP7B lifecycle is not a connector" in architecture
    assert "Snapshot-backed Chroma scanning remains unavailable" in contributing


def test_ci_requires_current_native_ext4_apfs_ntfs_matrix_without_chroma_extra():
    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
    ).read_text(encoding="utf-8")
    for exact in (
        "ubuntu-latest",
        "macos-15",
        "windows-latest",
        "filesystem: ext4",
        "filesystem: APFS",
        "filesystem: NTFS",
        "mkfs.ext4",
        "RLG_REQUIRE_NATIVE_SNAPSHOT_FS: \"1\"",
        '.[detect,dev]',
    ):
        assert exact in workflow
    assert ".[chroma" not in workflow.lower()


def _native_filesystem(path):
    if sys.platform.startswith("linux"):
        result = subprocess.run(
            ["stat", "-f", "-c", "%T", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return result.stdout.strip()
    if sys.platform == "darwin":
        mounted = subprocess.run(
            ["/bin/df", "-P", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        device = mounted.stdout.strip().splitlines()[-1].split()[0]
        result = subprocess.run(
            ["/usr/sbin/diskutil", "info", "-plist", device],
            capture_output=True,
            timeout=20,
            check=True,
        )
        document = plistlib.loads(result.stdout)
        return document.get("FilesystemType") or document.get("TypeBundle")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        volume = ctypes.create_unicode_buffer(64)
        root = Path(path).resolve().anchor
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            wintypes.LPCWSTR(root), None, 0, None, None, None, volume, len(volume)
        )
        if not ok:
            raise OSError(ctypes.get_last_error())
        return volume.value
    return "unsupported"


@pytest.mark.skipif(
    os.environ.get("RLG_REQUIRE_NATIVE_SNAPSHOT_FS") != "1",
    reason="exact native filesystem assertion is enabled only by the WP7B CI matrix",
)
def test_ci_runs_on_the_required_native_filesystem(tmp_path):
    observed = _native_filesystem(tmp_path).lower()
    if sys.platform.startswith("linux"):
        assert observed in {"ext2/ext3", "ext4"}
    elif sys.platform == "darwin":
        assert "apfs" in observed
    elif os.name == "nt":
        assert observed == "ntfs"
    else:
        pytest.fail("WP7B CI requires Linux, macOS, or Windows")
