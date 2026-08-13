"""Private, bounded filesystem confinement for operator-created snapshots.

This module is deliberately private.  It does not import Chroma, expose a connector,
or establish that an operator-created snapshot is quiescent or transactionally
consistent.  Its only contract is the bounded filesystem lifecycle exercised by
WP7B's tests.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shutil
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional, Tuple


_MAX_SOURCE_FILES = 20_000
_MAX_SOURCE_DIRECTORIES = 10_000
_MAX_RELATIVE_DEPTH = 16
_MAX_SINGLE_FILE_BYTES = 16 * 1024**3
_MAX_SOURCE_BYTES = 64 * 1024**3
_MAX_WORK_FILES = 21_000
_MAX_WORK_BYTES = 72 * 1024**3
_COPY_CHUNK_BYTES = 1024**2
_PREPARE_DEADLINE_SECONDS = 1_800
_CLEANUP_DEADLINE_SECONDS = 600
_FREE_SPACE_MARGIN_BYTES = 16 * 1024**2

_WORKSPACE_PREFIX = ".rlg-snapshot-workspace-"
_SNAPSHOT_PREFIX = ".rlg-snapshot-"
_WORKSPACE_KEY = ".rlg-workspace-key.json"
_WORKSPACE_MARKER = ".rlg-workspace-owner.json"
_SNAPSHOT_MARKER = ".rlg-snapshot-owner.json"
_LEASE_FILE = ".rlg-snapshot-lease.json"
_PAYLOAD_DIRECTORY = "data"
_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
_AUTH_RE = re.compile(r"^[0-9a-f]{64}$")
_WORKSPACE_CONSTRUCTION = "RLG-SNAPSHOT-WORKSPACE-HMAC-SHA256-v1"
_SNAPSHOT_CONSTRUCTION = "RLG-SNAPSHOT-OWNER-HMAC-SHA256-v1"
_LEASE_CONSTRUCTION = "RLG-SNAPSHOT-LEASE-HMAC-SHA256-v1"
_PERSISTENT_CONTROL_FILES = 4
_CONTROL_FILE_ALLOWANCE = 5
_CONTROL_BYTE_ALLOWANCE = 16 * 1024
_MAX_CLEANUP_OBJECTS = _MAX_WORK_FILES + _MAX_SOURCE_DIRECTORIES + 4
_MAX_CLEANUP_DEPTH = _MAX_RELATIVE_DEPTH + 4
_WINDOWS_PATH_HANDLE_CTIME_DIVERGES = os.name == "nt"


class _SnapshotError(RuntimeError):
    """Base class whose messages never include caller-controlled values."""


class _SnapshotPreparationError(_SnapshotError):
    def __init__(self) -> None:
        super().__init__("Snapshot confinement preparation failed.")


class _SnapshotCleanupError(_SnapshotError):
    def __init__(self) -> None:
        super().__init__("Snapshot confinement cleanup failed; residue may remain.")


class _SnapshotRecoveryError(_SnapshotError):
    def __init__(self) -> None:
        super().__init__("Snapshot confinement recovery failed closed.")


def _scrub_exception_chain(error: _SnapshotError) -> _SnapshotError:
    """Detach every retained exception that could carry operator-controlled data."""
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
class _Limits:
    source_files: int = _MAX_SOURCE_FILES
    source_directories: int = _MAX_SOURCE_DIRECTORIES
    relative_depth: int = _MAX_RELATIVE_DEPTH
    single_file_bytes: int = _MAX_SINGLE_FILE_BYTES
    source_bytes: int = _MAX_SOURCE_BYTES
    work_files: int = _MAX_WORK_FILES
    work_bytes: int = _MAX_WORK_BYTES
    chunk_bytes: int = _COPY_CHUNK_BYTES
    prepare_seconds: int = _PREPARE_DEADLINE_SECONDS
    cleanup_seconds: int = _CLEANUP_DEADLINE_SECONDS

    def __post_init__(self) -> None:
        maxima = (
            (self.source_files, _MAX_SOURCE_FILES),
            (self.source_directories, _MAX_SOURCE_DIRECTORIES),
            (self.relative_depth, _MAX_RELATIVE_DEPTH),
            (self.single_file_bytes, _MAX_SINGLE_FILE_BYTES),
            (self.source_bytes, _MAX_SOURCE_BYTES),
            (self.work_files, _MAX_WORK_FILES),
            (self.work_bytes, _MAX_WORK_BYTES),
            (self.chunk_bytes, _COPY_CHUNK_BYTES),
            (self.prepare_seconds, _PREPARE_DEADLINE_SECONDS),
            (self.cleanup_seconds, _CLEANUP_DEADLINE_SECONDS),
        )
        if any(type(value) is not int or value <= 0 or value > maximum for value, maximum in maxima):
            raise _SnapshotPreparationError()
        if self.work_files < self.source_files + _CONTROL_FILE_ALLOWANCE:
            raise _SnapshotPreparationError()
        if self.work_bytes < self.source_bytes + _CONTROL_BYTE_ALLOWANCE:
            raise _SnapshotPreparationError()


_DEFAULT_LIMITS = _Limits()


@dataclass(frozen=True)
class _Identity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    birth_ns: Optional[int]
    uid: Optional[int]
    gid: Optional[int]
    file_attributes: int


@dataclass(frozen=True)
class _Entry:
    parts: Tuple[str, ...]
    is_directory: bool
    identity: _Identity


@dataclass(frozen=True)
class _Inventory:
    root: Path
    root_identity: _Identity
    entries: Tuple[_Entry, ...]
    files: int
    directories: int
    total_bytes: int


@dataclass
class _RemovalBudget:
    objects: int = 0


def _canonical_json(value: dict) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _authentication(key: bytes, body: dict) -> str:
    return hmac.new(key, _canonical_json(body), hashlib.sha256).hexdigest()


def _authenticated_document(key: bytes, body: dict) -> bytes:
    document = dict(body)
    document["authentication"] = _authentication(key, body)
    return _canonical_json(document)


def _identity(value: os.stat_result) -> _Identity:
    return _Identity(
        device=int(value.st_dev),
        inode=int(value.st_ino),
        mode=int(value.st_mode),
        links=int(value.st_nlink),
        size=int(value.st_size),
        modified_ns=int(value.st_mtime_ns),
        changed_ns=int(value.st_ctime_ns),
        birth_ns=(
            int(value.st_birthtime_ns)
            if getattr(value, "st_birthtime_ns", None) is not None
            else None
        ),
        uid=int(value.st_uid) if hasattr(value, "st_uid") else None,
        gid=int(value.st_gid) if hasattr(value, "st_gid") else None,
        file_attributes=int(getattr(value, "st_file_attributes", 0)),
    )


def _is_reparse(identity: _Identity) -> bool:
    flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(identity.file_attributes & flag)


def _is_sparse(identity: _Identity, raw: os.stat_result) -> bool:
    sparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_SPARSE_FILE", 0x200))
    if identity.file_attributes & sparse_flag:
        return True
    blocks = getattr(raw, "st_blocks", None)
    return bool(identity.size and blocks is not None and int(blocks) * 512 < identity.size)


def _same_identity(left: _Identity, right: _Identity) -> bool:
    return left == right


def _same_path_handle_identity(path: _Identity, handle: _Identity) -> bool:
    """Correlate lstat/fstat without mixing Windows' incompatible ctime families.

    Every caller must also compare lstat-to-lstat and fstat-to-fstat with
    ``_same_identity`` so replacement and mutation checks retain the full signal.
    """
    if not _WINDOWS_PATH_HANDLE_CTIME_DIVERGES:
        return _same_identity(path, handle)
    return (
        path.device == handle.device
        and path.inode == handle.inode
        and path.mode == handle.mode
        and path.links == handle.links
        and path.size == handle.size
        and path.modified_ns == handle.modified_ns
        and path.birth_ns == handle.birth_ns
        and path.uid == handle.uid
        and path.gid == handle.gid
        and path.file_attributes == handle.file_attributes
    )


def _same_object(left: _Identity, right: _Identity) -> bool:
    return (
        left.device == right.device
        and left.inode == right.inode
        and stat.S_IFMT(left.mode) == stat.S_IFMT(right.mode)
    )


def _new_token(source: Callable[[int], bytes]) -> str:
    try:
        value = source(16)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise _SnapshotPreparationError() from None
    if not isinstance(value, bytes) or len(value) != 16:
        raise _SnapshotPreparationError()
    return value.hex()


def _coerce_path(
    value: object,
    error_type: type[_SnapshotError] = _SnapshotPreparationError,
) -> Path:
    try:
        raw = os.fspath(value)
        if not isinstance(raw, (str, bytes)) or b"\x00" in os.fsencode(raw):
            raise ValueError
        return Path(os.fsdecode(raw))
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise error_type() from None


def _resolved(
    path: Path,
    error_type: type[_SnapshotError] = _SnapshotPreparationError,
) -> Path:
    try:
        return Path(os.path.realpath(os.fspath(path)))
    except (OSError, ValueError, TypeError):
        raise error_type() from None


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        common = os.path.commonpath((os.path.normcase(str(first)), os.path.normcase(str(second))))
    except (OSError, ValueError):
        return False
    return common in {os.path.normcase(str(first)), os.path.normcase(str(second))}


def _check_control(
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
    error_type: type[_SnapshotError],
) -> None:
    try:
        now = clock()
        is_cancelled = bool(cancelled()) if cancelled is not None else False
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise error_type() from None
    if (
        not isinstance(now, (int, float))
        or isinstance(now, bool)
        or not math.isfinite(float(now))
        or float(now) > deadline
        or is_cancelled
    ):
        raise error_type()


def _deadline(seconds: int, clock: Callable[[], float], error_type: type[_SnapshotError]) -> float:
    try:
        start = clock()
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise error_type() from None
    if (
        not isinstance(start, (int, float))
        or isinstance(start, bool)
        or not math.isfinite(float(start))
    ):
        raise error_type()
    value = float(start) + seconds
    if not math.isfinite(value):
        raise error_type()
    return value


def _lstat(path: Path, error_type: type[_SnapshotError] = _SnapshotPreparationError) -> os.stat_result:
    try:
        return os.lstat(path)
    except (OSError, ValueError, TypeError):
        raise error_type() from None


def _validate_directory(
    path: Path,
    *,
    device: Optional[int] = None,
    error_type: type[_SnapshotError] = _SnapshotPreparationError,
) -> _Identity:
    raw = _lstat(path, error_type)
    identity = _identity(raw)
    if not stat.S_ISDIR(identity.mode) or stat.S_ISLNK(identity.mode) or _is_reparse(identity):
        raise error_type()
    if device is not None and identity.device != device:
        raise error_type()
    return identity


def _strict_directory_path(
    value: object,
    error_type: type[_SnapshotError] = _SnapshotPreparationError,
) -> tuple[Path, _Identity]:
    supplied = _coerce_path(value, error_type)
    try:
        absolute = Path(os.path.abspath(os.fspath(supplied)))
    except (OSError, ValueError, TypeError):
        raise error_type() from None
    identity = _validate_directory(absolute, error_type=error_type)
    resolved = _resolved(absolute, error_type)
    if os.path.normcase(str(absolute)) != os.path.normcase(str(resolved)):
        raise error_type()
    if not _same_identity(_validate_directory(resolved, error_type=error_type), identity):
        raise error_type()
    return resolved, identity


def _validate_component(name: str) -> None:
    if not name or name in {".", ".."} or "\x00" in name:
        raise _SnapshotPreparationError()
    if os.sep in name or (os.altsep and os.altsep in name):
        raise _SnapshotPreparationError()
    if os.name == "nt" and (":" in name or name[-1:] in {" ", "."}):
        raise _SnapshotPreparationError()


def _windows_has_named_streams(path: Path) -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class WIN32_FIND_STREAM_DATA(ctypes.Structure):
            _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", wintypes.WCHAR * 296)]

        data = WIN32_FIND_STREAM_DATA()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        find_first = kernel32.FindFirstStreamW
        find_first.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(WIN32_FIND_STREAM_DATA), wintypes.DWORD)
        find_first.restype = wintypes.HANDLE
        find_next = kernel32.FindNextStreamW
        find_next.argtypes = (wintypes.HANDLE, ctypes.POINTER(WIN32_FIND_STREAM_DATA))
        find_next.restype = wintypes.BOOL
        close = kernel32.FindClose
        close.argtypes = (wintypes.HANDLE,)
        close.restype = wintypes.BOOL
        handle = find_first(str(path), 0, ctypes.byref(data), 0)
        invalid = wintypes.HANDLE(-1).value
        if handle == invalid:
            error = ctypes.get_last_error()
            if error == 38:  # ERROR_HANDLE_EOF: no data stream to enumerate
                return False
            raise OSError(error)
        names = []
        try:
            names.append(data.cStreamName)
            while find_next(handle, ctypes.byref(data)):
                names.append(data.cStreamName)
            error = ctypes.get_last_error()
            if error not in (0, 38):  # ERROR_HANDLE_EOF
                raise OSError(error)
        finally:
            close(handle)
        return any(name != "::$DATA" for name in names)
    except (OSError, AttributeError, ValueError, TypeError):
        raise _SnapshotPreparationError() from None


def _inventory(
    source: Path,
    limits: _Limits,
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
) -> _Inventory:
    root_raw = _lstat(source)
    root_identity = _identity(root_raw)
    if not stat.S_ISDIR(root_identity.mode) or stat.S_ISLNK(root_identity.mode) or _is_reparse(root_identity):
        raise _SnapshotPreparationError()
    if _windows_has_named_streams(source):
        raise _SnapshotPreparationError()
    root_device = root_identity.device
    entries = []
    files = 0
    directories = 1
    total_bytes = 0
    if directories > limits.source_directories:
        raise _SnapshotPreparationError()
    pending = [(source, tuple(), root_identity)]

    while pending:
        _check_control(deadline, clock, cancelled, _SnapshotPreparationError)
        current, current_parts, expected_directory = pending.pop()
        if not _same_identity(_validate_directory(current, device=root_device), expected_directory):
            raise _SnapshotPreparationError()
        children = []
        try:
            with os.scandir(current) as iterator:
                for child in iterator:
                    children.append(child)
                    if (
                        len(children) + files + directories
                        > limits.source_files + limits.source_directories
                    ):
                        raise _SnapshotPreparationError()
            children.sort(key=lambda item: os.fsencode(item.name))
        except _SnapshotError:
            raise
        except (OSError, ValueError, TypeError, UnicodeError):
            raise _SnapshotPreparationError() from None
        discovered_directories = []
        for child in children:
            _check_control(deadline, clock, cancelled, _SnapshotPreparationError)
            name = child.name
            _validate_component(name)
            parts = current_parts + (name,)
            if len(parts) > limits.relative_depth:
                raise _SnapshotPreparationError()
            child_path = current.joinpath(name)
            raw = _lstat(child_path)
            identity = _identity(raw)
            if identity.device != root_device or stat.S_ISLNK(identity.mode) or _is_reparse(identity):
                raise _SnapshotPreparationError()
            if stat.S_ISDIR(identity.mode):
                if _windows_has_named_streams(child_path):
                    raise _SnapshotPreparationError()
                directories += 1
                if directories > limits.source_directories:
                    raise _SnapshotPreparationError()
                entry = _Entry(parts, True, identity)
                entries.append(entry)
                discovered_directories.append((child_path, parts, identity))
            elif stat.S_ISREG(identity.mode):
                if identity.links != 1 or _is_sparse(identity, raw) or _windows_has_named_streams(child_path):
                    raise _SnapshotPreparationError()
                files += 1
                total_bytes += identity.size
                if (
                    files > limits.source_files
                    or identity.size < 0
                    or identity.size > limits.single_file_bytes
                    or total_bytes > limits.source_bytes
                ):
                    raise _SnapshotPreparationError()
                entries.append(_Entry(parts, False, identity))
            else:
                raise _SnapshotPreparationError()
        if not _same_identity(_identity(_lstat(current)), expected_directory):
            raise _SnapshotPreparationError()
        pending.extend(reversed(discovered_directories))
    entries.sort(key=lambda entry: tuple(os.fsencode(part) for part in entry.parts))
    return _Inventory(source, root_identity, tuple(entries), files, directories, total_bytes)


def _inventory_shape(inventory: _Inventory) -> tuple:
    return (
        inventory.files,
        inventory.directories,
        inventory.total_bytes,
        tuple(
            (entry.parts, entry.is_directory, 0 if entry.is_directory else entry.identity.size)
            for entry in inventory.entries
        ),
    )


def _assert_restrictive(path: Path, directory: bool) -> None:
    identity = _identity(_lstat(path))
    if stat.S_ISLNK(identity.mode) or _is_reparse(identity):
        raise _SnapshotPreparationError()
    if os.name != "nt":
        wanted = 0o700 if directory else 0o600
        if stat.S_IMODE(identity.mode) != wanted:
            raise _SnapshotPreparationError()


def _windows_apis():
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    )
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    )
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi.SetNamedSecurityInfoW.argtypes = (
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.CreateDirectoryW.argtypes = (wintypes.LPCWSTR, wintypes.LPVOID)
    kernel32.CreateDirectoryW.restype = wintypes.BOOL
    return ctypes, wintypes, advapi, kernel32


def _windows_restrictive_sddl(ctypes, wintypes, advapi, kernel32) -> str:
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(
            token,
            1,
            ctypes.cast(buffer, wintypes.LPVOID),
            needed,
            ctypes.byref(needed),
        ):
            raise OSError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        sid_text = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise OSError(ctypes.get_last_error())
        try:
            return f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid_text.value})"
        finally:
            kernel32.LocalFree(ctypes.cast(sid_text, wintypes.HLOCAL))
    finally:
        kernel32.CloseHandle(token)


def _windows_descriptor(ctypes, wintypes, advapi, sddl: str):
    descriptor = ctypes.c_void_p()
    size = wintypes.DWORD()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)
    ):
        raise OSError(ctypes.get_last_error())
    return descriptor


def _windows_harden(path: Path) -> None:
    if os.name != "nt":
        return
    try:
        ctypes, wintypes, advapi, kernel32 = _windows_apis()
        sddl = _windows_restrictive_sddl(ctypes, wintypes, advapi, kernel32)
        descriptor = _windows_descriptor(ctypes, wintypes, advapi, sddl)
        try:
            present = wintypes.BOOL()
            defaulted = wintypes.BOOL()
            dacl = ctypes.c_void_p()
            if not advapi.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
            ) or not present.value:
                raise OSError(ctypes.get_last_error())
            result = advapi.SetNamedSecurityInfoW(
                str(path), 1, 0x00000004 | 0x80000000, None, None, dacl, None
            )
            if result:
                raise OSError(result)
        finally:
            kernel32.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))
    except (OSError, AttributeError, ValueError, TypeError):
        raise _SnapshotPreparationError() from None


def _windows_make_directory(path: Path) -> None:
    try:
        ctypes, wintypes, advapi, kernel32 = _windows_apis()
        sddl = _windows_restrictive_sddl(ctypes, wintypes, advapi, kernel32)
        descriptor = _windows_descriptor(ctypes, wintypes, advapi, sddl)

        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = (
                ("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", wintypes.LPVOID),
                ("bInheritHandle", wintypes.BOOL),
            )

        attributes = SECURITY_ATTRIBUTES(
            ctypes.sizeof(SECURITY_ATTRIBUTES),
            descriptor,
            False,
        )
        try:
            if not kernel32.CreateDirectoryW(
                str(path), ctypes.cast(ctypes.byref(attributes), wintypes.LPVOID)
            ):
                raise OSError(ctypes.get_last_error())
        finally:
            kernel32.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))
    except (OSError, AttributeError, ValueError, TypeError):
        raise _SnapshotPreparationError() from None


def _harden(path: Path, directory: bool) -> None:
    try:
        os.chmod(path, 0o700 if directory else 0o600)
        _windows_harden(path)
        _assert_restrictive(path, directory)
    except _SnapshotError:
        raise
    except OSError:
        raise _SnapshotPreparationError() from None


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)) | int(getattr(os, "O_CLOEXEC", 0))
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        os.fsync(descriptor)
    except OSError:
        raise _SnapshotPreparationError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_exclusive(path: Path, encoded: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_BINARY", 0))
    descriptor = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _harden(path, False)
    except _SnapshotError:
        raise
    except OSError:
        raise _SnapshotPreparationError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _replace_control(path: Path, encoded: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    try:
        _write_exclusive(temporary, encoded)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except _SnapshotError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    except OSError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise _SnapshotPreparationError() from None


def _read_bounded(path: Path, maximum: int, error_type: type[_SnapshotError]) -> bytes:
    descriptor = None
    try:
        raw = _lstat(path, error_type)
        identity = _identity(raw)
        if (
            not stat.S_ISREG(identity.mode)
            or stat.S_ISLNK(identity.mode)
            or _is_reparse(identity)
            or identity.links != 1
            or identity.size < 1
            or identity.size > maximum
        ):
            raise error_type()
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOINHERIT", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(path, flags)
        opened = _identity(os.fstat(descriptor))
        if not _same_path_handle_identity(identity, opened):
            raise error_type()
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            encoded = handle.read(maximum + 1)
            closed = _identity(os.fstat(handle.fileno()))
        if (
            len(encoded) > maximum
            or not _same_identity(opened, closed)
            or not _same_identity(identity, _identity(_lstat(path, error_type)))
        ):
            raise error_type()
        return encoded
    except _SnapshotError:
        raise
    except (OSError, ValueError, TypeError):
        raise error_type() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


class _LeaseLock:
    def __init__(self, path: Path, *, create: bool) -> None:
        flags = os.O_RDWR | int(getattr(os, "O_BINARY", 0))
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOINHERIT", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        try:
            self._fd = os.open(path, flags, 0o600)
            if create and os.fstat(self._fd).st_size == 0:
                os.write(self._fd, b"\x00")
                os.fsync(self._fd)
                os.lseek(self._fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError):
            descriptor = getattr(self, "_fd", None)
            if descriptor is not None:
                os.close(descriptor)
            raise _SnapshotRecoveryError() if not create else _SnapshotPreparationError()
        self._closed = False
        self._identity = _identity(os.fstat(self._fd))

    @property
    def descriptor(self) -> int:
        if self._closed:
            raise _SnapshotCleanupError()
        return self._fd

    @property
    def identity(self) -> _Identity:
        if self._closed:
            raise _SnapshotCleanupError()
        observed = _identity(os.fstat(self._fd))
        if not _same_identity(observed, self._identity):
            raise _SnapshotCleanupError()
        return observed

    def close(self) -> None:
        if self._closed:
            return
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._closed = True


def _read_locked_lease(
    lock: _LeaseLock,
    maximum: int,
    error_type: type[_SnapshotError],
) -> bytes:
    """Read the lease through its locking descriptor for Windows lock compatibility."""
    try:
        identity = lock.identity
        if (
            not stat.S_ISREG(identity.mode)
            or _is_reparse(identity)
            or identity.links != 1
            or identity.size < 1
            or identity.size > maximum
        ):
            raise error_type()
        descriptor = lock.descriptor
        original_offset = os.lseek(descriptor, 0, os.SEEK_CUR)
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            encoded = os.read(descriptor, maximum + 1)
        finally:
            os.lseek(descriptor, original_offset, os.SEEK_SET)
        if len(encoded) > maximum or not _same_identity(identity, lock.identity):
            raise error_type()
        return encoded
    except _SnapshotError:
        raise error_type() from None
    except (OSError, ValueError, TypeError):
        raise error_type() from None


def _create_locked_lease(path: Path, encoded: bytes) -> _LeaseLock:
    lock = _LeaseLock(path, create=True)
    try:
        with os.fdopen(os.dup(lock.descriptor), "r+b", closefd=True) as handle:
            handle.seek(0)
            handle.truncate(0)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _harden(path, False)
        lock._identity = _identity(os.fstat(lock.descriptor))
        return lock
    except BaseException:
        lock.close()
        raise


def _open_source_file(path: Path, expected: _Identity):
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        opened = _identity(os.fstat(descriptor))
        if (
            not _same_path_handle_identity(expected, opened)
            or not stat.S_ISREG(opened.mode)
            or opened.links != 1
            or _is_reparse(opened)
        ):
            raise _SnapshotPreparationError()
        handle = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = None
        return handle, opened
    except _SnapshotError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise _SnapshotPreparationError() from None


def _copy_file(
    source: Path,
    destination: Path,
    expected: _Identity,
    limits: _Limits,
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
) -> bytes:
    digest = hashlib.sha256()
    written = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_BINARY", 0))
    descriptor = None
    try:
        input_handle, opened = _open_source_file(source, expected)
        with input_handle:
            descriptor = os.open(destination, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as output_handle:
                descriptor = None
                while True:
                    _check_control(deadline, clock, cancelled, _SnapshotPreparationError)
                    chunk = input_handle.read(limits.chunk_bytes)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > expected.size or written > limits.single_file_bytes:
                        raise _SnapshotPreparationError()
                    digest.update(chunk)
                    output_handle.write(chunk)
                output_handle.flush()
                os.fsync(output_handle.fileno())
            if written != expected.size or not _same_identity(
                _identity(os.fstat(input_handle.fileno())), opened
            ):
                raise _SnapshotPreparationError()
        if not _same_identity(_identity(_lstat(source)), expected):
            raise _SnapshotPreparationError()
        _harden(destination, False)
        verified = _hash_copy(
            destination,
            expected.size,
            limits,
            deadline,
            clock,
            cancelled,
        )
        if not hmac.compare_digest(digest.digest(), verified):
            raise _SnapshotPreparationError()
        return digest.digest()
    except _SnapshotError:
        raise
    except (OSError, ValueError, TypeError):
        raise _SnapshotPreparationError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _hash_source(
    path: Path,
    expected: _Identity,
    limits: _Limits,
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
) -> bytes:
    digest = hashlib.sha256()
    read = 0
    try:
        handle, opened = _open_source_file(path, expected)
        with handle:
            while True:
                _check_control(deadline, clock, cancelled, _SnapshotPreparationError)
                chunk = handle.read(limits.chunk_bytes)
                if not chunk:
                    break
                read += len(chunk)
                if read > expected.size:
                    raise _SnapshotPreparationError()
                digest.update(chunk)
            if read != expected.size or not _same_identity(
                _identity(os.fstat(handle.fileno())), opened
            ):
                raise _SnapshotPreparationError()
        if not _same_identity(_identity(_lstat(path)), expected):
            raise _SnapshotPreparationError()
        return digest.digest()
    except _SnapshotError:
        raise
    except OSError:
        raise _SnapshotPreparationError() from None


def _hash_copy(
    path: Path,
    expected_size: int,
    limits: _Limits,
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
) -> bytes:
    digest = hashlib.sha256()
    read = 0
    try:
        raw = _lstat(path)
        identity = _identity(raw)
        if (
            not stat.S_ISREG(identity.mode)
            or stat.S_ISLNK(identity.mode)
            or _is_reparse(identity)
            or identity.links != 1
            or identity.size != expected_size
        ):
            raise _SnapshotPreparationError()
        handle, opened = _open_source_file(path, identity)
        with handle:
            while True:
                _check_control(deadline, clock, cancelled, _SnapshotPreparationError)
                chunk = handle.read(limits.chunk_bytes)
                if not chunk:
                    break
                read += len(chunk)
                if read > expected_size:
                    raise _SnapshotPreparationError()
                digest.update(chunk)
            if not _same_identity(_identity(os.fstat(handle.fileno())), opened):
                raise _SnapshotPreparationError()
        if read != expected_size or not _same_identity(identity, _identity(_lstat(path))):
            raise _SnapshotPreparationError()
        return digest.digest()
    except _SnapshotError:
        raise
    except (OSError, ValueError, TypeError):
        raise _SnapshotPreparationError() from None


def _disk_free_bytes(path: Path) -> int:
    try:
        return int(shutil.disk_usage(path).free)
    except (OSError, ValueError, TypeError):
        raise _SnapshotPreparationError() from None


def _make_directory(
    path: Path,
    identity_sink: Optional[list] = None,
) -> _Identity:
    try:
        if os.name == "nt":
            _windows_make_directory(path)
        else:
            os.mkdir(path, 0o700)
        created = _identity(_lstat(path))
        if identity_sink is not None:
            identity_sink.append(created)
        _harden(path, True)
        _fsync_directory(path.parent)
        observed = _identity(_lstat(path))
        if observed.device != created.device or observed.inode != created.inode:
            raise _SnapshotPreparationError()
        return observed
    except _SnapshotError:
        raise
    except OSError:
        raise _SnapshotPreparationError() from None


def _workspace_body(workspace_id: str, key_id: str) -> dict:
    return {
        "construction": _WORKSPACE_CONSTRUCTION,
        "key_id": key_id,
        "version": 1,
        "workspace_id": workspace_id,
    }


def _snapshot_body(workspace_id: str, snapshot_id: str, lease_id: str, phase: str) -> dict:
    return {
        "construction": _SNAPSHOT_CONSTRUCTION,
        "lease_id": lease_id,
        "phase": phase,
        "snapshot_id": snapshot_id,
        "version": 1,
        "workspace_id": workspace_id,
    }


def _lease_body(workspace_id: str, snapshot_id: str, lease_id: str) -> dict:
    return {
        "construction": _LEASE_CONSTRUCTION,
        "lease_id": lease_id,
        "snapshot_id": snapshot_id,
        "version": 1,
        "workspace_id": workspace_id,
    }


def _key_document(workspace_id: str, key_id: str, key: bytes) -> bytes:
    return _canonical_json(
        {
            "construction": _WORKSPACE_CONSTRUCTION,
            "key": base64.b64encode(key).decode("ascii"),
            "key_id": key_id,
            "version": 1,
            "workspace_id": workspace_id,
        }
    )


class _PreparedSnapshot:
    """Private capability that keeps the work directory lease held."""

    __slots__ = (
        "_base",
        "_workspace",
        "_snapshot",
        "_data",
        "_workspace_id",
        "_snapshot_id",
        "_lease_id",
        "_key",
        "_lock",
        "_limits",
        "_workspace_identity",
        "_snapshot_identity",
        "_closed",
    )

    def __init__(
        self,
        *,
        base: Path,
        workspace: Path,
        snapshot: Path,
        workspace_id: str,
        snapshot_id: str,
        lease_id: str,
        key: bytes,
        lock: _LeaseLock,
        limits: _Limits,
        workspace_identity: _Identity,
        snapshot_identity: _Identity,
    ) -> None:
        self._base = base
        self._workspace = workspace
        self._snapshot = snapshot
        self._data = snapshot / _PAYLOAD_DIRECTORY
        self._workspace_id = workspace_id
        self._snapshot_id = snapshot_id
        self._lease_id = lease_id
        self._key = key
        self._lock = lock
        self._limits = limits
        self._workspace_identity = workspace_identity
        self._snapshot_identity = snapshot_identity
        self._closed = False

    def __repr__(self) -> str:
        return "<RAGLeakGuard private prepared snapshot: redacted>"

    @property
    def data_path(self) -> Path:
        if self._closed:
            raise _SnapshotCleanupError()
        return self._data

    def cleanup(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> None:
        if self._closed:
            return
        failure = None
        try:
            deadline = _deadline(self._limits.cleanup_seconds, clock, _SnapshotCleanupError)
            _cleanup_snapshot(
                self._base,
                self._workspace,
                self._snapshot,
                self._workspace_id,
                self._snapshot_id,
                self._lease_id,
                self._key,
                self._lock,
                deadline,
                clock,
                cancelled,
                remove_workspace=True,
                expected_workspace=self._workspace_identity,
                expected_snapshot=self._snapshot_identity,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except _SnapshotCleanupError as error:
            failure = error
        except BaseException:
            failure = _SnapshotCleanupError()
        if failure is not None:
            raise _scrub_exception_chain(failure)
        self._closed = True

    def __enter__(self) -> "_PreparedSnapshot":
        if self._closed:
            raise _SnapshotCleanupError()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.cleanup()
        return False


def _prepare_snapshot_impl(
    source_path: object,
    work_parent: object,
    *,
    limits: _Limits = _DEFAULT_LIMITS,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Optional[Callable[[], bool]] = None,
    token_source: Callable[[int], bytes] = secrets.token_bytes,
) -> _PreparedSnapshot:
    """Create a private bounded copy; never establish a source-connector claim."""
    if not isinstance(limits, _Limits):
        raise _SnapshotPreparationError()
    deadline = _deadline(limits.prepare_seconds, clock, _SnapshotPreparationError)
    source, _ = _strict_directory_path(source_path)
    base, base_identity = _strict_directory_path(work_parent)
    if _paths_overlap(source, base):
        raise _SnapshotPreparationError()
    _check_control(deadline, clock, cancelled, _SnapshotPreparationError)
    inventory = _inventory(source, limits, deadline, clock, cancelled)
    if inventory.files + _CONTROL_FILE_ALLOWANCE > limits.work_files:
        raise _SnapshotPreparationError()
    estimated_work_bytes = inventory.total_bytes + _CONTROL_BYTE_ALLOWANCE
    if estimated_work_bytes > limits.work_bytes:
        raise _SnapshotPreparationError()
    if _disk_free_bytes(base) < estimated_work_bytes + _FREE_SPACE_MARGIN_BYTES:
        raise _SnapshotPreparationError()
    if not _same_identity(_validate_directory(base), base_identity):
        raise _SnapshotPreparationError()

    workspace_id = _new_token(token_source)
    snapshot_id = _new_token(token_source)
    lease_id = _new_token(token_source)
    key_id = _new_token(token_source)
    try:
        key = token_source(32)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise _SnapshotPreparationError() from None
    if not isinstance(key, bytes) or len(key) != 32:
        raise _SnapshotPreparationError()
    workspace = base / (_WORKSPACE_PREFIX + workspace_id)
    snapshot = workspace / (_SNAPSHOT_PREFIX + snapshot_id)
    data = snapshot / _PAYLOAD_DIRECTORY
    lock = None
    prepared = None
    workspace_identity = None
    snapshot_identity = None
    workspace_created = []
    snapshot_created = []
    try:
        workspace_identity = _make_directory(workspace, workspace_created)
        _write_exclusive(workspace / _WORKSPACE_KEY, _key_document(workspace_id, key_id, key))
        _write_exclusive(
            workspace / _WORKSPACE_MARKER,
            _authenticated_document(key, _workspace_body(workspace_id, key_id)),
        )
        snapshot_identity = _make_directory(snapshot, snapshot_created)
        lock = _create_locked_lease(
            snapshot / _LEASE_FILE,
            _authenticated_document(key, _lease_body(workspace_id, snapshot_id, lease_id)),
        )
        _write_exclusive(
            snapshot / _SNAPSHOT_MARKER,
            _authenticated_document(
                key, _snapshot_body(workspace_id, snapshot_id, lease_id, "preparing")
            ),
        )
        _make_directory(data)
        copied_hashes = {}
        work_bytes = sum(
            _identity(_lstat(path)).size
            for path in (
                workspace / _WORKSPACE_KEY,
                workspace / _WORKSPACE_MARKER,
                snapshot / _SNAPSHOT_MARKER,
                snapshot / _LEASE_FILE,
            )
        )
        work_files = _PERSISTENT_CONTROL_FILES
        for entry in inventory.entries:
            _check_control(deadline, clock, cancelled, _SnapshotPreparationError)
            source_entry = source.joinpath(*entry.parts)
            destination = data.joinpath(*entry.parts)
            if entry.is_directory:
                _make_directory(destination)
            else:
                work_files += 1
                work_bytes += entry.identity.size
                if work_files > limits.work_files or work_bytes > limits.work_bytes:
                    raise _SnapshotPreparationError()
                copied_hashes[entry.parts] = _copy_file(
                    source_entry,
                    destination,
                    entry.identity,
                    limits,
                    deadline,
                    clock,
                    cancelled,
                )
        second_inventory = _inventory(source, limits, deadline, clock, cancelled)
        if inventory != second_inventory:
            raise _SnapshotPreparationError()
        first_copy_inventory = _inventory(data, limits, deadline, clock, cancelled)
        if _inventory_shape(first_copy_inventory) != _inventory_shape(inventory):
            raise _SnapshotPreparationError()
        for entry in inventory.entries:
            if not entry.is_directory:
                observed = _hash_source(
                    source.joinpath(*entry.parts),
                    entry.identity,
                    limits,
                    deadline,
                    clock,
                    cancelled,
                )
                copied = _hash_copy(
                    data.joinpath(*entry.parts),
                    entry.identity.size,
                    limits,
                    deadline,
                    clock,
                    cancelled,
                )
                if (
                    not hmac.compare_digest(observed, copied_hashes[entry.parts])
                    or not hmac.compare_digest(copied, copied_hashes[entry.parts])
                ):
                    raise _SnapshotPreparationError()
        third_inventory = _inventory(source, limits, deadline, clock, cancelled)
        second_copy_inventory = _inventory(data, limits, deadline, clock, cancelled)
        if (
            inventory != third_inventory
            or _inventory_shape(first_copy_inventory) != _inventory_shape(second_copy_inventory)
            or not _same_identity(_identity(_lstat(source)), inventory.root_identity)
        ):
            raise _SnapshotPreparationError()
        _check_control(deadline, clock, cancelled, _SnapshotPreparationError)
        _replace_control(
            snapshot / _SNAPSHOT_MARKER,
            _authenticated_document(
                key, _snapshot_body(workspace_id, snapshot_id, lease_id, "ready")
            ),
        )
        _fsync_directory(data)
        _fsync_directory(snapshot)
        _fsync_directory(workspace)
        _check_control(deadline, clock, cancelled, _SnapshotPreparationError)
        prepared = _PreparedSnapshot(
            base=base,
            workspace=workspace,
            snapshot=snapshot,
            workspace_id=workspace_id,
            snapshot_id=snapshot_id,
            lease_id=lease_id,
            key=key,
            lock=lock,
            limits=limits,
            workspace_identity=workspace_identity,
            snapshot_identity=snapshot_identity,
        )
        return prepared
    except BaseException as original_error:
        if workspace_identity is None and workspace_created:
            workspace_identity = workspace_created[0]
        if snapshot_identity is None and snapshot_created:
            snapshot_identity = snapshot_created[0]
        if prepared is None and os.path.lexists(workspace):
            try:
                cleanup_deadline = _deadline(limits.cleanup_seconds, clock, _SnapshotCleanupError)
                if lock is not None and snapshot.exists():
                    _cleanup_snapshot(
                        base,
                        workspace,
                        snapshot,
                        workspace_id,
                        snapshot_id,
                        lease_id,
                        key,
                        lock,
                        cleanup_deadline,
                        clock,
                        None,
                        remove_workspace=True,
                        allow_pre_marker=True,
                        expected_workspace=workspace_identity,
                        expected_snapshot=snapshot_identity,
                    )
                else:
                    if lock is not None:
                        lock.close()
                    if workspace_identity is None:
                        raise _SnapshotCleanupError()
                    if not _same_object(
                        _identity(_lstat(workspace, _SnapshotCleanupError)),
                        workspace_identity,
                    ):
                        raise _SnapshotCleanupError()
                    _safe_remove_tree(
                        workspace,
                        workspace,
                        workspace_identity,
                        cleanup_deadline,
                        clock,
                        None,
                        _SnapshotCleanupError,
                    )
            except BaseException:
                if lock is not None:
                    try:
                        lock.close()
                    except BaseException:
                        pass
                raise _SnapshotCleanupError() from None
        if isinstance(original_error, (KeyboardInterrupt, SystemExit)):
            raise
        raise _SnapshotPreparationError() from None


def _prepare_snapshot(
    source_path: object,
    work_parent: object,
    *,
    limits: _Limits = _DEFAULT_LIMITS,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Optional[Callable[[], bool]] = None,
    token_source: Callable[[int], bytes] = secrets.token_bytes,
) -> _PreparedSnapshot:
    """Run preparation behind a static, chain-free exception boundary."""
    try:
        return _prepare_snapshot_impl(
            source_path,
            work_parent,
            limits=limits,
            clock=clock,
            cancelled=cancelled,
            token_source=token_source,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except _SnapshotError as error:
        failure = error
    except BaseException:
        failure = _SnapshotPreparationError()
    raise _scrub_exception_chain(failure)


def _parse_document(encoded: bytes, error_type: type[_SnapshotError]) -> dict:
    try:
        document = json.loads(
            encoded.decode("ascii"),
            object_pairs_hook=lambda pairs: _pairs_object(pairs, error_type),
        )
    except _SnapshotError:
        raise
    except (UnicodeError, ValueError, TypeError):
        raise error_type() from None
    if not isinstance(document, dict):
        raise error_type()
    return document


def _pairs_object(pairs: Iterable[tuple], error_type: type[_SnapshotError]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise error_type()
        value[key] = item
    return value


def _load_workspace(workspace: Path, error_type: type[_SnapshotError]) -> tuple[str, str, bytes]:
    try:
        identity = _identity(_lstat(workspace, error_type))
        if not stat.S_ISDIR(identity.mode) or stat.S_ISLNK(identity.mode) or _is_reparse(identity):
            raise error_type()
        workspace_id = workspace.name.removeprefix(_WORKSPACE_PREFIX)
        if _TOKEN_RE.fullmatch(workspace_id) is None:
            raise error_type()
        key_document = _parse_document(_read_bounded(workspace / _WORKSPACE_KEY, 4096, error_type), error_type)
        if set(key_document) != {"construction", "key", "key_id", "version", "workspace_id"}:
            raise error_type()
        if (
            key_document["construction"] != _WORKSPACE_CONSTRUCTION
            or type(key_document["version"]) is not int
            or key_document["version"] != 1
            or key_document["workspace_id"] != workspace_id
        ):
            raise error_type()
        key_id = _ensure_recovery_token(key_document["key_id"], error_type)
        try:
            key = base64.b64decode(key_document["key"], validate=True)
        except (ValueError, TypeError):
            raise error_type() from None
        if len(key) != 32 or base64.b64encode(key).decode("ascii") != key_document["key"]:
            raise error_type()
        marker = _parse_document(_read_bounded(workspace / _WORKSPACE_MARKER, 4096, error_type), error_type)
        if set(marker) != {"authentication", "construction", "key_id", "version", "workspace_id"}:
            raise error_type()
        authentication = marker.pop("authentication")
        if (
            not isinstance(authentication, str)
            or _AUTH_RE.fullmatch(authentication) is None
            or type(marker.get("version")) is not int
            or marker != _workspace_body(workspace_id, key_id)
            or not hmac.compare_digest(authentication, _authentication(key, marker))
        ):
            raise error_type()
        return workspace_id, key_id, key
    except _SnapshotError:
        raise error_type() from None
    except (OSError, ValueError, TypeError, KeyError):
        raise error_type() from None


def _ensure_recovery_token(value: object, error_type: type[_SnapshotError]) -> str:
    if not isinstance(value, str) or _TOKEN_RE.fullmatch(value) is None:
        raise error_type()
    return value


def _load_snapshot_marker(
    snapshot: Path,
    workspace_id: str,
    key: bytes,
    error_type: type[_SnapshotError],
    lease_lock: Optional[_LeaseLock] = None,
) -> tuple[str, str, str]:
    try:
        snapshot_id = snapshot.name.removeprefix(_SNAPSHOT_PREFIX)
        _ensure_recovery_token(snapshot_id, error_type)
        document = _parse_document(_read_bounded(snapshot / _SNAPSHOT_MARKER, 4096, error_type), error_type)
        if set(document) != {
            "authentication", "construction", "lease_id", "phase", "snapshot_id", "version", "workspace_id"
        }:
            raise error_type()
        authentication = document.pop("authentication")
        lease_id = _ensure_recovery_token(document.get("lease_id"), error_type)
        phase = document.get("phase")
        if phase not in {"preparing", "ready"}:
            raise error_type()
        if (
            not isinstance(authentication, str)
            or _AUTH_RE.fullmatch(authentication) is None
            or type(document.get("version")) is not int
            or document != _snapshot_body(workspace_id, snapshot_id, lease_id, phase)
            or not hmac.compare_digest(authentication, _authentication(key, document))
        ):
            raise error_type()
        lease_encoded = (
            _read_locked_lease(lease_lock, 4096, error_type)
            if lease_lock is not None
            else _read_bounded(snapshot / _LEASE_FILE, 4096, error_type)
        )
        lease = _parse_document(lease_encoded, error_type)
        if set(lease) != {
            "authentication", "construction", "lease_id", "snapshot_id", "version", "workspace_id"
        }:
            raise error_type()
        lease_authentication = lease.pop("authentication")
        if (
            not isinstance(lease_authentication, str)
            or _AUTH_RE.fullmatch(lease_authentication) is None
            or type(lease.get("version")) is not int
            or lease != _lease_body(workspace_id, snapshot_id, lease_id)
            or not hmac.compare_digest(lease_authentication, _authentication(key, lease))
        ):
            raise error_type()
        return snapshot_id, lease_id, phase
    except _SnapshotError:
        raise error_type() from None
    except (OSError, ValueError, TypeError, KeyError):
        raise error_type() from None


def _safe_remove_tree(
    root: Path,
    path: Path,
    root_identity: _Identity,
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
    error_type: type[_SnapshotError],
    budget: Optional[_RemovalBudget] = None,
    depth: int = 0,
) -> None:
    _check_control(deadline, clock, cancelled, error_type)
    if path != root and root not in path.parents:
        raise error_type()
    if budget is None:
        budget = _RemovalBudget()
    budget.objects += 1
    if budget.objects > _MAX_CLEANUP_OBJECTS or depth > _MAX_CLEANUP_DEPTH:
        raise error_type()
    identity = _identity(_lstat(path, error_type))
    if (
        identity.device != root_identity.device
        or stat.S_ISLNK(identity.mode)
        or _is_reparse(identity)
        or not (stat.S_ISDIR(identity.mode) or stat.S_ISREG(identity.mode))
    ):
        raise error_type()
    if stat.S_ISREG(identity.mode):
        if identity.links != 1:
            raise error_type()
        try:
            os.chmod(path, 0o600)
            path.unlink()
        except OSError:
            raise error_type() from None
        return
    children = []
    try:
        with os.scandir(path) as iterator:
            for child in iterator:
                children.append(child)
                if len(children) + budget.objects > _MAX_CLEANUP_OBJECTS:
                    raise error_type()
    except _SnapshotError:
        raise
    except OSError:
        raise error_type() from None
    for child in children:
        _safe_remove_tree(
            root,
            path / child.name,
            root_identity,
            deadline,
            clock,
            cancelled,
            error_type,
            budget,
            depth + 1,
        )
    try:
        os.chmod(path, 0o700)
        path.rmdir()
    except OSError:
        raise error_type() from None


def _cleanup_snapshot(
    base: Path,
    workspace: Path,
    snapshot: Path,
    workspace_id: str,
    snapshot_id: str,
    lease_id: str,
    key: bytes,
    lock: _LeaseLock,
    deadline: float,
    clock: Callable[[], float],
    cancelled: Optional[Callable[[], bool]],
    *,
    remove_workspace: bool,
    allow_pre_marker: bool = False,
    expected_workspace: Optional[_Identity] = None,
    expected_snapshot: Optional[_Identity] = None,
) -> None:
    _check_control(deadline, clock, cancelled, _SnapshotCleanupError)
    base_resolved = _resolved(base)
    workspace_resolved = _resolved(workspace)
    snapshot_resolved = _resolved(snapshot)
    if (
        workspace.parent != base
        or snapshot.parent != workspace
        or workspace_resolved.parent != base_resolved
        or snapshot_resolved.parent != workspace_resolved
        or workspace.name != _WORKSPACE_PREFIX + workspace_id
        or snapshot.name != _SNAPSHOT_PREFIX + snapshot_id
    ):
        raise _SnapshotCleanupError()
    observed_workspace = _identity(_lstat(workspace, _SnapshotCleanupError))
    observed_snapshot = _identity(_lstat(snapshot, _SnapshotCleanupError))
    if (
        (expected_workspace is not None and not _same_object(observed_workspace, expected_workspace))
        or (expected_snapshot is not None and not _same_object(observed_snapshot, expected_snapshot))
        or not _same_path_handle_identity(
            _identity(_lstat(snapshot / _LEASE_FILE, _SnapshotCleanupError)),
            lock.identity,
        )
    ):
        raise _SnapshotCleanupError()
    loaded_workspace_id, _, loaded_key = _load_workspace(workspace, _SnapshotCleanupError)
    if loaded_workspace_id != workspace_id or not hmac.compare_digest(loaded_key, key):
        raise _SnapshotCleanupError()
    try:
        loaded_snapshot_id, loaded_lease_id, _ = _load_snapshot_marker(
            snapshot, workspace_id, key, _SnapshotCleanupError, lock
        )
        if loaded_snapshot_id != snapshot_id or loaded_lease_id != lease_id:
            raise _SnapshotCleanupError()
    except _SnapshotCleanupError:
        if not allow_pre_marker:
            raise
    root_identity = _identity(_lstat(workspace, _SnapshotCleanupError))
    snapshot_identity = _identity(_lstat(snapshot, _SnapshotCleanupError))
    if snapshot_identity.device != root_identity.device:
        raise _SnapshotCleanupError()

    protected = {snapshot / _SNAPSHOT_MARKER, snapshot / _LEASE_FILE}
    removal_budget = _RemovalBudget()
    try:
        snapshot_children = []
        with os.scandir(snapshot) as iterator:
            for child in iterator:
                snapshot_children.append(child)
                if len(snapshot_children) > _MAX_CLEANUP_OBJECTS:
                    raise _SnapshotCleanupError()
        for child in snapshot_children:
            child_path = snapshot / child.name
            if child_path not in protected:
                _safe_remove_tree(
                    workspace,
                    child_path,
                    root_identity,
                    deadline,
                    clock,
                    cancelled,
                    _SnapshotCleanupError,
                    removal_budget,
                )
        _check_control(deadline, clock, cancelled, _SnapshotCleanupError)
        lock.close()
        for protected_path in (snapshot / _LEASE_FILE, snapshot / _SNAPSHOT_MARKER):
            if protected_path.exists():
                _safe_remove_tree(
                    workspace,
                    protected_path,
                    root_identity,
                    deadline,
                    clock,
                    cancelled,
                    _SnapshotCleanupError,
                    removal_budget,
                )
        _check_control(deadline, clock, cancelled, _SnapshotCleanupError)
        snapshot.rmdir()
        if remove_workspace:
            remaining = set()
            with os.scandir(workspace) as iterator:
                for entry in iterator:
                    if len(remaining) >= _MAX_CLEANUP_OBJECTS:
                        raise _SnapshotCleanupError()
                    remaining.add(entry.name)
            expected = {_WORKSPACE_KEY, _WORKSPACE_MARKER}
            if remaining != expected:
                raise _SnapshotCleanupError()
            for name in (_WORKSPACE_KEY, _WORKSPACE_MARKER):
                _safe_remove_tree(
                    workspace,
                    workspace / name,
                    root_identity,
                    deadline,
                    clock,
                    cancelled,
                    _SnapshotCleanupError,
                    removal_budget,
                )
            _check_control(deadline, clock, cancelled, _SnapshotCleanupError)
            workspace.rmdir()
            _fsync_directory(base)
            _check_control(deadline, clock, cancelled, _SnapshotCleanupError)
    except _SnapshotError:
        raise
    except OSError:
        raise _SnapshotCleanupError() from None


def _recover_snapshots_impl(
    work_parent: object,
    *,
    limits: _Limits = _DEFAULT_LIMITS,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Optional[Callable[[], bool]] = None,
) -> int:
    """Remove only inactive workspaces with authenticated ownership evidence."""
    if not isinstance(limits, _Limits):
        raise _SnapshotRecoveryError()
    recovered = 0
    try:
        base, base_identity = _strict_directory_path(work_parent, _SnapshotRecoveryError)
        deadline = _deadline(limits.cleanup_seconds, clock, _SnapshotRecoveryError)
        candidates = []
        with os.scandir(base) as iterator:
            for entry in iterator:
                if entry.name.startswith(_WORKSPACE_PREFIX):
                    candidates.append(base / entry.name)
                    if len(candidates) > _MAX_SOURCE_DIRECTORIES:
                        raise _SnapshotRecoveryError()
        candidates.sort(key=lambda path: os.fsencode(path.name))
        for workspace in candidates:
            _check_control(deadline, clock, cancelled, _SnapshotRecoveryError)
            if not _same_identity(
                _validate_directory(base, error_type=_SnapshotRecoveryError),
                base_identity,
            ):
                raise _SnapshotRecoveryError()
            workspace_identity = _identity(_lstat(workspace, _SnapshotRecoveryError))
            workspace_id, _, key = _load_workspace(workspace, _SnapshotRecoveryError)
            entries = {}
            with os.scandir(workspace) as iterator:
                for entry in iterator:
                    if entry.name in entries or len(entries) >= _MAX_SOURCE_DIRECTORIES + 2:
                        raise _SnapshotRecoveryError()
                    entries[entry.name] = workspace / entry.name
            snapshots = sorted(
                (path for name, path in entries.items() if name.startswith(_SNAPSHOT_PREFIX)),
                key=lambda path: os.fsencode(path.name),
            )
            if not snapshots or set(entries) != {
                _WORKSPACE_KEY,
                _WORKSPACE_MARKER,
                *(path.name for path in snapshots),
            }:
                raise _SnapshotRecoveryError()
            for snapshot in snapshots:
                snapshot_identity = _identity(_lstat(snapshot, _SnapshotRecoveryError))
                lock = _LeaseLock(snapshot / _LEASE_FILE, create=False)
                try:
                    snapshot_id, lease_id, _ = _load_snapshot_marker(
                        snapshot, workspace_id, key, _SnapshotRecoveryError, lock
                    )
                    _cleanup_snapshot(
                        base,
                        workspace,
                        snapshot,
                        workspace_id,
                        snapshot_id,
                        lease_id,
                        key,
                        lock,
                        deadline,
                        clock,
                        cancelled,
                        remove_workspace=snapshot == snapshots[-1],
                        expected_workspace=workspace_identity,
                        expected_snapshot=snapshot_identity,
                    )
                except BaseException:
                    try:
                        lock.close()
                    except BaseException:
                        pass
                    raise
                recovered += 1
        return recovered
    except _SnapshotError:
        raise _SnapshotRecoveryError() from None
    except (OSError, ValueError, TypeError):
        raise _SnapshotRecoveryError() from None


def _recover_snapshots(
    work_parent: object,
    *,
    limits: _Limits = _DEFAULT_LIMITS,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Optional[Callable[[], bool]] = None,
) -> int:
    """Run recovery behind a static, chain-free exception boundary."""
    try:
        return _recover_snapshots_impl(
            work_parent,
            limits=limits,
            clock=clock,
            cancelled=cancelled,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except _SnapshotError as error:
        failure = error
    except BaseException:
        failure = _SnapshotRecoveryError()
    raise _scrub_exception_chain(failure)


__all__ = ()
