"""Verify build-once candidate archives and write privacy-minimal build evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath

from packaging.metadata import Metadata


PACKAGE = "ragleakguard"
PACKAGE_MODULES = {
    "__init__.py",
    "_chroma_snapshot.py",
    "_snapshot.py",
    "cli.py",
    "connectors.py",
    "detect.py",
    "monitor.py",
    "report.py",
    "risk_policy.py",
}
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
FORBIDDEN_PARTS = {
    ".env",
    ".git",
    ".github",
    ".pytest_cache",
    "reports",
    "scripts",
    "tests",
}
FORBIDDEN_SUFFIXES = {
    ".db",
    ".key",
    ".pem",
    ".pdf",
    ".sqlite",
    ".sqlite3",
}
PRIVACY_CANARIES = (
    b"document-text-canary",
    b"detected-value-canary",
    b"record-id-canary",
    b"collection-name-canary",
    b"tenant-canary",
    b"secret-token-canary",
    b"operator-snapshot-path-canary",
    b"private-work-parent-path-canary",
    b"private-report-path-canary",
)
CREDENTIAL_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bpypi-[A-Za-z0-9_-]{20,}"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
)
ABSOLUTE_PATH_PATTERNS = (
    re.compile(rb"[A-Za-z]:\\Users\\"),
    re.compile(rb"/home/runner/"),
    re.compile(rb"/Users/runner/"),
)


class CandidateVerificationError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(raw: str, *, sdist_root: str | None) -> tuple[str, ...]:
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or "\\" in raw or ".." in path.parts:
        raise CandidateVerificationError("archive contains an unsafe member path")
    parts = path.parts
    if sdist_root is not None:
        if not parts or parts[0] != sdist_root:
            raise CandidateVerificationError("sdist member escaped the versioned root")
        parts = parts[1:]
    lowered = tuple(part.lower() for part in parts)
    if any(part in FORBIDDEN_PARTS for part in lowered):
        raise CandidateVerificationError("archive contains a forbidden path")
    if parts and PurePosixPath(*parts).suffix.lower() in FORBIDDEN_SUFFIXES:
        raise CandidateVerificationError("archive contains a forbidden file type")
    return parts


def _scan_content(data: bytes) -> None:
    if len(data) > MAX_MEMBER_BYTES:
        raise CandidateVerificationError("archive member exceeds the inspection bound")
    if any(canary in data for canary in PRIVACY_CANARIES):
        raise CandidateVerificationError("archive contains a privacy canary")
    if any(pattern.search(data) for pattern in CREDENTIAL_PATTERNS):
        raise CandidateVerificationError("archive contains credential-shaped material")
    if any(pattern.search(data) for pattern in ABSOLUTE_PATH_PATTERNS):
        raise CandidateVerificationError("archive contains a local runner path")


def _inspect_wheel(path: Path, version: str) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            parts = _safe_name(member.filename, sdist_root=None)
            mode = member.external_attr >> 16
            if member.is_dir():
                continue
            if stat.S_ISLNK(mode):
                raise CandidateVerificationError("wheel contains a symbolic link")
            data = archive.read(member)
            total += len(data)
            if total > MAX_ARCHIVE_BYTES:
                raise CandidateVerificationError("wheel exceeds the inspection bound")
            _scan_content(data)
            files["/".join(parts)] = data
    expected = {
        *(f"{PACKAGE}/{name}" for name in PACKAGE_MODULES),
        f"{PACKAGE}-{version}.dist-info/METADATA",
        f"{PACKAGE}-{version}.dist-info/WHEEL",
        f"{PACKAGE}-{version}.dist-info/entry_points.txt",
        f"{PACKAGE}-{version}.dist-info/licenses/LICENSE",
        f"{PACKAGE}-{version}.dist-info/RECORD",
    }
    if set(files) != expected:
        raise CandidateVerificationError("wheel contents differ from the exact allowlist")
    return files


def _inspect_sdist(path: Path, version: str) -> dict[str, bytes]:
    root = f"{PACKAGE}-{version}"
    files: dict[str, bytes] = {}
    total = 0
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive.getmembers():
            parts = _safe_name(member.name, sdist_root=root)
            if member.isdir():
                continue
            if not member.isfile():
                raise CandidateVerificationError("sdist contains a non-regular member")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise CandidateVerificationError("sdist member could not be inspected")
            data = extracted.read(MAX_MEMBER_BYTES + 1)
            total += len(data)
            if total > MAX_ARCHIVE_BYTES:
                raise CandidateVerificationError("sdist exceeds the inspection bound")
            _scan_content(data)
            files["/".join(parts)] = data
    expected = {
        "PKG-INFO",
        ".gitignore",
        "LICENSE",
        "README.md",
        "README.zh-TW.md",
        "SECURITY.md",
        "pyproject.toml",
        "docs/releases/0.1.1.md",
        *(f"src/ragleakguard/{name}" for name in PACKAGE_MODULES),
    }
    if set(files) != expected:
        raise CandidateVerificationError("sdist contents differ from the exact allowlist")
    return files


def _metadata(data: bytes, version: str) -> None:
    try:
        Metadata.from_email(data, validate=True)
    except Exception as error:
        raise CandidateVerificationError("artifact core metadata is invalid") from error
    message = BytesParser(policy=default).parsebytes(data)
    if message["Name"] != PACKAGE or message["Version"] != version:
        raise CandidateVerificationError("artifact name or version metadata differs")
    python_specifiers = {
        part.strip() for part in message["Requires-Python"].split(",")
    }
    if python_specifiers != {">=3.9", "<3.13"}:
        raise CandidateVerificationError("artifact Python metadata differs")
    requirements = "\n".join(message.get_all("Requires-Dist", []))
    if "chromadb==1.5.9" not in requirements or "chroma-snapshot" not in requirements:
        raise CandidateVerificationError("artifact Chroma extra is not exact")


def _runtime_version(data: bytes, version: str) -> None:
    match = re.search(rb'^__version__\s*=\s*["\']([^"\']+)["\']$', data, re.MULTILINE)
    if match is None or match.group(1).decode("ascii") != version:
        raise CandidateVerificationError("runtime version differs from artifact metadata")


def _atomic_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=".rlg-build-evidence-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        raise CandidateVerificationError("source SHA must be a full lowercase SHA-1")
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    if policy.get("schema") != 1 or policy.get("proposed_version") != args.expected_version:
        raise CandidateVerificationError("release policy version differs")
    artifacts = sorted(path for path in args.dist.iterdir() if path.is_file())
    wheel_name = f"{PACKAGE}-{args.expected_version}-py3-none-any.whl"
    sdist_name = f"{PACKAGE}-{args.expected_version}.tar.gz"
    if [path.name for path in artifacts] != sorted((wheel_name, sdist_name)):
        raise CandidateVerificationError("dist must contain exactly one expected wheel and sdist")
    wheel = args.dist / wheel_name
    sdist = args.dist / sdist_name
    wheel_files = _inspect_wheel(wheel, args.expected_version)
    sdist_files = _inspect_sdist(sdist, args.expected_version)
    _metadata(
        wheel_files[f"{PACKAGE}-{args.expected_version}.dist-info/METADATA"],
        args.expected_version,
    )
    _metadata(sdist_files["PKG-INFO"], args.expected_version)
    _runtime_version(wheel_files[f"{PACKAGE}/__init__.py"], args.expected_version)
    _runtime_version(sdist_files["src/ragleakguard/__init__.py"], args.expected_version)

    epoch_text = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch_text is None or not epoch_text.isascii() or not epoch_text.isdigit():
        raise CandidateVerificationError("SOURCE_DATE_EPOCH is required")
    generated = datetime.fromtimestamp(int(epoch_text), timezone.utc).isoformat()
    evidence = {
        "schema": 1,
        "status": "build-verified",
        "source_sha": args.source_sha,
        "source_date_epoch": int(epoch_text),
        "generated_at": generated,
        "version": args.expected_version,
        "python_requires": policy["python_requires"],
        "builder": policy["builder"],
        "actions": policy["actions"],
        "materials": {
            "build_requirements_sha256": _sha256(args.policy.parent / "build-requirements.txt"),
            "release_policy_sha256": _sha256(args.policy),
            "test_constraints_sha256": _sha256(args.policy.parent / "test-constraints.txt"),
        },
        "artifacts": [
            {"filename": wheel.name, "sha256": _sha256(wheel), "size": wheel.stat().st_size},
            {"filename": sdist.name, "sha256": _sha256(sdist), "size": sdist.stat().st_size},
        ],
        "inspection": {
            "forbidden_paths": "passed",
            "metadata": "passed",
            "privacy_canaries": "passed",
            "wheel_members": len(wheel_files),
            "sdist_members": len(sdist_files),
        },
    }
    _atomic_json(args.output, evidence)
    print("Candidate build evidence written after all archive gates passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
