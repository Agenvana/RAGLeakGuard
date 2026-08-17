"""Verify that an installed candidate came from an artifact, not the repository."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import sys
from pathlib import Path


def _inside(path: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath((path, parent)) == str(parent)
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-python", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--expected-chroma")
    args = parser.parse_args()

    expected_python = tuple(int(part) for part in args.expected_python.split("."))
    if sys.version_info[:2] != expected_python:
        raise RuntimeError("Python matrix entry differs")

    import ragleakguard
    from ragleakguard.connectors import ChromaConnectorUnavailableError, read_chroma

    module_path = Path(ragleakguard.__file__).resolve()
    workspace = args.workspace.resolve()
    if _inside(module_path, workspace):
        raise RuntimeError("package imported from the repository")
    distribution = importlib.metadata.distribution("ragleakguard")
    if ragleakguard.__version__ != args.expected_version:
        raise RuntimeError("runtime version differs")
    if distribution.version != args.expected_version:
        raise RuntimeError("installed metadata version differs")
    python_specifiers = {
        part.strip()
        for part in distribution.metadata["Requires-Python"].split(",")
    }
    if python_specifiers != {">=3.9", "<3.13"}:
        raise RuntimeError("installed Python metadata differs")
    direct_url = distribution.read_text("direct_url.json")
    if direct_url:
        document = json.loads(direct_url)
        if document.get("dir_info", {}).get("editable") is True:
            raise RuntimeError("editable install is forbidden")
    try:
        read_chroma(object())
    except ChromaConnectorUnavailableError:
        pass
    else:
        raise RuntimeError("direct Chroma boundary did not fail closed")
    if args.expected_chroma is not None:
        if importlib.metadata.version("chromadb") != args.expected_chroma:
            raise RuntimeError("installed Chroma version differs")
    print("Installed artifact import and metadata gates passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
