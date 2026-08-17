"""Download, byte-verify, and install the exact candidate spaCy model."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


MAX_MODEL_BYTES = 16 * 1024 * 1024
MODEL_FILENAME = "en_core_web_sm-3.7.1-py3-none-any.whl"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--size", required=True, type=int)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()

    if not args.url.startswith(
        "https://github.com/explosion/spacy-models/releases/download/"
    ):
        raise RuntimeError("spaCy model URL is outside the exact upstream release boundary")
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        raise RuntimeError("spaCy model SHA-256 is malformed")
    if args.size <= 0 or args.size > MAX_MODEL_BYTES:
        raise RuntimeError("spaCy model size is outside the download bound")

    destination = args.destination.resolve()
    if destination.name != MODEL_FILENAME:
        raise RuntimeError("spaCy model destination must preserve the exact wheel filename")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".rlg-spacy-model-", suffix=".whl", dir=destination.parent
    )
    digest = hashlib.sha256()
    observed_size = 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            with urllib.request.urlopen(args.url, timeout=120) as response:
                while chunk := response.read(1024 * 1024):
                    observed_size += len(chunk)
                    if observed_size > MAX_MODEL_BYTES:
                        raise RuntimeError("spaCy model download exceeded the bound")
                    digest.update(chunk)
                    output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if observed_size != args.size or digest.hexdigest() != args.sha256:
            raise RuntimeError("spaCy model bytes differ from release policy")
        os.replace(temporary_name, destination)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise

    subprocess.run(
        [sys.executable, "-m", "pip", "install", str(destination)],
        check=True,
        timeout=300,
    )
    print("Exact spaCy model digest verified before installation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
