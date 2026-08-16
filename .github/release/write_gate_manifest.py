"""Write final candidate evidence only after all required workflow jobs succeed."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path


def _atomic_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=".rlg-candidate-gate-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
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
    parser.add_argument("--build-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build = json.loads(args.build_evidence.read_text(encoding="utf-8"))
    if build.get("schema") != 1 or build.get("status") != "build-verified":
        raise RuntimeError("build evidence is incomplete")
    source_sha = os.environ.get("RLG_SOURCE_SHA")
    if source_sha != build.get("source_sha"):
        raise RuntimeError("workflow source SHA differs from build evidence")
    run_id = os.environ.get("GITHUB_RUN_ID")
    repository = os.environ.get("GITHUB_REPOSITORY")
    server = os.environ.get("GITHUB_SERVER_URL")
    if not run_id or not repository or not server:
        raise RuntimeError("workflow identity is incomplete")
    document = {
        "schema": 1,
        "status": "ready-for-independent-review",
        "source_sha": source_sha,
        "version": build["version"],
        "artifacts": build["artifacts"],
        "candidate_run": f"{server}/{repository}/actions/runs/{run_id}",
        "gates": {
            "artifact_install_wheel": "passed",
            "artifact_install_sdist": "passed",
            "base_matrix": "passed",
            "build_and_archive_inspection": "passed",
            "wp7c_private_matrix": "passed",
            "wp7d_public_matrix": "passed",
        },
        "publication_authorized": False,
    }
    _atomic_json(args.output, document)
    print("Candidate gate evidence written for independent review; publication remains unauthorized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
