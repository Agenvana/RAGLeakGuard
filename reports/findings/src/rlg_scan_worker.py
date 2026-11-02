"""RAGLeakGuard scan worker: runs the tool "as shipped" inside its own supported
environment and returns findings to scam_kit.py over a JSON file.

Why a worker: RAGLeakGuard's `detect` extra pins spaCy >=3.7,<3.8 and numpy <2.
The shared scamenv (spaCy 3.8.16, numpy 2.4.6, the pins Reports #1 and #3 measured
Presidio on) cannot satisfy them, so an "as shipped" claim needs the tool to run in
the environment its own package metadata supports: reports/tools/rlgenv, built from
`pip install -e <checkout>[detect]` (see reports/tools/requirements-rlg.txt).

Protocol (stdlib only on this side):
    python rlg_scan_worker.py <request.json> <response.json>
request  = {"texts": [str, ...], "locale": null | "au"}
response = {"findings": [[[type, score, start, end], ...] per text],
            "environment": {...versions, commit, dirty...}}
"""

from __future__ import annotations

import json
import os
import subprocess
import sys


def environment() -> dict:
    import ragleakguard
    from importlib.metadata import version, PackageNotFoundError
    out = {"python": sys.version.split()[0], "ragleakguard": ragleakguard.__version__}
    for pkg in ("spacy", "numpy", "presidio-analyzer", "en-core-web-sm"):
        try:
            out[pkg] = version(pkg)
        except PackageNotFoundError:
            out[pkg] = None
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(ragleakguard.__file__))))
    try:
        out["commit"] = subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"], text=True).strip()
        out["dirty"] = bool(subprocess.check_output(["git", "-C", root, "status", "--porcelain"], text=True).strip())
    except Exception as exc:  # noqa: BLE001
        out["commit"] = f"unknown ({exc})"
    out["root_basename"] = os.path.basename(root)
    out["venv"] = sys.prefix
    return out


def main(req_path: str, resp_path: str) -> None:
    from ragleakguard.detect import detect
    with open(req_path, encoding="utf-8") as fh:
        req = json.load(fh)
    locale = req.get("locale")
    findings = []
    for text in req["texts"]:
        findings.append([[f["type"], f["score"], f["start"], f["end"]] for f in detect(text, locale=locale)])
    with open(resp_path, "w", encoding="utf-8") as fh:
        json.dump({"findings": findings, "environment": environment()}, fh)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
