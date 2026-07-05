"""Monitoring — re-scan a store on a schedule and diff against the last run.

State file: JSON mapping record-key -> a fingerprint of that record's findings
(finding types + counts). Fingerprints and per-type counts ONLY — no raw
sensitive values, no document text, no spans are ever written to the state
file or a webhook payload. That metadata-only rule is load-bearing: the whole
point of this tool is not to become a leak itself.
"""
import hashlib
import json
import os
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

STATE_VERSION = 1

DetectFn = Callable[..., List[Dict[str, Any]]]


def _record_key(item: Dict[str, Any]) -> str:
    return f"{item.get('collection', '')}:{item['id']}"


def _type_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["type"]] = counts.get(f["type"], 0) + 1
    return counts


def fingerprint(findings: List[Dict[str, Any]]) -> str:
    """Stable fingerprint of a record's findings — order-independent, types+counts only."""
    canon = json.dumps(sorted(_type_counts(findings).items()))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]


def build_snapshot(
    items: Iterable[Dict[str, Any]], detect_fn: DetectFn, locale: Optional[str] = None
) -> Dict[str, Dict[str, Any]]:
    """Scan every item and reduce each record to metadata: fingerprint + counts."""
    records: Dict[str, Dict[str, Any]] = {}
    for it in items:
        found = detect_fn(it["text"], locale=locale)
        records[_record_key(it)] = {
            "fp": fingerprint(found),
            "n": len(found),
            "types": _type_counts(found),
        }
    return records


def diff(previous: Dict[str, Dict[str, Any]], current: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
    """Classify records against the last run: new / changed / resolved.

    new      — a record with findings that wasn't tracked before, or findings
               appearing on a previously-clean record.
    changed  — a record whose findings changed but still has some.
    resolved — a record that had findings and now has none (or disappeared).
    """
    new: List[str] = []
    changed: List[str] = []
    resolved: List[str] = []
    for key, rec in current.items():
        old = previous.get(key)
        if old is None:
            if rec["n"] > 0:
                new.append(key)
        elif rec["fp"] != old["fp"]:
            if old.get("n", 0) == 0 and rec["n"] > 0:
                new.append(key)
            elif rec["n"] == 0:
                resolved.append(key)
            else:
                changed.append(key)
    for key, old in previous.items():
        if key not in current and old.get("n", 0) > 0:
            resolved.append(key)
    return {"new": sorted(new), "changed": sorted(changed), "resolved": sorted(resolved)}


def load_state(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_state(path: str, records: Dict[str, Dict[str, Any]], source: str, store_path: str) -> None:
    """Atomic write (tmp + rename) so a crash never leaves a corrupt state file."""
    state = {
        "version": STATE_VERSION,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
        "path": store_path,
        "records": records,
    }
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def build_webhook_payload(
    delta: Dict[str, List[str]],
    current: Dict[str, Dict[str, Any]],
    source: str,
    store_path: str,
) -> Dict[str, Any]:
    """Alert payload — record keys and per-type counts only, never content."""

    def _summarize(keys: List[str]) -> List[Dict[str, Any]]:
        return [
            {"record": k, "findings": current.get(k, {}).get("n", 0), "types": current.get(k, {}).get("types", {})}
            for k in keys
        ]

    totals = {
        "records": len(current),
        "records_with_findings": sum(1 for r in current.values() if r["n"] > 0),
        "findings": sum(r["n"] for r in current.values()),
    }
    return {
        "event": "ragleakguard.monitor",
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "store": {"source": source, "path": store_path},
        "totals": totals,
        "new": _summarize(delta["new"]),
        "changed": _summarize(delta["changed"]),
        "resolved": [{"record": k} for k in delta["resolved"]],
    }


def post_webhook(url: str, payload: Dict[str, Any], timeout: int = 10) -> int:
    """POST the alert as JSON. Returns the HTTP status code."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - user-supplied alert URL
        return resp.status
