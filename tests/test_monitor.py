"""Monitor v3 outbox, protocol-v2, integrity, lifecycle, and privacy tests."""
import base64
import copy
import hashlib
import hmac
import inspect
import json
import os
import secrets
import socket
import threading
import time
from pathlib import Path

import pytest

from ragleakguard import monitor as mon


def _crypto():
    return mon.MonitorCrypto(
        mon.MonitorKey(secrets.token_hex(16), secrets.token_bytes(32))
    )


def _finding(value="synthetic-detected-a", finding_type="EMAIL_ADDRESS", **extra):
    finding = {"type": finding_type, "text": value}
    finding.update(extra)
    return finding


def _item(record_id="synthetic-record-a", text="EMAIL_A", collection="synthetic-notes"):
    return {
        "id": record_id,
        "text": text,
        "metadata": {},
        "collection": collection,
    }


def fake_detect(text, locale=None):
    findings = []
    if "EMAIL_A" in text:
        findings.append(_finding("synthetic-detected-a"))
    if "EMAIL_B" in text:
        findings.append(_finding("synthetic-detected-b"))
    for _ in range(text.count("PHONE_A")):
        findings.append(_finding("synthetic-phone-a", "PHONE_NUMBER"))
    return findings


def _snapshot(crypto, source="chroma", path="synthetic-store", items=None):
    scope = crypto.scope_token(source, path)
    records = mon.build_snapshot(
        items or [_item()], fake_detect, crypto, scope
    )
    return scope, records


def _state_document(records, crypto, scope, pending_alert=None):
    return json.loads(
        mon.serialize_state(records, crypto, scope, pending_alert).decode("utf-8")
    )


def _reauth(document, crypto):
    body = {key: value for key, value in document.items() if key != "authentication"}
    document["authentication"] = crypto.authenticate_state(mon._canonical_json(body))


def _write_json(path, document):
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")


def _all_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, nested in value.items():
            yield from _all_strings(key)
            yield from _all_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _all_strings(nested)


def test_equal_type_equal_count_value_replacement_changes_full_fingerprint():
    crypto = _crypto()
    before = mon.fingerprint([_finding("synthetic-value-before")], crypto)
    after = mon.fingerprint([_finding("synthetic-value-after")], crypto)

    assert before != after
    assert len(before) == len(after) == 64
    assert bytes.fromhex(before) and bytes.fromhex(after)


def test_equal_type_equal_count_record_replacement_is_classified_changed():
    crypto = _crypto()
    scope = crypto.scope_token("chroma", "synthetic-store")
    before = mon.build_snapshot(
        [_item(text="EMAIL_A")], fake_detect, crypto, scope
    )
    after = mon.build_snapshot(
        [_item(text="EMAIL_B")], fake_detect, crypto, scope
    )
    token = next(iter(before))

    assert before[token]["finding_count"] == after[token]["finding_count"] == 1
    assert before[token]["type_counts"] == after[token]["type_counts"] == {
        "EMAIL_ADDRESS": 1
    }
    assert mon.diff(before, after) == {
        "new": [],
        "changed": [token],
        "resolved": [],
    }


def test_finding_multiset_reordering_and_duplicate_multiplicity():
    crypto = _crypto()
    email = _finding("synthetic-email")
    phone = _finding("synthetic-phone", "PHONE_NUMBER")

    assert mon.fingerprint([email, phone], crypto) == mon.fingerprint(
        [phone, email], crypto
    )
    assert mon.fingerprint([email], crypto) != mon.fingerprint(
        [email, email], crypto
    )
    assert mon.fingerprint([email, email], crypto) != mon.fingerprint(
        [email, phone], crypto
    )
    assert mon.fingerprint([], crypto) != mon.fingerprint([email], crypto)


def test_position_score_and_dictionary_order_do_not_change_identity():
    crypto = _crypto()
    first = {
        "type": "EMAIL_ADDRESS",
        "text": "synthetic-value",
        "start": 1,
        "end": 10,
        "score": 0.1,
    }
    second = {
        "score": 0.99,
        "end": 200,
        "text": "synthetic-value",
        "start": 100,
        "type": "EMAIL_ADDRESS",
    }
    assert mon.fingerprint([first], crypto) == mon.fingerprint([second], crypto)


def test_typed_length_prefixes_are_unambiguous_and_unicode_is_not_normalized():
    crypto = _crypto()
    assert mon.canonicalize_finding(_finding("BC", "A")) != mon.canonicalize_finding(
        _finding("C", "AB")
    )
    assert mon.canonicalize_finding(_finding("a|b:c")) != mon.canonicalize_finding(
        _finding("a", "EMAIL_ADDRESS")
    )
    assert mon.fingerprint([_finding("é")], crypto) != mon.fingerprint(
        [_finding("e\u0301")], crypto
    )


@pytest.mark.parametrize(
    "finding",
    [
        {},
        {"type": "EMAIL_ADDRESS"},
        {"text": "synthetic"},
        {"type": "", "text": "synthetic"},
        {"type": "email", "text": "synthetic"},
        {"type": "EMAIL_ADDRESS", "text": ""},
        {"type": "EMAIL_ADDRESS", "text": 7},
        {"type": "EMAIL_ADDRESS", "text": "\ud800"},
    ],
)
def test_malformed_or_missing_finding_identity_fails_closed(finding):
    with pytest.raises(mon.MonitorFingerprintError):
        mon.fingerprint([finding], _crypto())


def test_purpose_separation_and_independent_key_unlinkability():
    first = _crypto()
    second = _crypto()
    identity = mon.canonicalize_finding(_finding("synthetic-value"))
    scope_first = first.scope_token("chroma", "synthetic-store")
    scope_second = second.scope_token("chroma", "synthetic-store")
    record_first = first.record_token(
        bytes.fromhex(scope_first), "synthetic-notes", "synthetic-record"
    )
    record_second = second.record_token(
        bytes.fromhex(scope_second), "synthetic-notes", "synthetic-record"
    )
    outputs = {
        first.finding_token(identity).hex(),
        first.aggregate_fingerprint([first.finding_token(identity)]),
        scope_first,
        record_first,
        first.authenticate_state(b"synthetic-state"),
    }

    assert len(outputs) == 5
    assert all(len(value) == 64 for value in outputs)
    assert scope_first != scope_second
    assert record_first != record_second
    assert mon.fingerprint([_finding("synthetic-value")], first) != mon.fingerprint(
        [_finding("synthetic-value")], second
    )
    derived = {
        first._finding_key,
        first._aggregate_key,
        first._record_key,
        first._scope_key,
        first._state_auth_key,
    }
    assert len(derived) == 5


def test_forced_same_run_finding_token_collision_fails_closed():
    constant = lambda identity: b"x" * 32
    with pytest.raises(mon.MonitorCollisionError):
        mon._fingerprint_with_token_digest(
            [_finding("synthetic-a"), _finding("synthetic-b")],
            _crypto(),
            constant,
        )


def test_forced_cross_run_single_token_collision_documents_residual_behavior():
    """No raw prior identity exists, so a forced cross-run token collision is equal."""
    crypto = _crypto()
    constant = lambda identity: b"x" * 32
    first = mon._fingerprint_with_token_digest(
        [_finding("synthetic-a")], crypto, constant
    )
    second = mon._fingerprint_with_token_digest(
        [_finding("synthetic-b")], crypto, constant
    )
    assert first == second


@pytest.mark.parametrize(
    "item",
    [
        {},
        {"id": "record", "text": "synthetic"},
        {"collection": "notes", "text": "synthetic"},
        {"collection": "notes", "id": "record"},
        {"collection": "", "id": "record", "text": "synthetic"},
        {"collection": "notes", "id": "", "text": "synthetic"},
        {"collection": "notes", "id": 1, "text": "synthetic"},
        {"collection": "notes", "id": "record", "text": None},
    ],
)
def test_malformed_record_identity_or_text_fails_closed(item):
    crypto = _crypto()
    scope = crypto.scope_token("chroma", "synthetic-store")
    with pytest.raises(mon.MonitorFingerprintError):
        mon.build_snapshot([item], fake_detect, crypto, scope)


def test_duplicate_record_identity_fails_instead_of_overwriting():
    crypto = _crypto()
    scope = crypto.scope_token("chroma", "synthetic-store")
    with pytest.raises(mon.MonitorCollisionError):
        mon.build_snapshot([_item(), _item()], fake_detect, crypto, scope)


def test_diff_classifies_new_changed_and_resolved_tokens():
    token_clean = "1" * 64
    token_dirty = "2" * 64
    token_gone = "3" * 64
    token_fixed = "4" * 64
    token_new = "5" * 64
    previous = {
        token_clean: {"fingerprint": "a" * 64, "finding_count": 0},
        token_dirty: {"fingerprint": "b" * 64, "finding_count": 1},
        token_gone: {"fingerprint": "c" * 64, "finding_count": 1},
        token_fixed: {"fingerprint": "d" * 64, "finding_count": 1},
    }
    current = {
        token_clean: {"fingerprint": "e" * 64, "finding_count": 1},
        token_dirty: {"fingerprint": "f" * 64, "finding_count": 1},
        token_fixed: {"fingerprint": "0" * 64, "finding_count": 0},
        token_new: {"fingerprint": "9" * 64, "finding_count": 1},
    }
    delta = mon.diff(previous, current)
    assert delta == {
        "new": [token_clean, token_new],
        "changed": [token_dirty],
        "resolved": [token_gone, token_fixed],
    }


def test_state_v3_roundtrip_is_authenticated_and_omits_ephemeral_types(tmp_path):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    state = tmp_path / "state.json"

    mon.save_state(str(state), records, crypto, scope, initialize=True)
    loaded = mon.load_state(str(state), crypto, scope)
    on_disk = json.loads(state.read_text(encoding="utf-8"))

    assert loaded["version"] == 3
    assert loaded["pending_alert"] is None
    assert loaded["records"] == on_disk["records"]
    assert loaded["totals"] == {"records": 1, "findings": 1}
    assert "type_counts" not in state.read_text(encoding="utf-8")
    assert set(on_disk) == {
        "authentication",
        "construction",
        "key_id",
        "pending_alert",
        "records",
        "scope_token",
        "totals",
        "version",
    }


def test_serialized_state_recursive_privacy_canaries(tmp_path):
    canaries = {
        "document": "document-text-canary",
        "detected": "detected-value-canary",
        "span": "span-canary",
        "record": "record-id-canary",
        "collection": "collection-canary",
        "tenant": "tenant-canary",
        "store_path": "store-path-canary",
        "state_path": "state-path-canary",
        "secret": "secret-key-canary",
        "reversible": "reversible-identifier-canary",
        "exception": "exception-text-canary",
    }
    material = (canaries["secret"].encode("utf-8") + b"x" * 32)[:32]
    crypto = mon.MonitorCrypto(mon.MonitorKey(secrets.token_hex(16), material))
    scope = crypto.scope_token("chroma", canaries["store_path"])
    item = {
        "id": canaries["record"] + canaries["reversible"],
        "collection": canaries["collection"] + canaries["tenant"],
        "text": canaries["document"],
        "metadata": {},
    }

    def detect_canary(text, locale=None):
        return [
            {
                "type": "EMAIL_ADDRESS",
                "text": canaries["detected"],
                "start": canaries["span"],
                "end": 1,
                "score": 1.0,
            }
        ]

    records = mon.build_snapshot([item], detect_canary, crypto, scope)
    state = tmp_path / (canaries["state_path"] + ".json")
    mon.save_state(str(state), records, crypto, scope, initialize=True)
    document = json.loads(state.read_text(encoding="utf-8"))
    serialized_strings = set(_all_strings(document))
    serialized = json.dumps(document)

    for canary in canaries.values():
        assert canary not in serialized
        assert all(canary not in value for value in serialized_strings)
    assert base64.b64encode(material).decode("ascii") not in serialized


def test_pending_alert_state_is_privacy_minimal_and_contains_no_attempt_bytes(tmp_path):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    pending = mon.new_pending_alert(
        clock=lambda: 2_000_000_000,
        delivery_id_source=lambda size: b"d" * 16,
    )
    state = tmp_path / "state.json"
    mon.save_state(
        str(state), records, crypto, scope, pending_alert=pending, initialize=True
    )
    document = json.loads(state.read_text(encoding="utf-8"))
    assert set(document["pending_alert"]) == {
        "attempts",
        "delivery_id",
        "event",
        "next_attempt_at",
        "webhook_version",
    }
    serialized = json.dumps(document)
    for canary in (
        "https://url-authority-query-canary.invalid/private",
        "webhook-secret-canary",
        "signing-key-id-canary",
        "timestamp-header-canary",
        "nonce-canary",
        "signature-canary",
        "prepared-request-canary",
        "source-store-path-canary",
        "collection-tenant-canary",
        "record-id-token-canary",
        "finding-type-count-value-canary",
        "document-text-canary",
        "exception-response-canary",
    ):
        assert canary not in serialized


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.update({"unknown": "field"}),
        lambda doc: doc["totals"].update({"unknown": 1}),
        lambda doc: next(iter(doc["records"].values())).update({"unknown": 1}),
        lambda doc: doc.update({"key_id": "A" * 32}),
        lambda doc: doc.update({"scope_token": "0" * 63}),
        lambda doc: doc["totals"].update({"records": True}),
        lambda doc: doc["totals"].update({"findings": -1}),
        lambda doc: doc["totals"].update({"findings": mon.MAX_TOTAL_FINDINGS + 1}),
        lambda doc: doc["totals"].update({"records": mon.MAX_RECORDS + 1}),
        lambda doc: doc["totals"].update({"records": 0}),
        lambda doc: next(iter(doc["records"].values())).update(
            {"finding_count": True}
        ),
        lambda doc: next(iter(doc["records"].values())).update(
            {"finding_count": -1}
        ),
        lambda doc: (
            next(iter(doc["records"].values())).update({"finding_count": 0}),
            doc["totals"].update({"findings": 0}),
        ),
        lambda doc: next(iter(doc["records"].values())).update(
            {"fingerprint": "f" * 63}
        ),
        lambda doc: doc["records"].update(
            {"UPPER": {"finding_count": 0, "fingerprint": "0" * 64}}
        ),
    ],
    ids=[
        "unknown-top-level",
        "unknown-total",
        "unknown-record",
        "invalid-key-id",
        "invalid-scope-token",
        "boolean-record-total",
        "negative-finding-total",
        "finding-total-over-bound",
        "record-total-over-bound",
        "inconsistent-record-total",
        "boolean-finding-count",
        "negative-finding-count",
        "zero-count-nonempty-fingerprint",
        "invalid-fingerprint",
        "invalid-record-token",
    ],
)
def test_strict_state_schema_rejects_invalid_or_inconsistent_fields(tmp_path, mutate):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    document = _state_document(records, crypto, scope)
    mutate(document)
    _reauth(document, crypto)
    state = tmp_path / "state.json"
    _write_json(state, document)

    with pytest.raises(mon.MonitorStateError):
        mon.load_state(str(state), crypto, scope)


def test_state_authentication_detects_body_and_authenticator_tampering(tmp_path):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    original = _state_document(records, crypto, scope)
    state = tmp_path / "state.json"

    body_tampered = copy.deepcopy(original)
    next(iter(body_tampered["records"].values()))["fingerprint"] = "e" * 64
    _write_json(state, body_tampered)
    with pytest.raises(mon.MonitorStateError):
        mon.load_state(str(state), crypto, scope)

    auth_tampered = copy.deepcopy(original)
    auth_tampered["authentication"] = "0" * 64
    _write_json(state, auth_tampered)
    with pytest.raises(mon.MonitorStateError):
        mon.load_state(str(state), crypto, scope)


def test_pending_alert_schema_is_strict_bounded_and_authenticated(tmp_path):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    pending = mon.new_pending_alert(
        clock=lambda: 2_000_000_000,
        delivery_id_source=lambda size: bytes.fromhex("ab" * 16),
    )
    expected = {
        "attempts": 0,
        "delivery_id": "ab" * 16,
        "event": "ragleakguard.monitor.exposure-change",
        "next_attempt_at": 2_000_000_000,
        "webhook_version": 2,
    }
    assert pending == expected

    state = tmp_path / "state.json"
    mon.save_state(
        str(state), records, crypto, scope, pending_alert=pending, initialize=True
    )
    loaded = mon.load_state(str(state), crypto, scope)
    assert loaded["pending_alert"] == expected

    mutations = [
        lambda value: value.update({"unknown": "field"}),
        lambda value: value.update({"event": "wrong"}),
        lambda value: value.update({"webhook_version": True}),
        lambda value: value.update({"webhook_version": 1}),
        lambda value: value.update({"delivery_id": "A" * 32}),
        lambda value: value.update({"attempts": True}),
        lambda value: value.update({"attempts": -1}),
        lambda value: value.update({"attempts": mon.MAX_PENDING_ALERT_ATTEMPTS + 1}),
        lambda value: value.update({"next_attempt_at": True}),
        lambda value: value.update({"next_attempt_at": -1}),
        lambda value: value.update({"next_attempt_at": mon.MAX_UNIX_TIME + 1}),
    ]
    for mutate in mutations:
        document = _state_document(records, crypto, scope, pending)
        mutate(document["pending_alert"])
        _reauth(document, crypto)
        _write_json(state, document)
        with pytest.raises(mon.MonitorStateError):
            mon.load_state(str(state), crypto, scope)

    document = _state_document(records, crypto, scope, pending)
    document["pending_alert"]["attempts"] = 1
    _write_json(state, document)
    with pytest.raises(mon.MonitorStateError):
        mon.load_state(str(state), crypto, scope)


def test_authenticated_v2_loads_without_pending_and_next_save_migrates_to_v3(
    tmp_path,
):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    document = _state_document(records, crypto, scope)
    document.pop("pending_alert")
    document["version"] = 2
    _reauth(document, crypto)
    state = tmp_path / "state.json"
    _write_json(state, document)
    before = state.read_bytes()

    loaded = mon.load_state(str(state), crypto, scope)
    assert loaded["version"] == 2
    assert "pending_alert" not in loaded
    assert state.read_bytes() == before

    mon.save_state(str(state), loaded["records"], crypto, scope)
    migrated = mon.load_state(str(state), crypto, scope)
    assert migrated["version"] == 3
    assert migrated["pending_alert"] is None


def test_v2_to_v3_replacement_failure_preserves_authenticated_v2(
    tmp_path, monkeypatch
):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    document = _state_document(records, crypto, scope)
    document.pop("pending_alert")
    document["version"] = 2
    _reauth(document, crypto)
    state = tmp_path / "state.json"
    _write_json(state, document)
    before = state.read_bytes()
    monkeypatch.setattr(
        mon,
        "_replace_state",
        lambda *args: (_ for _ in ()).throw(OSError("migration-exception-canary")),
    )

    with pytest.raises(mon.MonitorWriteError) as caught:
        mon.save_state(str(state), records, crypto, scope)
    assert "migration-exception-canary" not in str(caught.value)
    assert state.read_bytes() == before
    assert not list(tmp_path.glob(".rlg-monitor-*.tmp"))


def test_key_rotation_and_store_scope_mismatch_preserve_state(tmp_path):
    first = _crypto()
    scope, records = _snapshot(first)
    state = tmp_path / "state.json"
    mon.save_state(str(state), records, first, scope, initialize=True)
    before = state.read_bytes()

    different_key = _crypto()
    with pytest.raises(mon.MonitorKeyMismatchError):
        mon.load_state(str(state), different_key, scope)
    with pytest.raises(mon.MonitorKeyMismatchError):
        mon.load_state(
            str(state), first, first.scope_token("chroma", "different-store")
        )
    same_id_different_material = mon.MonitorCrypto(
        mon.MonitorKey(first.key_id, secrets.token_bytes(32))
    )
    with pytest.raises(mon.MonitorStateError):
        mon.load_state(str(state), same_id_different_material, scope)
    assert state.read_bytes() == before


@pytest.mark.parametrize(
    ("contents", "error"),
    [
        (b'{"version":1,"records":{}}', mon.LegacyMonitorStateError),
        (b'{"version":1,"records":{"x":{}}}', mon.LegacyMonitorStateError),
        (b'{"version":1', mon.MonitorStateError),
        (b'{"version":1,"records":', mon.MonitorStateError),
        (b'{"version":4,"records":{}}', mon.UnsupportedMonitorStateError),
        (b'{"version":0,"records":{}}', mon.UnsupportedMonitorStateError),
    ],
    ids=[
        "valid-v1",
        "inconsistent-v1",
        "truncated-v1",
        "malformed-v1",
        "future-version",
        "older-unsupported-version",
    ],
)
def test_legacy_malformed_and_unsupported_state_rejection_preserves_bytes(
    tmp_path, contents, error
):
    crypto = _crypto()
    scope = crypto.scope_token("chroma", "synthetic-store")
    state = tmp_path / "state.json"
    state.write_bytes(contents)

    with pytest.raises(error):
        mon.load_state(str(state), crypto, scope)
    assert state.read_bytes() == contents
    assert not list(tmp_path.glob(".rlg-monitor-*.tmp"))


def test_duplicate_json_members_are_rejected(tmp_path):
    crypto = _crypto()
    scope = crypto.scope_token("chroma", "synthetic-store")
    state = tmp_path / "state.json"
    state.write_bytes(b'{"version":2,"version":2}')
    with pytest.raises(mon.MonitorStateError):
        mon.load_state(str(state), crypto, scope)


def test_explicit_initialization_refuses_valid_or_invalid_existing_state(tmp_path):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    state = tmp_path / "state.json"

    mon.save_state(str(state), records, crypto, scope, initialize=True)
    valid = state.read_bytes()
    with pytest.raises(mon.MonitorInitializationError):
        mon.save_state(str(state), records, crypto, scope, initialize=True)
    assert state.read_bytes() == valid

    state.write_bytes(b"invalid-state-sentinel")
    invalid = state.read_bytes()
    with pytest.raises(mon.MonitorInitializationError):
        mon.save_state(str(state), records, crypto, scope, initialize=True)
    assert state.read_bytes() == invalid


def test_temporary_write_failure_preserves_prior_checkpoint_and_cleans_temp(
    tmp_path, monkeypatch
):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    state = tmp_path / "state.json"
    mon.save_state(str(state), records, crypto, scope, initialize=True)
    before = state.read_bytes()

    def fail_after_partial_write(handle, encoded):
        handle.write(encoded[:10])
        raise OSError("exception-canary")

    monkeypatch.setattr(mon, "_write_state_bytes", fail_after_partial_write)
    with pytest.raises(mon.MonitorWriteError) as caught:
        mon.save_state(str(state), records, crypto, scope)
    assert "exception-canary" not in str(caught.value)
    assert state.read_bytes() == before
    assert not list(tmp_path.glob(".rlg-monitor-*.tmp"))


def test_state_fsync_failure_preserves_prior_checkpoint_and_cleans_temp(
    tmp_path, monkeypatch
):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    state = tmp_path / "state.json"
    mon.save_state(str(state), records, crypto, scope, initialize=True)
    before = state.read_bytes()
    monkeypatch.setattr(
        mon.os,
        "fsync",
        lambda fd: (_ for _ in ()).throw(OSError("fsync-exception-canary")),
    )

    with pytest.raises(mon.MonitorWriteError) as caught:
        mon.save_state(
            str(state),
            records,
            crypto,
            scope,
            pending_alert=mon.new_pending_alert(clock=lambda: 1),
        )
    assert "fsync-exception-canary" not in str(caught.value)
    assert state.read_bytes() == before
    assert not list(tmp_path.glob(".rlg-monitor-*.tmp"))


def test_atomic_replace_failure_preserves_prior_checkpoint_and_cleans_temp(
    tmp_path, monkeypatch
):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    state = tmp_path / "state.json"
    mon.save_state(str(state), records, crypto, scope, initialize=True)
    before = state.read_bytes()

    def fail_replace(tmp_name, target_name):
        raise OSError("replace-exception-canary")

    monkeypatch.setattr(mon, "_replace_state", fail_replace)
    with pytest.raises(mon.MonitorWriteError) as caught:
        mon.save_state(str(state), records, crypto, scope)
    assert "replace-exception-canary" not in str(caught.value)
    assert state.read_bytes() == before
    assert not list(tmp_path.glob(".rlg-monitor-*.tmp"))


def test_oversized_state_is_rejected_before_any_temporary_artifact(
    tmp_path, monkeypatch
):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    state = tmp_path / "state.json"
    monkeypatch.setattr(mon, "MAX_STATE_FILE_BYTES", 1)

    with pytest.raises(mon.MonitorStateError):
        mon.save_state(str(state), records, crypto, scope, initialize=True)
    assert not state.exists()
    assert not list(tmp_path.iterdir())


def test_key_generation_uses_csprng_and_refuses_overwrite(tmp_path, monkeypatch):
    calls = []

    def token_bytes(length):
        calls.append(("bytes", length))
        return secrets.SystemRandom().randbytes(length)

    def token_hex(length):
        calls.append(("hex", length))
        return secrets.SystemRandom().randbytes(length).hex()

    monkeypatch.setattr(mon.secrets, "token_bytes", token_bytes)
    monkeypatch.setattr(mon.secrets, "token_hex", token_hex)
    path = tmp_path / "monitor-key.json"
    key_id = mon.generate_key_file(str(path))
    before = path.read_bytes()
    loaded = mon.load_key_file(str(path))

    assert calls == [("hex", 16), ("bytes", 32)]
    assert loaded.key_id == key_id
    assert len(loaded._material) == 32
    assert loaded._material not in before
    assert repr(loaded).find(base64.b64encode(loaded._material).decode("ascii")) == -1
    with pytest.raises(mon.MonitorKeyError):
        mon.generate_key_file(str(path))
    assert path.read_bytes() == before
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.update({"purpose": "wrong-purpose"}),
        lambda doc: doc.update({"construction": "wrong-construction"}),
        lambda doc: doc.update({"version": 2}),
        lambda doc: doc.update({"key_id": "z" * 32}),
        lambda doc: doc.update({"key": base64.b64encode(b"short").decode("ascii")}),
        lambda doc: doc.update({"unknown": "field"}),
    ],
    ids=[
        "wrong-purpose",
        "wrong-construction",
        "wrong-version",
        "malformed-key-id",
        "weak-key",
        "unknown-field",
    ],
)
def test_wrong_purpose_weak_or_incompatible_key_material_fails_static(
    tmp_path, mutate
):
    path = tmp_path / "monitor-key.json"
    mon.generate_key_file(str(path))
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    _write_json(path, document)

    with pytest.raises(mon.MonitorKeyError) as caught:
        mon.load_key_file(str(path))
    assert "synthetic" not in str(caught.value)
    assert str(path) not in str(caught.value)


@pytest.mark.parametrize("contents", [b"", b"{", b"[]", b"not-json"])
def test_missing_malformed_or_unreadable_key_material_fails_static(tmp_path, contents):
    path = tmp_path / "key-path-canary"
    if contents:
        path.write_bytes(contents)
    with pytest.raises(mon.MonitorKeyError) as caught:
        mon.load_key_file(str(path))
    assert "key-path-canary" not in str(caught.value)


def test_pending_alert_generation_uses_128_bit_csprng_and_static_failures(monkeypatch):
    calls = []

    def delivery_source(size):
        calls.append(size)
        return bytes.fromhex("11" * 16)

    pending = mon.new_pending_alert(
        clock=lambda: 1234,
        delivery_id_source=delivery_source,
    )
    assert calls == [16]
    assert pending["delivery_id"] == "11" * 16
    assert pending["next_attempt_at"] == 1234

    for source in (
        lambda size: b"short",
        lambda size: (_ for _ in ()).throw(RuntimeError("exception-canary")),
    ):
        with pytest.raises(mon.WebhookPreparationError) as caught:
            mon.new_pending_alert(clock=lambda: 1234, delivery_id_source=source)
        assert "exception-canary" not in str(caught.value)


def test_bounded_exponential_full_jitter_formula_and_endpoints():
    observed = []

    def low(envelope):
        observed.append(envelope)
        return 0

    assert mon.retry_backoff_seconds(1, jitter_source=low) == 1
    assert mon.retry_backoff_seconds(2, jitter_source=low) == 1
    assert mon.retry_backoff_seconds(8, jitter_source=low) == 1
    assert observed == [30, 60, 3600]

    assert mon.retry_backoff_seconds(
        1, jitter_source=lambda envelope: envelope - 1
    ) == 30
    assert mon.retry_backoff_seconds(
        2, jitter_source=lambda envelope: envelope - 1
    ) == 60
    assert mon.retry_backoff_seconds(
        mon.MAX_PENDING_ALERT_ATTEMPTS,
        jitter_source=lambda envelope: envelope - 1,
    ) == mon.WEBHOOK_RETRY_MAX_SECONDS


def test_backoff_uses_csprng_default_and_rejects_bad_jitter(monkeypatch):
    calls = []
    monkeypatch.setattr(
        mon.secrets,
        "randbelow",
        lambda envelope: calls.append(envelope) or envelope - 1,
    )
    assert mon.retry_backoff_seconds(1) == 30
    assert calls == [30]

    for value in (-1, 30, True, "0"):
        with pytest.raises(mon.WebhookRetryError):
            mon.retry_backoff_seconds(1, jitter_source=lambda envelope, v=value: v)


def test_pending_due_clock_rollback_future_bounds_and_overflow_fail_closed():
    pending = mon.new_pending_alert(
        clock=lambda: 100,
        delivery_id_source=lambda size: b"a" * 16,
    )
    assert not mon.pending_alert_is_due(pending, clock=lambda: 99)
    assert mon.pending_alert_is_due(pending, clock=lambda: 100)

    far_future = dict(pending, next_attempt_at=mon.MAX_UNIX_TIME)
    assert not mon.pending_alert_is_due(far_future, clock=lambda: 100)

    exhausted = dict(pending, attempts=mon.MAX_PENDING_ALERT_ATTEMPTS)
    with pytest.raises(mon.WebhookRetryError):
        mon.pending_alert_is_due(exhausted, clock=lambda: 100)
    with pytest.raises(mon.WebhookRetryError):
        mon.advance_pending_alert(exhausted, clock=lambda: 100)
    with pytest.raises(mon.WebhookRetryError):
        mon.pending_alert_is_due(
            pending,
            clock=lambda: mon.MAX_UNIX_TIME - mon.WEBHOOK_RETRY_MAX_SECONDS + 1,
        )


def test_failed_attempt_advances_metadata_without_changing_delivery_id():
    pending = mon.new_pending_alert(
        clock=lambda: 100,
        delivery_id_source=lambda size: b"b" * 16,
    )
    first = mon.advance_pending_alert(
        pending,
        clock=lambda: 200,
        jitter_source=lambda envelope: envelope - 1,
    )
    second = mon.advance_pending_alert(
        first,
        clock=lambda: 300,
        jitter_source=lambda envelope: 0,
    )
    assert first["delivery_id"] == second["delivery_id"] == pending["delivery_id"]
    assert first["attempts"] == 1
    assert first["next_attempt_at"] == 230
    assert second["attempts"] == 2
    assert second["next_attempt_at"] == 301


WEBHOOK_VECTOR_SECRET = bytes(range(32))
WEBHOOK_VECTOR_KEY_ID = "00112233445566778899aabbccddeeff"
WEBHOOK_VECTOR_URL = "https://receiver.example.test/hooks/rlg?channel=security"
WEBHOOK_VECTOR_TIMESTAMP = 1786320000
WEBHOOK_VECTOR_NONCE = "0123456789abcdeffedcba9876543210"
WEBHOOK_VECTOR_DELIVERY_ID = "ffeeddccbbaa99887766554433221100"
WEBHOOK_VECTOR_SIGNATURE = (
    "v2=fd7ce5c478368ffeb37c38d04d9ae5cb18e2a45b507e870ab9f48829ce13a438"
)
WEBHOOK_HEADER_NAMES = {
    "Host",
    "Content-Length",
    "Content-Type",
    "User-Agent",
    "X-RAGLeakGuard-Webhook-Version",
    "X-RAGLeakGuard-Key-Id",
    "X-RAGLeakGuard-Delivery-Id",
    "X-RAGLeakGuard-Timestamp",
    "X-RAGLeakGuard-Nonce",
    "X-RAGLeakGuard-Signature",
}


def _vector_secret():
    return mon.WebhookSecret(WEBHOOK_VECTOR_KEY_ID, WEBHOOK_VECTOR_SECRET)


def _prepared_vector():
    return mon.prepare_webhook_request(
        True,
        mon.validate_webhook_url(WEBHOOK_VECTOR_URL),
        _vector_secret(),
        WEBHOOK_VECTOR_DELIVERY_ID,
        clock=lambda: WEBHOOK_VECTOR_TIMESTAMP,
        nonce_source=lambda size: bytes.fromhex(WEBHOOK_VECTOR_NONCE),
    )


def _header_pairs(prepared):
    return list(prepared.headers.items())


def test_webhook_secret_generation_loading_and_exclusive_creation(tmp_path, monkeypatch):
    calls = []

    def token_hex(length):
        calls.append(("hex", length))
        return WEBHOOK_VECTOR_KEY_ID

    def token_bytes(length):
        calls.append(("bytes", length))
        return WEBHOOK_VECTOR_SECRET

    monkeypatch.setattr(mon.secrets, "token_hex", token_hex)
    monkeypatch.setattr(mon.secrets, "token_bytes", token_bytes)
    path = tmp_path / "webhook-secret.json"

    key_id = mon.generate_webhook_secret_file(str(path))
    before = path.read_bytes()
    document = json.loads(before.decode("utf-8"))
    loaded = mon.load_webhook_secret_file(str(path))

    assert calls == [("hex", 16), ("bytes", 32)]
    assert key_id == WEBHOOK_VECTOR_KEY_ID
    assert set(document) == {
        "construction", "key_id", "purpose", "secret", "version"
    }
    assert document == {
        "construction": "RLG-WEBHOOK-HMAC-SHA256-v2",
        "key_id": WEBHOOK_VECTOR_KEY_ID,
        "purpose": "ragleakguard.webhook-signing.v2",
        "secret": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "version": 2,
    }
    assert loaded.key_id == WEBHOOK_VECTOR_KEY_ID
    assert loaded._material == WEBHOOK_VECTOR_SECRET
    assert document["secret"] not in repr(loaded)
    with pytest.raises(mon.WebhookSecretError):
        mon.generate_webhook_secret_file(str(path))
    assert path.read_bytes() == before
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "contents",
    [
        b"",
        b"{",
        b"[]",
        b'\xff',
        b'{"version":2,"version":2}',
        json.dumps({
            "version": True,
            "purpose": "ragleakguard.webhook-signing.v2",
            "construction": "RLG-WEBHOOK-HMAC-SHA256-v2",
            "key_id": WEBHOOK_VECTOR_KEY_ID,
            "secret": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        }).encode(),
        json.dumps({
            "version": 2,
            "purpose": "ragleakguard.monitor",
            "construction": "RLG-MONITOR-HMAC-SHA256-v1",
            "key_id": WEBHOOK_VECTOR_KEY_ID,
            "key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        }).encode(),
        json.dumps({
            "version": 2,
            "purpose": "ragleakguard.webhook-signing.v2",
            "construction": "wrong-construction",
            "key_id": WEBHOOK_VECTOR_KEY_ID,
            "secret": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        }).encode(),
        json.dumps({
            "version": 2,
            "purpose": "ragleakguard.webhook-signing.v2",
            "construction": "RLG-WEBHOOK-HMAC-SHA256-v2",
            "key_id": "A" * 32,
            "secret": "c2hvcnQ=",
            "unknown": "field",
        }).encode(),
    ],
    ids=[
        "empty", "truncated", "non-object", "invalid-utf8", "duplicate",
        "boolean-version", "monitor-key", "wrong-construction", "unknown-and-weak",
    ],
)
def test_webhook_secret_loader_rejects_malformed_material_with_static_errors(
    tmp_path, contents
):
    path = tmp_path / "secret-path-canary"
    path.write_bytes(contents)
    with pytest.raises(mon.WebhookSecretError) as caught:
        mon.load_webhook_secret_file(str(path))
    rendered = str(caught.value)
    assert "secret-path-canary" not in rendered
    assert WEBHOOK_VECTOR_KEY_ID not in rendered
    assert "AAECAwQ" not in rendered


def test_webhook_secret_loader_rejects_oversize_directory_symlink_and_broad_mode(
    tmp_path
):
    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"x" * (mon.MAX_WEBHOOK_SECRET_FILE_BYTES + 1))
    with pytest.raises(mon.WebhookSecretError):
        mon.load_webhook_secret_file(str(oversized))
    with pytest.raises(mon.WebhookSecretError):
        mon.load_webhook_secret_file(str(tmp_path))

    target = tmp_path / "target"
    mon.generate_webhook_secret_file(str(target))
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pass
    else:
        with pytest.raises(mon.WebhookSecretError):
            mon.load_webhook_secret_file(str(link))

    if os.name != "nt":
        target.chmod(0o644)
        with pytest.raises(mon.WebhookSecretError):
            mon.load_webhook_secret_file(str(target))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.pop("secret"),
        lambda doc: doc.update({"unknown": "field"}),
        lambda doc: doc.update({"version": 1}),
        lambda doc: doc.update({"purpose": "wrong-purpose"}),
        lambda doc: doc.update({"construction": "wrong-construction"}),
        lambda doc: doc.update({"key_id": "z" * 32}),
        lambda doc: doc.update({"secret": "not-base64"}),
        lambda doc: doc.update({"secret": base64.b64encode(b"short").decode("ascii")}),
        lambda doc: doc.update({
            "secret": base64.b64encode(WEBHOOK_VECTOR_SECRET).decode("ascii") + "="
        }),
    ],
    ids=[
        "missing", "unknown", "wrong-version", "wrong-purpose",
        "wrong-construction", "bad-key-id", "bad-base64", "weak", "noncanonical-base64",
    ],
)
def test_webhook_secret_schema_has_an_exact_allowlist(tmp_path, mutate):
    path = tmp_path / "secret.json"
    mon.generate_webhook_secret_file(str(path))
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(mon.WebhookSecretError):
        mon.load_webhook_secret_file(str(path))


def test_protocol_v1_secret_cannot_masquerade_as_v2(tmp_path):
    path = tmp_path / "legacy-v1-secret.json"
    path.write_text(
        json.dumps(
            {
                "construction": "RLG-WEBHOOK-HMAC-SHA256-v1",
                "key_id": WEBHOOK_VECTOR_KEY_ID,
                "purpose": "ragleakguard.webhook-signing",
                "secret": base64.b64encode(WEBHOOK_VECTOR_SECRET).decode("ascii"),
                "version": 1,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(mon.WebhookSecretError):
        mon.load_webhook_secret_file(str(path))


def test_webhook_secret_generation_failure_removes_partial_file(tmp_path, monkeypatch):
    path = tmp_path / "secret.json"
    monkeypatch.setattr(
        mon.os,
        "fsync",
        lambda fd: (_ for _ in ()).throw(OSError("exception-canary")),
    )

    with pytest.raises(mon.WebhookSecretError) as caught:
        mon.generate_webhook_secret_file(str(path))
    assert not path.exists()
    assert "exception-canary" not in str(caught.value)


def test_version_2_body_headers_and_published_hmac_vector_are_exact():
    prepared = _prepared_vector()

    assert mon.build_webhook_body() is prepared.body
    assert prepared.body == (
        b'{"event":"ragleakguard.monitor.exposure-change","version":2}'
    )
    assert len(prepared.body) == 60
    assert prepared.target.authority == "receiver.example.test"
    assert prepared.target.request_target == "/hooks/rlg?channel=security"
    assert set(prepared.headers) == WEBHOOK_HEADER_NAMES
    assert dict(prepared.headers) == {
        "Host": "receiver.example.test",
        "Content-Length": "60",
        "Content-Type": "application/json",
        "User-Agent": "RAGLeakGuard-Webhook/2",
        "X-RAGLeakGuard-Webhook-Version": "2",
        "X-RAGLeakGuard-Key-Id": WEBHOOK_VECTOR_KEY_ID,
        "X-RAGLeakGuard-Delivery-Id": WEBHOOK_VECTOR_DELIVERY_ID,
        "X-RAGLeakGuard-Timestamp": str(WEBHOOK_VECTOR_TIMESTAMP),
        "X-RAGLeakGuard-Nonce": WEBHOOK_VECTOR_NONCE,
        "X-RAGLeakGuard-Signature": WEBHOOK_VECTOR_SIGNATURE,
    }
    assert "receiver.example.test" not in repr(prepared)
    assert WEBHOOK_VECTOR_KEY_ID not in repr(prepared)
    assert "channel=security" not in repr(prepared)


def test_published_vector_matches_independent_framing_implementation():
    prepared = _prepared_vector()

    def independent_frame(label, value):
        label_bytes = label.encode("ascii")
        return (
            len(label_bytes).to_bytes(4, "big")
            + label_bytes
            + len(value).to_bytes(8, "big")
            + value
        )

    fields = [
        ("construction", b"RLG-WEBHOOK-HMAC-SHA256-v2"),
        ("method", b"POST"),
        ("authority", b"receiver.example.test"),
        ("request-target", b"/hooks/rlg?channel=security"),
        ("content-length", b"60"),
        ("content-type", b"application/json"),
        ("user-agent", b"RAGLeakGuard-Webhook/2"),
        ("webhook-version", b"2"),
        ("key-id", WEBHOOK_VECTOR_KEY_ID.encode("ascii")),
        ("delivery-id", WEBHOOK_VECTOR_DELIVERY_ID.encode("ascii")),
        ("timestamp", str(WEBHOOK_VECTOR_TIMESTAMP).encode("ascii")),
        ("nonce", WEBHOOK_VECTOR_NONCE.encode("ascii")),
        ("body", prepared.body),
    ]
    message = b"".join(independent_frame(label, value) for label, value in fields)
    independent_signature = "v2=" + hmac.new(
        WEBHOOK_VECTOR_SECRET, message, hashlib.sha256
    ).hexdigest()

    assert independent_signature == WEBHOOK_VECTOR_SIGNATURE
    assert independent_signature == prepared.headers["X-RAGLeakGuard-Signature"]


def test_prepared_request_recursively_excludes_application_privacy_canaries():
    prepared = _prepared_vector()
    serialized = json.dumps(dict(prepared.headers)) + prepared.body.decode("ascii")
    for canary in (
        "source-store-canary",
        "state-path-canary",
        "collection-tenant-canary",
        "record-id-canary",
        "record-token-canary",
        "document-text-canary",
        "detected-value-canary",
        "span-canary",
        "finding-type-canary",
        "finding-count-canary",
        "monitor-key-canary",
        "exception-text-canary",
    ):
        assert canary not in serialized
        assert canary not in repr(prepared)
    assert base64.b64encode(WEBHOOK_VECTOR_SECRET).decode("ascii") not in serialized


def test_request_builder_accepts_only_trigger_target_secret_delivery_clock_nonce():
    assert tuple(inspect.signature(mon.prepare_webhook_request).parameters) == (
        "alert_trigger",
        "target",
        "secret",
        "delivery_id",
        "clock",
        "nonce_source",
    )


@pytest.mark.parametrize(
    ("url", "authority", "target"),
    [
        ("https://EXAMPLE.test", "example.test", "/"),
        ("https://EXAMPLE.test:443?x=%2F", "example.test", "/?x=%2F"),
        ("https://EXAMPLE.test:8443/a%2Fb?x=1?2", "example.test:8443", "/a%2Fb?x=1?2"),
        ("HTTPS://example.test/path?", "example.test", "/path?"),
        ("https://[2001:db8::1]:9443/a", "[2001:db8::1]:9443", "/a"),
    ],
)
def test_webhook_url_validation_normalizes_authority_and_preserves_target(
    url, authority, target
):
    validated = mon.validate_webhook_url(url)
    assert validated.authority == authority
    assert validated.request_target == target


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/hook",
        "ftp://example.test/hook",
        "https://",
        "https://user:pass@example.test/hook",
        "https://example.test/hook#fragment",
        "https://example.test:0/hook",
        "https://example.test:65536/hook",
        "https://example.test:/hook",
        "https://example.test/%",
        "https://example.test/%0G",
        "https://example.test/white space",
        "https://example.test/\ncontrol",
        "https://例.example/hook",
        "https://example.test\\hook",
        "https://[not-ipv6]/hook",
        "https://[2001:db8::1]authority-junk/hook",
        "https://[fe80::1%25zone]/hook",
        "x" * 2049,
    ],
)
def test_webhook_url_validation_rejects_unsafe_or_malformed_urls(url):
    with pytest.raises(mon.WebhookConfigurationError) as caught:
        mon.validate_webhook_url(url)
    assert url not in str(caught.value)


def test_receiver_accepts_published_vector_and_uses_constant_time_comparison(
    monkeypatch
):
    prepared = _prepared_vector()
    calls = []
    real_compare = mon.hmac.compare_digest

    def compare(left, right):
        calls.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(mon.hmac, "compare_digest", compare)
    cache = mon.WebhookReplayCache()
    processed = []
    result = mon.verify_webhook_request(
        method="POST",
        authority=prepared.target.authority,
        request_target=prepared.target.request_target,
        headers=_header_pairs(prepared),
        body=prepared.body,
        secrets_by_key_id={WEBHOOK_VECTOR_KEY_ID: WEBHOOK_VECTOR_SECRET},
        receiver_now=WEBHOOK_VECTOR_TIMESTAMP,
        replay_cache=cache,
        delivery_store=mon.WebhookMemoryDeliveryStore(),
        process_event=lambda: processed.append("processed"),
    )
    assert result == mon.WebhookVerificationResult(duplicate=False)
    assert processed == ["processed"]
    assert calls


@pytest.mark.parametrize(
    "tamper",
    [
        lambda request: request.update(method="GET"),
        lambda request: request.update(authority="other.example.test"),
        lambda request: request.update(request_target="/hooks/other?channel=security"),
        lambda request: request.update(body=request["body"] + b" "),
        lambda request: request["headers"].__setitem__("Host", "other.example.test"),
        lambda request: request["headers"].__setitem__("Content-Length", "59"),
        lambda request: request["headers"].__setitem__("Content-Type", "text/plain"),
        lambda request: request["headers"].__setitem__("User-Agent", "Python/3"),
        lambda request: request["headers"].__setitem__("X-RAGLeakGuard-Webhook-Version", "1"),
        lambda request: request["headers"].__setitem__("X-RAGLeakGuard-Key-Id", "f" * 32),
        lambda request: request["headers"].__setitem__("X-RAGLeakGuard-Delivery-Id", "e" * 32),
        lambda request: request["headers"].__setitem__("X-RAGLeakGuard-Timestamp", "01786320000"),
        lambda request: request["headers"].__setitem__("X-RAGLeakGuard-Nonce", "A" * 32),
        lambda request: request["headers"].__setitem__("X-RAGLeakGuard-Signature", "v2=" + "A" * 64),
        lambda request: request["headers"].__setitem__("Authorization", "canary"),
        lambda request: request["headers"].pop("Content-Type"),
        lambda request: request.update(request_target="/" + "x" * 2048),
    ],
    ids=[
        "method", "authority", "target", "body", "host", "length", "type",
        "agent", "version", "key-id", "delivery-id", "timestamp", "nonce", "signature",
        "extra-header", "missing-header", "over-length-url",
    ],
)
def test_receiver_rejects_tampering_and_header_allowlist_violations(tamper):
    prepared = _prepared_vector()
    request = {
        "method": "POST",
        "authority": prepared.target.authority,
        "request_target": prepared.target.request_target,
        "headers": dict(prepared.headers),
        "body": prepared.body,
    }
    tamper(request)
    with pytest.raises(mon.WebhookVerificationError) as caught:
        mon.verify_webhook_request(
            **request,
            secrets_by_key_id={WEBHOOK_VECTOR_KEY_ID: WEBHOOK_VECTOR_SECRET},
            receiver_now=WEBHOOK_VECTOR_TIMESTAMP,
            replay_cache=mon.WebhookReplayCache(),
            delivery_store=mon.WebhookMemoryDeliveryStore(),
            process_event=lambda: None,
        )
    assert str(caught.value) == "Webhook request verification failed."


def test_receiver_rejects_wrong_unknown_and_retired_keys_and_duplicate_headers():
    prepared = _prepared_vector()
    base = dict(
        method="POST",
        authority=prepared.target.authority,
        request_target=prepared.target.request_target,
        headers=_header_pairs(prepared),
        body=prepared.body,
        receiver_now=WEBHOOK_VECTOR_TIMESTAMP,
        replay_cache=mon.WebhookReplayCache(),
        delivery_store=mon.WebhookMemoryDeliveryStore(),
        process_event=lambda: None,
    )
    for secrets_by_key_id in ({}, {WEBHOOK_VECTOR_KEY_ID: b"x" * 32}):
        with pytest.raises(mon.WebhookVerificationError):
            mon.verify_webhook_request(
                **base, secrets_by_key_id=secrets_by_key_id
            )
    with pytest.raises(mon.WebhookVerificationError):
        mon.verify_webhook_request(
            **dict(base, headers=base["headers"] + [("Host", "receiver.example.test")]),
            secrets_by_key_id={WEBHOOK_VECTOR_KEY_ID: WEBHOOK_VECTOR_SECRET},
        )


def test_receiver_authenticates_before_freshness_and_replay_acceptance():
    prepared = _prepared_vector()

    class Cache:
        def __init__(self):
            self.calls = []

        def accept(self, *args):
            self.calls.append(args)
            return True

    cache = Cache()
    invalid_headers = dict(prepared.headers)
    invalid_headers["X-RAGLeakGuard-Signature"] = "v2=" + "0" * 64
    delivery_calls = []

    class DeliveryStore:
        def process_once(self, *args):
            delivery_calls.append(args)
            return True
    with pytest.raises(mon.WebhookVerificationError):
        mon.verify_webhook_request(
            method="POST",
            authority=prepared.target.authority,
            request_target=prepared.target.request_target,
            headers=list(invalid_headers.items()),
            body=prepared.body,
            secrets_by_key_id={WEBHOOK_VECTOR_KEY_ID: WEBHOOK_VECTOR_SECRET},
            receiver_now=WEBHOOK_VECTOR_TIMESTAMP,
            replay_cache=cache,
            delivery_store=DeliveryStore(),
            process_event=lambda: None,
        )
    assert not cache.calls

    with pytest.raises(mon.WebhookVerificationError):
        mon.verify_webhook_request(
            method="POST",
            authority=prepared.target.authority,
            request_target=prepared.target.request_target,
            headers=_header_pairs(prepared),
            body=prepared.body,
            secrets_by_key_id={WEBHOOK_VECTOR_KEY_ID: WEBHOOK_VECTOR_SECRET},
            receiver_now=WEBHOOK_VECTOR_TIMESTAMP + 301,
            replay_cache=cache,
            delivery_store=DeliveryStore(),
            process_event=lambda: None,
        )
    assert not cache.calls
    assert not delivery_calls


@pytest.mark.parametrize(
    ("offset", "accepted"),
    [(-301, False), (-300, True), (0, True), (300, True), (301, False)],
)
def test_receiver_timestamp_freshness_boundaries(offset, accepted):
    timestamp = 2_000_000_000
    prepared = mon.prepare_webhook_request(
        True,
        mon.validate_webhook_url("https://receiver.example.test/hook"),
        _vector_secret(),
        WEBHOOK_VECTOR_DELIVERY_ID,
        clock=lambda: timestamp + offset,
        nonce_source=lambda size: bytes.fromhex(WEBHOOK_VECTOR_NONCE),
    )
    call = lambda: mon.verify_webhook_request(
        method="POST",
        authority=prepared.target.authority,
        request_target=prepared.target.request_target,
        headers=_header_pairs(prepared),
        body=prepared.body,
        secrets_by_key_id={WEBHOOK_VECTOR_KEY_ID: WEBHOOK_VECTOR_SECRET},
        receiver_now=timestamp,
        replay_cache=mon.WebhookReplayCache(),
        delivery_store=mon.WebhookMemoryDeliveryStore(),
        process_event=lambda: None,
    )
    if accepted:
        assert call()
    else:
        with pytest.raises(mon.WebhookVerificationError):
            call()


def test_receiver_replay_cache_is_atomic_and_retains_future_skew_until_expiry():
    cache = mon.WebhookReplayCache()
    now = 2_000_000_000
    timestamp = now + 300
    prepared = mon.prepare_webhook_request(
        True,
        mon.validate_webhook_url("https://receiver.example.test/hook"),
        _vector_secret(),
        WEBHOOK_VECTOR_DELIVERY_ID,
        clock=lambda: timestamp,
        nonce_source=lambda size: bytes.fromhex(WEBHOOK_VECTOR_NONCE),
    )
    delivery_store = mon.WebhookMemoryDeliveryStore()

    def verify(receiver_now):
        return mon.verify_webhook_request(
            method="POST",
            authority=prepared.target.authority,
            request_target=prepared.target.request_target,
            headers=_header_pairs(prepared),
            body=prepared.body,
            secrets_by_key_id={WEBHOOK_VECTOR_KEY_ID: WEBHOOK_VECTOR_SECRET},
            receiver_now=receiver_now,
            replay_cache=cache,
            delivery_store=delivery_store,
            process_event=lambda: None,
        )

    assert verify(now)
    with pytest.raises(mon.WebhookVerificationError):
        verify(timestamp + 300)
    with pytest.raises(mon.WebhookVerificationError):
        verify(timestamp + 301)

    results = []
    cache = mon.WebhookReplayCache()
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            verify(now)
        except mon.WebhookVerificationError:
            results.append(False)
        else:
            results.append(True)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
    assert results.count(False) == 7


def test_receiver_replay_cache_retains_nonce_through_exact_expiry_second():
    cache = mon.WebhookReplayCache()
    timestamp = 2_000_000_000
    assert cache.accept(WEBHOOK_VECTOR_KEY_ID, WEBHOOK_VECTOR_NONCE, timestamp, timestamp)
    assert not cache.accept(
        WEBHOOK_VECTOR_KEY_ID,
        WEBHOOK_VECTOR_NONCE,
        timestamp,
        timestamp + mon.WEBHOOK_FRESHNESS_SECONDS,
    )
    assert cache.accept(
        WEBHOOK_VECTOR_KEY_ID,
        WEBHOOK_VECTOR_NONCE,
        timestamp,
        timestamp + mon.WEBHOOK_FRESHNESS_SECONDS + 1,
    )


def test_receiver_rotation_overlap_accepts_distinct_key_ids():
    old = _prepared_vector()
    new_secret = mon.WebhookSecret("f" * 32, b"z" * 32)
    new = mon.prepare_webhook_request(
        True,
        mon.validate_webhook_url(WEBHOOK_VECTOR_URL),
        new_secret,
        "00" * 16,
        clock=lambda: WEBHOOK_VECTOR_TIMESTAMP,
        nonce_source=lambda size: b"y" * 16,
    )
    cache = mon.WebhookReplayCache()
    delivery_store = mon.WebhookMemoryDeliveryStore()
    mapping = {
        WEBHOOK_VECTOR_KEY_ID: WEBHOOK_VECTOR_SECRET,
        new_secret.key_id: new_secret._material,
    }
    for prepared in (old, new):
        assert mon.verify_webhook_request(
            method="POST",
            authority=prepared.target.authority,
            request_target=prepared.target.request_target,
            headers=_header_pairs(prepared),
            body=prepared.body,
            secrets_by_key_id=mapping,
            receiver_now=WEBHOOK_VECTOR_TIMESTAMP,
            replay_cache=cache,
            delivery_store=delivery_store,
            process_event=lambda: None,
        )


def test_receiver_shared_delivery_store_returns_duplicate_success_without_reprocessing():
    first = _prepared_vector()
    retry = mon.prepare_webhook_request(
        True,
        mon.validate_webhook_url(WEBHOOK_VECTOR_URL),
        _vector_secret(),
        WEBHOOK_VECTOR_DELIVERY_ID,
        clock=lambda: WEBHOOK_VECTOR_TIMESTAMP + 1,
        nonce_source=lambda size: b"r" * 16,
    )
    shared_delivery_store = mon.WebhookMemoryDeliveryStore()
    processed = []

    def receive(prepared, replay_cache):
        return mon.verify_webhook_request(
            method="POST",
            authority=prepared.target.authority,
            request_target=prepared.target.request_target,
            headers=_header_pairs(prepared),
            body=prepared.body,
            secrets_by_key_id={WEBHOOK_VECTOR_KEY_ID: WEBHOOK_VECTOR_SECRET},
            receiver_now=WEBHOOK_VECTOR_TIMESTAMP + 1,
            replay_cache=replay_cache,
            delivery_store=shared_delivery_store,
            process_event=lambda: processed.append("processed"),
        )

    first_result = receive(first, mon.WebhookReplayCache())
    duplicate_result = receive(retry, mon.WebhookReplayCache())
    assert first_result == mon.WebhookVerificationResult(duplicate=False)
    assert duplicate_result == mon.WebhookVerificationResult(duplicate=True)
    assert processed == ["processed"]
    assert "redacted" in repr(shared_delivery_store).lower()


def test_receiver_requires_atomic_delivery_interface_and_static_processor_failure():
    prepared = _prepared_vector()
    base = dict(
        method="POST",
        authority=prepared.target.authority,
        request_target=prepared.target.request_target,
        headers=_header_pairs(prepared),
        body=prepared.body,
        secrets_by_key_id={WEBHOOK_VECTOR_KEY_ID: WEBHOOK_VECTOR_SECRET},
        receiver_now=WEBHOOK_VECTOR_TIMESTAMP,
        replay_cache=mon.WebhookReplayCache(),
    )
    with pytest.raises(mon.WebhookVerificationError):
        mon.verify_webhook_request(
            **base,
            delivery_store=object(),
            process_event=lambda: None,
        )

    with pytest.raises(mon.WebhookVerificationError) as caught:
        mon.verify_webhook_request(
            **dict(base, replay_cache=mon.WebhookReplayCache()),
            delivery_store=mon.WebhookMemoryDeliveryStore(),
            process_event=lambda: (_ for _ in ()).throw(
                RuntimeError("processor-exception-canary")
            ),
        )
    assert "processor-exception-canary" not in str(caught.value)


class _FakeRawSocket:
    def __init__(self, events):
        self.events = events
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        self.events.append(("connect", address))

    def close(self):
        self.events.append(("raw-close",))


class _FakeTlsSocket:
    def __init__(self, events, response):
        self.events = events
        self.response = bytearray(response)
        self.timeouts = []
        self.sent_objects = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def do_handshake(self):
        self.events.append(("handshake",))

    def sendall(self, data):
        self.sent_objects.append(data)
        self.events.append(("send", bytes(data)))

    def recv(self, size):
        self.events.append(("recv-size", size))
        if not self.response:
            return b""
        chunk = bytes(self.response[:size])
        del self.response[:size]
        return chunk

    def close(self):
        self.events.append(("tls-close",))


class _FakeTlsContext:
    def __init__(self, events, tls):
        self.events = events
        self.tls = tls
        self.check_hostname = True
        self.verify_mode = 2

    def wrap_socket(self, raw, server_hostname, do_handshake_on_connect):
        self.events.append(
            ("wrap", server_hostname, do_handshake_on_connect, self.check_hostname, self.verify_mode)
        )
        return self.tls


def _install_fake_transport(monkeypatch, response):
    events = []
    raw = _FakeRawSocket(events)
    tls = _FakeTlsSocket(events, response)
    context = _FakeTlsContext(events, tls)
    monkeypatch.setattr(
        mon,
        "_resolve_addresses",
        lambda *args: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.10", 443))
        ],
    )
    monkeypatch.setattr(mon.socket, "socket", lambda *args: raw)
    monkeypatch.setattr(mon.ssl, "create_default_context", lambda: context)
    return events, raw, tls, context


def test_transport_sends_exact_http11_allowlist_body_object_and_ignores_body(
    monkeypatch
):
    response = b"HTTP/1.1 204 No Content\r\nX-Receiver: ignored\r\n\r\nresponse-body-canary"
    events, raw, tls, context = _install_fake_transport(monkeypatch, response)
    prepared = _prepared_vector()

    assert mon.post_webhook(prepared) == 204
    sends = [event[1] for event in events if event[0] == "send"]
    assert len(sends) == 2
    head = sends[0].decode("ascii")
    assert head.startswith("POST /hooks/rlg?channel=security HTTP/1.1\r\n")
    wire_headers = head.split("\r\n")[1:-2]
    assert {line.split(":", 1)[0] for line in wire_headers} == WEBHOOK_HEADER_NAMES
    assert wire_headers == [
        f"{name}: {prepared.headers[name]}" for name in mon.WEBHOOK_HEADER_ORDER
    ]
    assert sends[1] == mon.WEBHOOK_BODY_BYTES
    assert tls.sent_objects[1] is prepared.body
    assert all(event != ("recv-size", 2) for event in events)
    assert all(
        event != ("recv-size", len(b"response-body-canary")) for event in events
    )
    assert tls.response == bytearray(b"response-body-canary")
    assert ("wrap", "receiver.example.test", False, True, 2) in events
    assert events.count(("handshake",)) == 1
    assert raw.timeouts and tls.timeouts
    assert all(0 < timeout <= mon.WEBHOOK_DEADLINE_SECONDS for timeout in raw.timeouts)
    assert all(0 < timeout <= mon.WEBHOOK_DEADLINE_SECONDS for timeout in tls.timeouts)


def test_transport_uses_one_decreasing_monotonic_deadline_across_all_phases(
    monkeypatch
):
    _, raw, tls, _ = _install_fake_transport(
        monkeypatch, b"HTTP/1.1 200 OK\r\n\r\n"
    )
    ticks = [100.0]

    def monotonic():
        value = ticks[0]
        ticks[0] += 0.01
        return value

    monkeypatch.setattr(mon.time, "monotonic", monotonic)

    assert mon.post_webhook(_prepared_vector()) == 200
    observed = raw.timeouts + tls.timeouts
    assert observed
    assert all(
        later < earlier for earlier, later in zip(observed, observed[1:])
    )
    assert observed[0] < mon.WEBHOOK_DEADLINE_SECONDS


@pytest.mark.parametrize("status", [199, 300, 400, 500, 599])
def test_transport_rejects_status_boundaries(status, monkeypatch):
    events, _, _, _ = _install_fake_transport(
        monkeypatch, f"HTTP/1.1 {status} Synthetic\r\n\r\n".encode("ascii")
    )
    with pytest.raises(mon.WebhookTransportError):
        mon.post_webhook(_prepared_vector())
    assert sum(event[0] == "send" for event in events) == 2


@pytest.mark.parametrize("status", [200, 299])
def test_transport_accepts_status_boundaries(status, monkeypatch):
    _install_fake_transport(
        monkeypatch, f"HTTP/1.1 {status} Synthetic\r\n\r\n".encode("ascii")
    )
    assert mon.post_webhook(_prepared_vector()) == status


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "location",
    [
        "https://receiver.example.test/other",
        "https://other.example.test/hook",
        "http://receiver.example.test/hook",
    ],
)
def test_transport_never_follows_redirects(status, location, monkeypatch):
    response = (
        f"HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\n\r\n"
    ).encode("ascii")
    events, _, _, _ = _install_fake_transport(monkeypatch, response)
    with pytest.raises(mon.WebhookTransportError):
        mon.post_webhook(_prepared_vector())
    assert sum(event[0] == "connect" for event in events) == 1
    assert sum(event[0] == "send" for event in events) == 2


@pytest.mark.parametrize(
    "response",
    [
        b"",
        b"HTTP/1.0 200 OK\r\n\r\n",
        b"HTTP/1.1 20 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\n\n",
        b"HTTP/1.1 200 OK\r\n folded\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nBad Header\r\n\r\n",
    ],
)
def test_transport_rejects_malformed_response_headers(response, monkeypatch):
    _install_fake_transport(monkeypatch, response)
    with pytest.raises(mon.WebhookTransportError) as caught:
        mon.post_webhook(_prepared_vector())
    assert "receiver" not in str(caught.value).lower()


def test_transport_rejects_oversized_response_headers(monkeypatch):
    response = b"HTTP/1.1 200 OK\r\nX-Fill: " + (
        b"x" * mon.MAX_WEBHOOK_RESPONSE_HEADER_BYTES
    )
    _install_fake_transport(monkeypatch, response)
    with pytest.raises(mon.WebhookTransportError) as caught:
        mon.post_webhook(_prepared_vector())
    assert str(caught.value) == "Webhook delivery failed."


def test_dns_is_bounded_by_the_monotonic_end_to_end_deadline(monkeypatch):
    release = threading.Event()

    def blocked_dns(*args, **kwargs):
        release.wait(1)
        return []

    monkeypatch.setattr(mon.socket, "getaddrinfo", blocked_dns)
    monkeypatch.setattr(mon, "WEBHOOK_DEADLINE_SECONDS", 0.03)
    started = time.monotonic()
    try:
        with pytest.raises(mon.WebhookTransportError):
            mon.post_webhook(_prepared_vector())
    finally:
        release.set()
    assert time.monotonic() - started < 0.5


@pytest.mark.parametrize(
    "phase",
    ["dns", "connect", "tls-context", "tls-handshake", "transmit", "response"],
)
def test_transport_phase_failures_are_one_static_error(phase, monkeypatch):
    _, _, tls, _ = _install_fake_transport(
        monkeypatch, b"HTTP/1.1 200 OK\r\n\r\n"
    )

    def failure(*args, **kwargs):
        raise OSError("transport-exception-canary")

    if phase == "dns":
        monkeypatch.setattr(mon, "_resolve_addresses", failure)
    elif phase == "connect":
        monkeypatch.setattr(mon, "_connect_address", failure)
    elif phase == "tls-context":
        monkeypatch.setattr(mon.ssl, "create_default_context", failure)
    elif phase == "tls-handshake":
        monkeypatch.setattr(tls, "do_handshake", failure)
    elif phase == "transmit":
        monkeypatch.setattr(tls, "sendall", failure)
    else:
        monkeypatch.setattr(tls, "recv", failure)

    with pytest.raises(mon.WebhookTransportError) as caught:
        mon.post_webhook(_prepared_vector())
    assert str(caught.value) == "Webhook delivery failed."
    assert "transport-exception-canary" not in str(caught.value)


def test_transport_rejects_mutated_prepared_body_before_network(monkeypatch):
    prepared = _prepared_vector()
    mutated = mon.PreparedWebhook(
        prepared.target,
        prepared.body + b"x",
        prepared.headers,
    )
    calls = []
    monkeypatch.setattr(
        mon, "_resolve_addresses", lambda *args: calls.append(args)
    )

    with pytest.raises(mon.WebhookTransportError):
        mon.post_webhook(mutated)
    assert not calls


def test_manually_inconsistent_target_is_rejected_before_network(monkeypatch):
    target = mon.WebhookTarget(
        host="receiver.example.test",
        port=443,
        authority="different.example.test",
        request_target="/hook",
    )
    calls = []
    monkeypatch.setattr(
        mon, "_resolve_addresses", lambda *args: calls.append(args)
    )

    with pytest.raises(mon.WebhookPreparationError):
        mon.prepare_webhook_request(
            True,
            target,
            _vector_secret(),
            WEBHOOK_VECTOR_DELIVERY_ID,
            clock=lambda: WEBHOOK_VECTOR_TIMESTAMP,
            nonce_source=lambda size: bytes.fromhex(WEBHOOK_VECTOR_NONCE),
        )
    assert not calls


def test_preparation_rejects_bad_clock_nonce_and_false_trigger_with_static_errors():
    target = mon.validate_webhook_url("https://receiver.example.test/hook")
    cases = [
        dict(alert_trigger=False),
        dict(clock=lambda: -1),
        dict(clock=lambda: float("nan")),
        dict(clock=lambda: mon.MAX_UNIX_TIME + 1),
        dict(clock=lambda: "bad"),
        dict(delivery_id="A" * 32),
        dict(nonce_source=lambda size: b"short"),
        dict(nonce_source=lambda size: (_ for _ in ()).throw(RuntimeError("exception-canary"))),
    ]
    for overrides in cases:
        kwargs = dict(
            alert_trigger=True,
            target=target,
            secret=_vector_secret(),
            delivery_id=WEBHOOK_VECTOR_DELIVERY_ID,
            clock=lambda: WEBHOOK_VECTOR_TIMESTAMP,
            nonce_source=lambda size: bytes.fromhex(WEBHOOK_VECTOR_NONCE),
        )
        kwargs.update(overrides)
        with pytest.raises(mon.WebhookPreparationError) as caught:
            mon.prepare_webhook_request(**kwargs)
        assert "exception-canary" not in str(caught.value)


def test_public_webhook_protocol_records_vector_lifecycle_and_residual_risks():
    protocol = (
        Path(__file__).resolve().parents[1] / "docs" / "WEBHOOK_PROTOCOL.md"
    ).read_text(encoding="utf-8")

    for exact in (
        '{"event":"ragleakguard.monitor.exposure-change","version":2}',
        WEBHOOK_VECTOR_SIGNATURE,
        "RLG-WEBHOOK-HMAC-SHA256-v2",
        "abs(receiver_now - timestamp) <= 300",
        "timestamp + 300",
        "Windows DACL",
        "durable, atomic delivery-ID store",
        "pending alert blocks source access",
        "exactly-once",
    ):
        assert exact in protocol


@pytest.mark.parametrize("readme", ["README.md", "README.zh-TW.md"])
def test_readme_webhook_setup_requires_dedicated_verifier_and_secret(readme):
    text = (Path(__file__).resolve().parents[1] / readme).read_text(encoding="utf-8")
    section = text.split("## Monitor", maxsplit=1)[1].split("\n## ", maxsplit=1)[0]

    assert "generate-webhook-secret" in section
    assert "--webhook-secret-file" in section
    assert "docs/WEBHOOK_PROTOCOL.md" in section
    assert "exit 5" in section
    assert "Slack" in section
    assert "incompatib" in section or "不相容" in section
    assert "exactly-once" in section
