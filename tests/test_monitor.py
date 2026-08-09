"""Monitor v2 construction, state-integrity, lifecycle, and privacy tests."""
import base64
import copy
import json
import os
import secrets

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


def _state_document(records, crypto, scope):
    return json.loads(mon.serialize_state(records, crypto, scope).decode("utf-8"))


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


def test_state_v2_roundtrip_is_authenticated_and_omits_ephemeral_types(tmp_path):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    state = tmp_path / "state.json"

    mon.save_state(str(state), records, crypto, scope, initialize=True)
    loaded = mon.load_state(str(state), crypto, scope)
    on_disk = json.loads(state.read_text(encoding="utf-8"))

    assert loaded["version"] == 2
    assert loaded["records"] == on_disk["records"]
    assert loaded["totals"] == {"records": 1, "findings": 1}
    assert "type_counts" not in state.read_text(encoding="utf-8")
    assert set(on_disk) == {
        "authentication",
        "construction",
        "key_id",
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
        (b'{"version":3,"records":{}}', mon.UnsupportedMonitorStateError),
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


def test_webhook_payload_keeps_existing_contract_with_record_tokens(monkeypatch):
    crypto = _crypto()
    scope, records = _snapshot(crypto)
    token = next(iter(records))
    payload = mon.build_webhook_payload(
        {"new": [token], "changed": [], "resolved": []},
        records,
        "chroma",
        "synthetic-store",
    )
    sent = {}

    def fake_open(request, timeout=10):
        sent["request"] = request
        sent["timeout"] = timeout

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return Response()

    monkeypatch.setattr(mon.urllib.request, "urlopen", fake_open)
    assert payload["new"][0]["record"] == token
    assert payload["new"][0]["types"] == {"EMAIL_ADDRESS": 1}
    assert "synthetic-record-a" not in json.dumps(payload)
    assert mon.post_webhook("https://hooks.invalid/synthetic", payload) == 200
    assert sent["request"].headers["Content-type"] == "application/json"
