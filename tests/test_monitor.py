"""Monitor: fingerprint stability, diff classification, state roundtrip, payload hygiene."""
import json

from ragleakguard import monitor as mon


def fake_detect(text, locale=None):
    """Deterministic stand-in for the real detector: one finding per marker word."""
    findings = []
    for word, ftype in (("EMAILISH", "EMAIL_ADDRESS"), ("PHONEISH", "PHONE_NUMBER")):
        for _ in range(text.count(word)):
            findings.append({"type": ftype, "text": "raw-value-that-must-never-leak"})
    return findings


def _item(id_, text, collection="notes"):
    return {"id": id_, "text": text, "metadata": {}, "collection": collection}


def test_fingerprint_is_stable_and_order_independent():
    a = [{"type": "EMAIL_ADDRESS"}, {"type": "PHONE_NUMBER"}]
    b = [{"type": "PHONE_NUMBER"}, {"type": "EMAIL_ADDRESS"}]
    assert mon.fingerprint(a) == mon.fingerprint(b)
    assert mon.fingerprint(a) != mon.fingerprint([{"type": "EMAIL_ADDRESS"}])
    assert mon.fingerprint([]) == mon.fingerprint([])


def test_diff_classifies_new_changed_resolved():
    previous = {
        "notes:clean": {"fp": mon.fingerprint([]), "n": 0, "types": {}},
        "notes:dirty": {"fp": "aaaa", "n": 2, "types": {"EMAIL_ADDRESS": 2}},
        "notes:gone": {"fp": "bbbb", "n": 1, "types": {"PHONE_NUMBER": 1}},
        "notes:fixed": {"fp": "cccc", "n": 3, "types": {"EMAIL_ADDRESS": 3}},
    }
    current = {
        "notes:clean": {"fp": "dddd", "n": 1, "types": {"PHONE_NUMBER": 1}},   # was clean -> new
        "notes:dirty": {"fp": "eeee", "n": 3, "types": {"EMAIL_ADDRESS": 3}},  # changed
        "notes:fixed": {"fp": mon.fingerprint([]), "n": 0, "types": {}},        # resolved
        "notes:brandnew": {"fp": "ffff", "n": 1, "types": {"EMAIL_ADDRESS": 1}},  # new record
        # notes:gone disappeared entirely -> resolved
    }
    delta = mon.diff(previous, current)
    assert delta["new"] == ["notes:brandnew", "notes:clean"]
    assert delta["changed"] == ["notes:dirty"]
    assert delta["resolved"] == ["notes:fixed", "notes:gone"]


def test_snapshot_state_roundtrip_and_diff(tmp_path):
    state_file = str(tmp_path / "state.json")
    items_v1 = [_item("a", "hello EMAILISH"), _item("b", "all clean here")]
    snap1 = mon.build_snapshot(items_v1, fake_detect)
    mon.save_state(state_file, snap1, source="chroma", store_path="/tmp/store")

    loaded = mon.load_state(state_file)
    assert loaded["version"] == mon.STATE_VERSION
    assert loaded["records"] == snap1

    items_v2 = items_v1 + [_item("c", "PHONEISH PHONEISH")]  # injected new record
    snap2 = mon.build_snapshot(items_v2, fake_detect)
    delta = mon.diff(loaded["records"], snap2)
    assert delta["new"] == ["notes:c"]
    assert delta["changed"] == [] and delta["resolved"] == []


def test_state_and_payload_never_contain_raw_values(tmp_path):
    """The metadata-only principle, enforced by test: no document text, no finding values."""
    state_file = str(tmp_path / "state.json")
    secret = "raw-value-that-must-never-leak"
    items = [_item("a", f"EMAILISH {secret}")]
    snap = mon.build_snapshot(items, fake_detect)
    mon.save_state(state_file, snap, source="chroma", store_path="/tmp/store")

    on_disk = open(state_file, encoding="utf-8").read()
    assert secret not in on_disk and "EMAILISH" not in on_disk

    delta = mon.diff({}, snap)
    payload = json.dumps(mon.build_webhook_payload(delta, snap, "chroma", "/tmp/store"))
    assert secret not in payload and "EMAILISH" not in payload
    assert "EMAIL_ADDRESS" in payload  # types are the only content we ship


def test_webhook_posts_json(monkeypatch):
    sent = {}

    def fake_post(url, payload, timeout=10):
        sent["url"], sent["payload"] = url, payload
        return 200

    monkeypatch.setattr(mon, "post_webhook", fake_post)
    payload = mon.build_webhook_payload({"new": [], "changed": [], "resolved": []}, {}, "chroma", "/s")
    assert mon.post_webhook("https://hooks.example/x", payload) == 200
    assert sent["url"].startswith("https://")
    assert sent["payload"]["event"] == "ragleakguard.monitor"
