"""WP7A CLI precedence, artifact preservation, and side-effect denial tests."""
import builtins
import os
import socket
import sys
import types
from pathlib import Path

import pytest
from click import unstyle
from typer.testing import CliRunner

from ragleakguard import cli
from ragleakguard import connectors
from ragleakguard import detect as detection
from ragleakguard import monitor as monitoring
from ragleakguard import report as reporting


SOURCE_CANARY = "source-store-filesystem-canary"
PRIVACY_CANARY = "disabled-path-privacy-canary"
SUCCESS_SIGNALS = (
    "Risk-scored report written",
    "baseline saved",
    "baseline initialized",
    "No new exposure",
    "Exposure change detected",
    "Webhook response accepted",
    "Webhook alert delivered",
    "read 0 item",
    "sensitive finding",
    "✓",
)


def _forbid_source_filesystem(monkeypatch, source_path):
    calls = []
    source_text = str(source_path)

    def is_source(value):
        if isinstance(value, bytes):
            try:
                value = value.decode()
            except UnicodeDecodeError:
                return False
        return isinstance(value, (str, Path)) and str(value) == source_text

    def wrap(function, label):
        def guarded(path, *args, **kwargs):
            if is_source(path):
                calls.append(label)
                raise AssertionError(f"source filesystem access: {label}")
            return function(path, *args, **kwargs)

        return guarded

    monkeypatch.setattr(builtins, "open", wrap(builtins.open, "open"))
    for module, name in (
        (os, "open"),
        (os, "stat"),
        (os, "lstat"),
        (os, "listdir"),
        (os, "scandir"),
    ):
        monkeypatch.setattr(module, name, wrap(getattr(module, name), name))

    for name in ("open", "stat", "lstat", "exists", "is_dir", "iterdir", "resolve"):
        original = getattr(Path, name)

        def guarded(self, *args, _name=name, _original=original, **kwargs):
            if is_source(self):
                calls.append(f"Path.{_name}")
                raise AssertionError(f"source filesystem access: Path.{_name}")
            return _original(self, *args, **kwargs)

        monkeypatch.setattr(Path, name, guarded)
    return calls


def _forbid_chroma_import(monkeypatch):
    calls = []
    real_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name == "chromadb" or name.startswith("chromadb."):
            calls.append(name)
            raise AssertionError("Chroma import attempted")
        return real_import(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "chromadb", raising=False)
    monkeypatch.setattr(builtins, "__import__", guarded)
    return calls


def _forbid_network(monkeypatch):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("outbound socket attempt")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    return calls


def _assert_disabled_output(result):
    assert result.exit_code == cli.EXIT_CONNECTOR_UNAVAILABLE
    assert result.output.strip() == connectors.CHROMA_DISABLED_MESSAGE
    assert SOURCE_CANARY not in result.output
    assert PRIVACY_CANARY not in result.output
    assert not any(signal in result.output for signal in SUCCESS_SIGNALS)


def _assert_legacy_path_rejected(result):
    assert result.exit_code == cli.EXIT_USAGE
    assert "Legacy --path is rejected" in result.output
    assert SOURCE_CANARY not in result.output
    assert PRIVACY_CANARY not in result.output
    assert not any(signal in result.output for signal in SUCCESS_SIGNALS)


@pytest.mark.parametrize("existing_report", [False, True])
def test_scan_disabled_path_has_no_import_detector_source_report_or_network_side_effect(
    monkeypatch, tmp_path, existing_report
):
    source = tmp_path / SOURCE_CANARY
    report = tmp_path / "report.md"
    if existing_report:
        report.write_bytes(b"existing-report-bytes\x00\xff")
        before = report.read_bytes()
    else:
        before = None

    source_calls = _forbid_source_filesystem(monkeypatch, source)
    import_calls = _forbid_chroma_import(monkeypatch)
    network_calls = _forbid_network(monkeypatch)
    forbidden_calls = []
    monkeypatch.setattr(
        connectors,
        "read_chroma",
        lambda *args, **kwargs: forbidden_calls.append("connector"),
    )
    monkeypatch.setattr(
        cli,
        "validate_detection_runtime",
        lambda *args, **kwargs: forbidden_calls.append("runtime"),
    )
    monkeypatch.setattr(
        detection,
        "detect",
        lambda *args, **kwargs: forbidden_calls.append("detect"),
    )
    monkeypatch.setattr(
        reporting,
        "build_report",
        lambda *args, **kwargs: forbidden_calls.append("report"),
    )

    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            "--source",
            "chroma",
            "--path",
            str(source),
            "--locale",
            "au",
            "--report",
            str(report),
        ],
    )

    _assert_legacy_path_rejected(result)
    assert source_calls == []
    assert import_calls == []
    assert network_calls == []
    assert forbidden_calls == []
    if existing_report:
        assert report.read_bytes() == before
    else:
        assert not report.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_scan_never_constructs_a_chroma_client_or_embedding_function(
    monkeypatch, tmp_path
):
    calls = []
    fake_chroma = types.ModuleType("chromadb")
    fake_chroma.PersistentClient = lambda *args, **kwargs: calls.append("client")
    fake_chroma.utils = types.SimpleNamespace(
        embedding_functions=types.SimpleNamespace(
            DefaultEmbeddingFunction=lambda *args, **kwargs: calls.append("embedding")
        )
    )
    monkeypatch.setitem(sys.modules, "chromadb", fake_chroma)

    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            "--source",
            "chroma",
            "--path",
            str(tmp_path / SOURCE_CANARY),
        ],
    )

    _assert_legacy_path_rejected(result)
    assert calls == []


def _valid_monitor_state(tmp_path, source):
    key_path = tmp_path / "monitor-key.json"
    state_path = tmp_path / "state.json"
    monitoring.generate_key_file(str(key_path))
    crypto = monitoring.MonitorCrypto(monitoring.load_key_file(str(key_path)))
    scope = crypto.scope_token("chroma", str(source))
    monitoring.save_state(str(state_path), {}, crypto, scope, initialize=True)
    return key_path, state_path


def test_monitor_no_pending_preserves_state_and_denies_scan_alert_and_network(
    monkeypatch, tmp_path
):
    source = tmp_path / SOURCE_CANARY
    key_path, state_path = _valid_monitor_state(tmp_path, source)
    secret_path = tmp_path / "webhook-secret.json"
    monitoring.generate_webhook_secret_file(str(secret_path))
    before = state_path.read_bytes()

    source_calls = _forbid_source_filesystem(monkeypatch, source)
    import_calls = _forbid_chroma_import(monkeypatch)
    network_calls = _forbid_network(monkeypatch)
    forbidden_calls = []
    monkeypatch.setattr(
        connectors,
        "read_chroma",
        lambda *args, **kwargs: forbidden_calls.append("connector"),
    )
    monkeypatch.setattr(
        cli,
        "validate_detection_runtime",
        lambda *args, **kwargs: forbidden_calls.append("runtime"),
    )
    monkeypatch.setattr(
        detection,
        "detect",
        lambda *args, **kwargs: forbidden_calls.append("detect"),
    )
    monkeypatch.setattr(
        monitoring,
        "build_snapshot",
        lambda *args, **kwargs: forbidden_calls.append("snapshot"),
    )
    monkeypatch.setattr(
        monitoring,
        "new_pending_alert",
        lambda *args, **kwargs: forbidden_calls.append("new-pending"),
    )
    monkeypatch.setattr(
        monitoring,
        "prepare_webhook_request",
        lambda *args, **kwargs: forbidden_calls.append("prepare"),
    )
    monkeypatch.setattr(
        monitoring,
        "post_webhook",
        lambda *args, **kwargs: forbidden_calls.append("transport"),
    )

    result = CliRunner().invoke(
        cli.app,
        [
            "monitor",
            "--source",
            "chroma",
            "--path",
            str(source),
            "--state",
            str(state_path),
            "--key-file",
            str(key_path),
            "--webhook",
            "https://receiver.example.test/hook",
            "--webhook-secret-file",
            str(secret_path),
        ],
    )

    _assert_disabled_output(result)
    assert state_path.read_bytes() == before
    assert source_calls == []
    assert import_calls == []
    assert network_calls == []
    assert forbidden_calls == []
    assert not list(tmp_path.glob(".rlg-monitor-*.tmp"))
    assert {path.name for path in tmp_path.iterdir()} == {
        key_path.name,
        state_path.name,
        secret_path.name,
    }


def test_monitor_initialize_disabled_path_leaves_absent_state_absent(
    monkeypatch, tmp_path
):
    source = tmp_path / SOURCE_CANARY
    key_path = tmp_path / "monitor-key.json"
    state_path = tmp_path / "absent-state.json"
    monitoring.generate_key_file(str(key_path))
    source_calls = _forbid_source_filesystem(monkeypatch, source)
    network_calls = _forbid_network(monkeypatch)
    forbidden_calls = []
    monkeypatch.setattr(
        monitoring,
        "save_state",
        lambda *args, **kwargs: forbidden_calls.append("state-write"),
    )
    monkeypatch.setattr(
        monitoring,
        "build_snapshot",
        lambda *args, **kwargs: forbidden_calls.append("snapshot"),
    )

    result = CliRunner().invoke(
        cli.app,
        [
            "monitor",
            "--source",
            "chroma",
            "--path",
            str(source),
            "--state",
            str(state_path),
            "--key-file",
            str(key_path),
            "--initialize",
        ],
    )

    _assert_disabled_output(result)
    assert not state_path.exists()
    assert source_calls == []
    assert network_calls == []
    assert forbidden_calls == []
    assert {path.name for path in tmp_path.iterdir()} == {key_path.name}


@pytest.mark.parametrize(
    ("args", "exit_code", "message"),
    [
        (
            ["scan", "--source", "chroma"],
            cli.EXIT_USAGE,
            "Snapshot scan arguments are incomplete",
        ),
        (
            ["scan", "--source", "chroma", "--path", "synthetic", "--locale", "uk"],
            cli.EXIT_USAGE,
            "Legacy --path is rejected",
        ),
        (
            ["scan", "--source", "pinecone", "--path", "synthetic"],
            cli.EXIT_USAGE,
            "No source connector is available",
        ),
        (
            ["monitor", "--source", "chroma", "--path", "synthetic"],
            cli.EXIT_USAGE,
            "Missing option '--key-file'",
        ),
    ],
)
def test_ordinary_usage_validation_precedes_disabled_message(args, exit_code, message):
    result = CliRunner().invoke(cli.app, args)
    normalized_output = " ".join(unstyle(result.output).split())

    assert result.exit_code == exit_code
    assert message in normalized_output
    assert connectors.CHROMA_DISABLED_MESSAGE not in result.output
