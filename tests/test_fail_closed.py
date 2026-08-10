"""Fail-closed locale, detection-runtime, and monitor-state regression tests."""
import json
import re
from pathlib import Path

import pytest
from click import unstyle
from typer.testing import CliRunner

from ragleakguard import cli
from ragleakguard import connectors
from ragleakguard import detect as detection
from ragleakguard import monitor as monitoring


PRIVACY_CANARY = "privacy-canary-that-must-not-be-printed"
PATH_CANARY = "private-path-canary"
SUCCESS_SIGNALS = (
    "Risk-scored report written",
    "baseline saved",
    "baseline initialized",
    "No new exposure",
    "Webhook alert delivered",
    "✓",
)
SYNTHETIC_ITEM = {
    "id": "synthetic-record",
    "text": "deterministic synthetic text",
    "metadata": {},
    "collection": "synthetic-collection",
}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, None), ("au", "au"), ("AU", "au"), (" AU ", "au")],
)
def test_normalize_locale_accepts_supported_forms(raw, expected):
    assert detection.normalize_locale(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "a/u", "123", object()])
def test_normalize_locale_rejects_malformed_values(raw):
    with pytest.raises(detection.MalformedLocaleError):
        detection.normalize_locale(raw)


def test_normalize_locale_rejects_unsupported_pack():
    with pytest.raises(detection.UnsupportedLocaleError):
        detection.normalize_locale("uk")


def test_detect_validates_locale_before_empty_text(monkeypatch):
    def analyzer_must_not_run():
        raise AssertionError("runtime must not load after invalid locale")

    monkeypatch.setattr(detection, "_analyzer", analyzer_must_not_run)
    with pytest.raises(detection.UnsupportedLocaleError):
        detection.detect("", locale="uk")


@pytest.mark.parametrize(
    ("raw_error", "typed_error"),
    [
        (ImportError(PRIVACY_CANARY), detection.MissingDetectionDependencyError),
        (OSError(PRIVACY_CANARY), detection.MissingDetectionModelError),
    ],
)
def test_validate_detection_runtime_loads_analyzer_and_wraps_failures(
    monkeypatch, raw_error, typed_error
):
    def fail_to_build():
        raise raw_error

    detection._analyzer.cache_clear()
    monkeypatch.setattr(detection, "_build_analyzer", fail_to_build)
    try:
        with pytest.raises(typed_error) as caught:
            detection.validate_detection_runtime()
    finally:
        detection._analyzer.cache_clear()

    assert PRIVACY_CANARY not in str(caught.value)


def _patch_source(monkeypatch, items):
    calls = []

    def read_chroma(path):
        calls.append(path)
        return iter(items)

    monkeypatch.setattr(connectors, "read_chroma", read_chroma)
    return calls


def _command_args(command, tmp_path, locale=None):
    store_path = tmp_path / PATH_CANARY
    args = [command, "--source", "chroma", "--path", str(store_path)]
    artifact = tmp_path / ("report.md" if command == "scan" else "state.json")
    if command == "scan":
        args += ["--report", str(artifact)]
    else:
        args += [
            "--state",
            str(artifact),
            "--key-file",
            str(tmp_path / "monitor-key.json"),
        ]
    if locale is not None:
        args += ["--locale", locale]
    return args, artifact


def _assert_private_failure(result):
    assert PRIVACY_CANARY not in result.output
    assert PATH_CANARY not in result.output
    assert not any(signal in result.output for signal in SUCCESS_SIGNALS)


@pytest.mark.parametrize("command", ["scan", "monitor"])
@pytest.mark.parametrize(
    ("locale", "failure_message"),
    [("uk", "Unsupported locale"), ("   ", "Invalid locale")],
)
def test_cli_locale_failure_on_zero_item_source_creates_no_artifact_or_alert(
    monkeypatch, tmp_path, command, locale, failure_message
):
    source_calls = _patch_source(monkeypatch, [])
    webhook_calls = []
    monkeypatch.setattr(monitoring, "post_webhook", lambda *args, **kwargs: webhook_calls.append(args))
    args, artifact = _command_args(command, tmp_path, locale=locale)

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_USAGE
    assert isinstance(result.exception, SystemExit)
    assert not source_calls
    assert not artifact.exists()
    assert not webhook_calls
    assert not list(tmp_path.iterdir())
    assert failure_message in result.output
    _assert_private_failure(result)


@pytest.mark.parametrize("command", ["scan", "monitor"])
@pytest.mark.parametrize(
    "raw_error",
    [
        ImportError(PRIVACY_CANARY),
        OSError(PRIVACY_CANARY),
    ],
    ids=["missing-dependency", "missing-model"],
)
def test_cli_runtime_failure_on_zero_item_source_preserves_artifact_and_sends_no_alert(
    monkeypatch, tmp_path, command, raw_error
):
    def fail_to_build():
        raise raw_error

    detection._analyzer.cache_clear()
    monkeypatch.setattr(detection, "_build_analyzer", fail_to_build)
    source_calls = _patch_source(monkeypatch, [])
    webhook_calls = []
    monkeypatch.setattr(monitoring, "post_webhook", lambda *args, **kwargs: webhook_calls.append(args))
    args, artifact = _command_args(command, tmp_path)
    artifact.write_text("sentinel", encoding="utf-8")

    try:
        result = CliRunner().invoke(cli.app, args)
    finally:
        detection._analyzer.cache_clear()

    assert result.exit_code == cli.EXIT_DETECTION_RUNTIME
    assert isinstance(result.exception, SystemExit)
    assert not source_calls
    assert artifact.read_text(encoding="utf-8") == "sentinel"
    assert not (Path(f"{artifact}.tmp")).exists()
    assert not webhook_calls
    assert {path.name for path in tmp_path.iterdir()} == {artifact.name}
    _assert_private_failure(result)


@pytest.mark.parametrize("command", ["scan", "monitor"])
def test_mid_scan_model_failure_preserves_artifact_and_sends_no_alert(
    monkeypatch, tmp_path, command
):
    calls = []

    def fail_partway(text, locale=None):
        calls.append(text)
        if len(calls) == 2:
            raise detection.MissingDetectionModelError(PRIVACY_CANARY)
        return []

    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    monkeypatch.setattr(detection, "detect", fail_partway)
    _patch_source(monkeypatch, [SYNTHETIC_ITEM, dict(SYNTHETIC_ITEM, id="second")])
    webhook_calls = []
    monkeypatch.setattr(monitoring, "post_webhook", lambda *args, **kwargs: webhook_calls.append(args))
    args, artifact = _command_args(command, tmp_path)
    if command == "monitor":
        key_path = tmp_path / "monitor-key.json"
        monitoring.generate_key_file(str(key_path))
        crypto = monitoring.MonitorCrypto(monitoring.load_key_file(str(key_path)))
        scope = crypto.scope_token("chroma", str(tmp_path / PATH_CANARY))
        baseline = monitoring.build_snapshot(
            [SYNTHETIC_ITEM, dict(SYNTHETIC_ITEM, id="second")],
            lambda text, locale=None: [],
            crypto,
            scope,
        )
        monitoring.save_state(
            str(artifact), baseline, crypto, scope, initialize=True
        )
        before = artifact.read_bytes()
    else:
        artifact.write_text("sentinel", encoding="utf-8")
        before = artifact.read_bytes()

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_DETECTION_RUNTIME
    assert len(calls) == 2
    assert artifact.read_bytes() == before
    assert not list(tmp_path.glob(".rlg-monitor-*.tmp"))
    assert not webhook_calls
    expected = {artifact.name}
    if command == "monitor":
        expected.add("monitor-key.json")
    assert {path.name for path in tmp_path.iterdir()} == expected
    _assert_private_failure(result)


@pytest.mark.parametrize(
    ("locale_arg", "normalized"),
    [(None, None), ("au", "au"), ("AU", "au"), (" AU ", "au")],
)
def test_scan_supported_locale_forms_remain_compatible(
    monkeypatch, tmp_path, locale_arg, normalized
):
    seen_locales = []

    def fake_detect(text, locale=None):
        seen_locales.append(locale)
        return []

    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    monkeypatch.setattr(detection, "detect", fake_detect)
    _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    args, report = _command_args("scan", tmp_path, locale=locale_arg)

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 0
    assert seen_locales == [normalized]
    assert report.exists()
    assert "Risk-scored report written" in result.output


def test_monitor_successful_baseline_remains_compatible(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    monkeypatch.setattr(detection, "detect", lambda text, locale=None: [])
    _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    args, state = _command_args("monitor", tmp_path, locale="AU")
    monitoring.generate_key_file(str(tmp_path / "monitor-key.json"))
    args.append("--initialize")

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 0
    assert state.exists()
    assert "baseline initialized" in result.output


@pytest.mark.parametrize("command", ["scan", "monitor"])
def test_cli_help_advertises_only_implemented_locale_and_failure_exit(command):
    result = CliRunner().invoke(cli.app, [command, "--help"])
    normalized_output = " ".join(unstyle(result.output).split())

    assert result.exit_code == 0
    assert "Locale pack: au" in normalized_output
    assert not any(locale in normalized_output for locale in ("uk |", "sg |", "in ("))
    assert "2 = usage/locale error" in normalized_output
    assert "3 = detection unavailable" in normalized_output
    if command == "monitor":
        assert "4 = monitor key/state failure" in normalized_output
        assert "--key-file" in normalized_output
        assert "--initialize" in normalized_output


@pytest.mark.parametrize(
    ("readme", "heading"),
    [("README.md", "## Detection"), ("README.zh-TW.md", "## 偵測能力")],
)
def test_readme_locale_pack_entry_advertises_only_implemented_pack(readme, heading):
    text = (Path(__file__).resolve().parents[1] / readme).read_text(encoding="utf-8")
    section = text.split(heading, maxsplit=1)[1].split("\n## ", maxsplit=1)[0]
    locale_entries = [line for line in section.splitlines() if "--locale" in line]

    assert len(locale_entries) == 1
    assert re.findall(r"`([a-z]{2})`", locale_entries[0]) == ["au"]


@pytest.mark.parametrize(
    ("readme", "heading"),
    [("README.md", "## Monitor"), ("README.zh-TW.md", "## Monitor")],
)
def test_readme_monitor_workflow_requires_key_and_explicit_initialization(
    readme, heading
):
    text = (Path(__file__).resolve().parents[1] / readme).read_text(
        encoding="utf-8"
    )
    section = text.split(heading, maxsplit=1)[1].split("\n## ", maxsplit=1)[0]
    assert "generate-monitor-key" in section
    assert "--key-file" in section
    assert "--initialize" in section
    assert "exit code 4" in section or "exits 4" in section
    assert "docs/MONITOR_STATE.md" in section


def _prepare_valid_monitor_state(tmp_path, findings=None):
    key_path = tmp_path / "monitor-key.json"
    state_path = tmp_path / "state.json"
    monitoring.generate_key_file(str(key_path))
    crypto = monitoring.MonitorCrypto(monitoring.load_key_file(str(key_path)))
    scope = crypto.scope_token("chroma", str(tmp_path / PATH_CANARY))
    records = monitoring.build_snapshot(
        [SYNTHETIC_ITEM],
        lambda text, locale=None: list(findings or []),
        crypto,
        scope,
    )
    monitoring.save_state(
        str(state_path), records, crypto, scope, initialize=True
    )
    return key_path, state_path, state_path.read_bytes()


def test_monitor_missing_or_malformed_key_fails_before_source_and_preserves_state(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    source_calls = _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    webhook_calls = []
    monkeypatch.setattr(
        monitoring, "post_webhook", lambda *args, **kwargs: webhook_calls.append(args)
    )
    args, state = _command_args("monitor", tmp_path)
    state.write_text("prior-state-sentinel", encoding="utf-8")
    key_path = tmp_path / "monitor-key.json"
    key_path.write_text(
        '{"purpose":"wrong-purpose","key":"privacy-canary-that-must-not-be-printed"}',
        encoding="utf-8",
    )
    before = state.read_bytes()

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_MONITOR_STATE
    assert state.read_bytes() == before
    assert not source_calls
    assert not webhook_calls
    _assert_private_failure(result)


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        (b'{"version":1,"records":{}}', "Version-1 monitor state"),
        (b'{"version":1', "Monitor state is invalid"),
        (b'{"version":3,"records":{}}', "Monitor state is invalid"),
        (b"privacy-canary-that-must-not-be-printed", "Monitor state is invalid"),
    ],
    ids=["v1", "truncated-v1", "unsupported-version", "malformed-json"],
)
def test_monitor_state_rejection_is_static_preserves_bytes_and_sends_no_alert(
    monkeypatch, tmp_path, contents, message
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    source_calls = _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    webhook_calls = []
    monkeypatch.setattr(
        monitoring, "post_webhook", lambda *args, **kwargs: webhook_calls.append(args)
    )
    args, state = _command_args("monitor", tmp_path)
    monitoring.generate_key_file(str(tmp_path / "monitor-key.json"))
    state.write_bytes(contents)

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_MONITOR_STATE
    assert state.read_bytes() == contents
    assert not source_calls
    assert not webhook_calls
    assert message in result.output
    _assert_private_failure(result)


def test_monitor_absent_state_requires_explicit_initialization_before_source(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    source_calls = _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    args, state = _command_args("monitor", tmp_path)
    monitoring.generate_key_file(str(tmp_path / "monitor-key.json"))

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_MONITOR_STATE
    assert not state.exists()
    assert not source_calls
    assert "baseline is absent" in result.output
    _assert_private_failure(result)


def test_monitor_initialize_refuses_invalid_existing_state_before_source(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    source_calls = _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    args, state = _command_args("monitor", tmp_path)
    args.append("--initialize")
    monitoring.generate_key_file(str(tmp_path / "monitor-key.json"))
    state.write_text("invalid-existing-state", encoding="utf-8")
    before = state.read_bytes()

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_MONITOR_STATE
    assert state.read_bytes() == before
    assert not source_calls
    assert "initialization refused" in result.output
    _assert_private_failure(result)


@pytest.mark.parametrize(
    "failure_point",
    ["key-load", "state-validation", "canonicalization", "fingerprinting"],
)
def test_injected_monitor_failures_preserve_checkpoint_and_emit_no_success_or_webhook(
    monkeypatch, tmp_path, failure_point
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    monkeypatch.setattr(
        detection,
        "detect",
        lambda text, locale=None: [
            {"type": "EMAIL_ADDRESS", "text": "detected-value-canary"}
        ],
    )
    source_calls = _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    webhook_calls = []
    monkeypatch.setattr(
        monitoring, "post_webhook", lambda *args, **kwargs: webhook_calls.append(args)
    )
    _, state, before = _prepare_valid_monitor_state(tmp_path)
    args, _ = _command_args("monitor", tmp_path)

    if failure_point == "key-load":
        monkeypatch.setattr(
            monitoring,
            "load_key_file",
            lambda path: (_ for _ in ()).throw(
                monitoring.MonitorKeyError(PRIVACY_CANARY)
            ),
        )
    elif failure_point == "state-validation":
        monkeypatch.setattr(
            monitoring,
            "_validate_state",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                monitoring.MonitorStateError(PRIVACY_CANARY)
            ),
        )
    elif failure_point == "canonicalization":
        monkeypatch.setattr(
            monitoring,
            "canonicalize_finding",
            lambda finding: (_ for _ in ()).throw(
                monitoring.MonitorFingerprintError(PRIVACY_CANARY)
            ),
        )
    else:
        monkeypatch.setattr(
            monitoring,
            "fingerprint",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                monitoring.MonitorFingerprintError(PRIVACY_CANARY)
            ),
        )

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_MONITOR_STATE
    assert state.read_bytes() == before
    assert len(source_calls) == (0 if failure_point in {"key-load", "state-validation"} else 1)
    assert not webhook_calls
    assert not list(tmp_path.glob(".rlg-monitor-*.tmp"))
    _assert_private_failure(result)


@pytest.mark.parametrize("failure_point", ["temporary-write", "replacement"])
def test_cli_checkpoint_write_failures_preserve_prior_and_emit_no_success_or_webhook(
    monkeypatch, tmp_path, failure_point
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    monkeypatch.setattr(detection, "detect", lambda text, locale=None: [])
    source_calls = _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    webhook_calls = []
    monkeypatch.setattr(
        monitoring, "post_webhook", lambda *args, **kwargs: webhook_calls.append(args)
    )
    _, state, before = _prepare_valid_monitor_state(tmp_path)
    args, _ = _command_args("monitor", tmp_path)

    if failure_point == "temporary-write":
        def fail_write(handle, encoded):
            handle.write(encoded[:7])
            raise OSError(PRIVACY_CANARY)

        monkeypatch.setattr(monitoring, "_write_state_bytes", fail_write)
    else:
        monkeypatch.setattr(
            monitoring,
            "_replace_state",
            lambda *args: (_ for _ in ()).throw(OSError(PRIVACY_CANARY)),
        )

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_MONITOR_STATE
    assert state.read_bytes() == before
    assert len(source_calls) == 1
    assert not webhook_calls
    assert not list(tmp_path.glob(".rlg-monitor-*.tmp"))
    _assert_private_failure(result)


def test_generate_monitor_key_cli_is_private_and_refuses_overwrite(tmp_path):
    key_path = tmp_path / "private-key-path-canary.json"
    args = ["generate-monitor-key", "--output", str(key_path)]

    first = CliRunner().invoke(cli.app, args)
    before = key_path.read_bytes()
    document = json.loads(before.decode("utf-8"))
    second = CliRunner().invoke(cli.app, args)

    assert first.exit_code == 0
    assert "Monitor key generated" in first.output
    assert "private-key-path-canary" not in first.output
    assert document["key"] not in first.output
    assert second.exit_code == cli.EXIT_MONITOR_STATE
    assert "private-key-path-canary" not in second.output
    assert document["key"] not in second.output
    assert key_path.read_bytes() == before


def _add_webhook_pair(args, tmp_path, url="https://receiver.example.test/hook"):
    secret_path = tmp_path / "webhook-secret.json"
    monitoring.generate_webhook_secret_file(str(secret_path))
    args.extend(["--webhook", url, "--webhook-secret-file", str(secret_path)])
    return secret_path


@pytest.mark.parametrize(
    ("extra", "exit_code"),
    [
        (["--webhook", "https://receiver.example.test/hook"], cli.EXIT_WEBHOOK),
        (["--webhook-secret-file", "secret-path-canary"], cli.EXIT_USAGE),
    ],
    ids=["unsigned-legacy-webhook", "orphan-secret-file"],
)
def test_webhook_option_pair_fails_closed_before_source_access(
    monkeypatch, tmp_path, extra, exit_code
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    source_calls = _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    args, state = _command_args("monitor", tmp_path)
    args.extend(extra)

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == exit_code
    assert not source_calls
    assert not state.exists()
    assert "secret-path-canary" not in result.output
    assert "receiver.example.test" not in result.output
    _assert_private_failure(result)


@pytest.mark.parametrize(
    "mode",
    ["invalid-url", "missing-secret", "malformed-secret", "monitor-key-as-secret"],
)
def test_webhook_url_and_secret_preflight_fail_before_monitor_key_state_and_source(
    monkeypatch, tmp_path, mode
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    source_calls = _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    args, state = _command_args("monitor", tmp_path)
    secret_path = tmp_path / "webhook-secret-path-canary.json"
    url = "https://receiver.example.test/private-query-canary"
    if mode == "invalid-url":
        monitoring.generate_webhook_secret_file(str(secret_path))
        url = "http://url-canary.invalid/hook"
    elif mode == "malformed-secret":
        secret_path.write_text(PRIVACY_CANARY, encoding="utf-8")
    elif mode == "monitor-key-as-secret":
        monitoring.generate_key_file(str(secret_path))
    args.extend(["--webhook", url, "--webhook-secret-file", str(secret_path)])

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_WEBHOOK
    assert not source_calls
    assert not state.exists()
    for canary in (
        PRIVACY_CANARY,
        "webhook-secret-path-canary",
        "private-query-canary",
        "url-canary",
    ):
        assert canary not in result.output
    _assert_private_failure(result)


def test_generate_webhook_secret_cli_is_private_and_refuses_overwrite(tmp_path):
    secret_path = tmp_path / "private-webhook-path-canary.json"
    args = ["generate-webhook-secret", "--output", str(secret_path)]

    first = CliRunner().invoke(cli.app, args)
    before = secret_path.read_bytes()
    document = json.loads(before.decode("utf-8"))
    second = CliRunner().invoke(cli.app, args)

    assert first.exit_code == 0
    assert "Webhook signing secret generated" in first.output
    assert "private-webhook-path-canary" not in first.output
    assert document["secret"] not in first.output
    assert second.exit_code == cli.EXIT_WEBHOOK
    assert "private-webhook-path-canary" not in second.output
    assert document["secret"] not in second.output
    assert secret_path.read_bytes() == before


def test_webhook_preparation_checkpoint_transport_order_and_private_success(
    monkeypatch, tmp_path
):
    finding = {"type": "EMAIL_ADDRESS", "text": "detected-value-canary"}
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    monkeypatch.setattr(detection, "detect", lambda text, locale=None: [finding])
    _patch_source(
        monkeypatch,
        [dict(SYNTHETIC_ITEM, id="record-id-canary", collection="tenant-canary")],
    )
    _, state, before = _prepare_valid_monitor_state(tmp_path)
    args, _ = _command_args("monitor", tmp_path)
    _add_webhook_pair(
        args, tmp_path, "https://receiver.example.test/url-query-canary?private=yes"
    )
    events = []
    real_prepare = monitoring.prepare_webhook_request
    real_save = monitoring.save_state

    def prepare(*prepare_args, **prepare_kwargs):
        events.append("prepare")
        return real_prepare(*prepare_args, **prepare_kwargs)

    def save(*save_args, **save_kwargs):
        events.append("checkpoint")
        return real_save(*save_args, **save_kwargs)

    def post(prepared):
        events.append("transport")
        assert prepared.body is monitoring.WEBHOOK_BODY_BYTES
        assert set(prepared.headers) == monitoring.WEBHOOK_HEADER_ALLOWLIST
        return 204

    monkeypatch.setattr(monitoring, "prepare_webhook_request", prepare)
    monkeypatch.setattr(monitoring, "save_state", save)
    monkeypatch.setattr(monitoring, "post_webhook", post)

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 1
    assert events == ["prepare", "checkpoint", "transport"]
    assert state.read_bytes() != before
    assert "Exposure change detected." in result.output
    assert "Webhook alert delivered." in result.output
    for canary in (
        "detected-value-canary",
        "record-id-canary",
        "tenant-canary",
        "url-query-canary",
        "private=yes",
        "EMAIL_ADDRESS",
    ):
        assert canary not in result.output


def test_webhook_preparation_failure_preserves_checkpoint_and_sends_nothing(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    monkeypatch.setattr(
        detection,
        "detect",
        lambda text, locale=None: [
            {"type": "EMAIL_ADDRESS", "text": "detected-value-canary"}
        ],
    )
    _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    _, state, before = _prepare_valid_monitor_state(tmp_path)
    args, _ = _command_args("monitor", tmp_path)
    _add_webhook_pair(args, tmp_path)
    transport_calls = []
    monkeypatch.setattr(
        monitoring,
        "prepare_webhook_request",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            monitoring.WebhookPreparationError(PRIVACY_CANARY)
        ),
    )
    monkeypatch.setattr(
        monitoring, "post_webhook", lambda *args: transport_calls.append(args)
    )

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_WEBHOOK
    assert state.read_bytes() == before
    assert not transport_calls
    assert "Webhook alert preparation failed" in result.output
    _assert_private_failure(result)


def test_checkpoint_failure_after_signing_sends_nothing_and_preserves_prior(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    monkeypatch.setattr(
        detection,
        "detect",
        lambda text, locale=None: [
            {"type": "EMAIL_ADDRESS", "text": "detected-value-canary"}
        ],
    )
    _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    _, state, before = _prepare_valid_monitor_state(tmp_path)
    args, _ = _command_args("monitor", tmp_path)
    _add_webhook_pair(args, tmp_path)
    events = []
    real_prepare = monitoring.prepare_webhook_request

    def prepared(*prepare_args, **prepare_kwargs):
        events.append("prepare")
        return real_prepare(*prepare_args, **prepare_kwargs)

    monkeypatch.setattr(monitoring, "prepare_webhook_request", prepared)
    monkeypatch.setattr(
        monitoring,
        "save_state",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            monitoring.MonitorWriteError(PRIVACY_CANARY)
        ),
    )
    monkeypatch.setattr(
        monitoring, "post_webhook", lambda *args: events.append("transport")
    )

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_MONITOR_STATE
    assert events == ["prepare"]
    assert state.read_bytes() == before
    _assert_private_failure(result)


def test_transport_failure_advances_checkpoint_but_claims_no_delivery(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    monkeypatch.setattr(
        detection,
        "detect",
        lambda text, locale=None: [
            {"type": "EMAIL_ADDRESS", "text": "detected-value-canary"}
        ],
    )
    _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    _, state, before = _prepare_valid_monitor_state(tmp_path)
    args, _ = _command_args("monitor", tmp_path)
    _add_webhook_pair(args, tmp_path)
    monkeypatch.setattr(
        monitoring,
        "post_webhook",
        lambda prepared: (_ for _ in ()).throw(
            monitoring.WebhookTransportError(PRIVACY_CANARY)
        ),
    )

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_WEBHOOK
    assert state.read_bytes() != before
    normalized = " ".join(result.output.split())
    assert "Webhook delivery failed." in normalized
    assert "checkpoint was advanced" in normalized
    assert "Webhook alert delivered" not in result.output
    assert "Exposure change detected" not in result.output
    _assert_private_failure(result)


@pytest.mark.parametrize("run_kind", ["initialize", "no-change", "resolved-only"])
def test_non_alert_monitor_paths_never_prepare_or_send_webhook(
    monkeypatch, tmp_path, run_kind
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    current_findings = []
    previous_findings = []
    if run_kind == "resolved-only":
        previous_findings = [
            {"type": "EMAIL_ADDRESS", "text": "detected-value-canary"}
        ]
    monkeypatch.setattr(
        detection, "detect", lambda text, locale=None: list(current_findings)
    )
    _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    if run_kind == "initialize":
        monitoring.generate_key_file(str(tmp_path / "monitor-key.json"))
    else:
        _prepare_valid_monitor_state(tmp_path, findings=previous_findings)
    args, state = _command_args("monitor", tmp_path)
    _add_webhook_pair(args, tmp_path)
    if run_kind == "initialize":
        args.append("--initialize")
    calls = []
    monkeypatch.setattr(
        monitoring, "prepare_webhook_request", lambda *args, **kwargs: calls.append("prepare")
    )
    monkeypatch.setattr(
        monitoring, "post_webhook", lambda *args, **kwargs: calls.append("transport")
    )

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 0
    assert state.exists()
    assert not calls
    if run_kind == "initialize":
        assert "baseline initialized" in result.output
    else:
        assert "No new exposure." in result.output


@pytest.mark.parametrize("failure", ["monitor-key", "detection"])
def test_configured_webhook_never_sends_on_key_state_or_detection_failure(
    monkeypatch, tmp_path, failure
):
    monkeypatch.setattr(cli, "validate_detection_runtime", detection.normalize_locale)
    source_calls = _patch_source(monkeypatch, [SYNTHETIC_ITEM])
    args, state = _command_args("monitor", tmp_path)
    if failure == "detection":
        _prepare_valid_monitor_state(tmp_path)
        monkeypatch.setattr(
            detection,
            "detect",
            lambda text, locale=None: (_ for _ in ()).throw(
                detection.MissingDetectionModelError(PRIVACY_CANARY)
            ),
        )
        before = state.read_bytes()
    else:
        before = None
    _add_webhook_pair(args, tmp_path)
    calls = []
    monkeypatch.setattr(
        monitoring, "post_webhook", lambda *args, **kwargs: calls.append(args)
    )

    result = CliRunner().invoke(cli.app, args)

    expected = (
        cli.EXIT_MONITOR_STATE if failure == "monitor-key" else cli.EXIT_DETECTION_RUNTIME
    )
    assert result.exit_code == expected
    assert not calls
    assert len(source_calls) == (0 if failure == "monitor-key" else 1)
    if before is not None:
        assert state.read_bytes() == before
    _assert_private_failure(result)


def test_monitor_help_documents_authenticated_https_and_breaking_exit_code():
    result = CliRunner().invoke(cli.app, ["monitor", "--help"])
    normalized = " ".join(unstyle(result.output).split())

    assert result.exit_code == 0
    assert "--webhook-secret-file" in normalized
    assert "HTTPS" in normalized
    assert "authenticated" in normalized
    assert "5 = webhook failure" in normalized
    assert "Slack" not in normalized
    assert "Discord" not in normalized
