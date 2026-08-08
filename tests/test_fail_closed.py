"""Fail-closed locale and detection-runtime regression tests."""
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
    "No new exposure",
    "Webhook alert sent",
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
def test_detect_wraps_runtime_failures_without_raw_error(monkeypatch, raw_error, typed_error):
    def fail_to_build():
        raise raw_error

    detection._analyzer.cache_clear()
    monkeypatch.setattr(detection, "_build_analyzer", fail_to_build)
    try:
        with pytest.raises(typed_error) as caught:
            detection.detect("deterministic synthetic text")
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
        args += ["--state", str(artifact), "--webhook", "https://hooks.invalid/canary"]
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
    "runtime_error_type",
    [
        detection.MissingDetectionDependencyError,
        detection.MissingDetectionModelError,
    ],
    ids=["missing-dependency", "missing-model"],
)
def test_cli_runtime_failure_on_zero_item_source_preserves_artifact_and_sends_no_alert(
    monkeypatch, tmp_path, command, runtime_error_type
):
    def fail_preflight(locale):
        raise runtime_error_type(PRIVACY_CANARY)

    monkeypatch.setattr(cli, "validate_detection_runtime", fail_preflight)
    source_calls = _patch_source(monkeypatch, [])
    webhook_calls = []
    monkeypatch.setattr(monitoring, "post_webhook", lambda *args, **kwargs: webhook_calls.append(args))
    args, artifact = _command_args(command, tmp_path)
    artifact.write_text("sentinel", encoding="utf-8")

    result = CliRunner().invoke(cli.app, args)

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
    artifact.write_text("sentinel", encoding="utf-8")

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == cli.EXIT_DETECTION_RUNTIME
    assert len(calls) == 2
    assert artifact.read_text(encoding="utf-8") == "sentinel"
    assert not (Path(f"{artifact}.tmp")).exists()
    assert not webhook_calls
    assert {path.name for path in tmp_path.iterdir()} == {artifact.name}
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

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 0
    assert state.exists()
    assert "baseline saved" in result.output


@pytest.mark.parametrize("command", ["scan", "monitor"])
def test_cli_help_advertises_only_implemented_locale_and_failure_exit(command):
    result = CliRunner().invoke(cli.app, [command, "--help"])
    normalized_output = " ".join(unstyle(result.output).split())

    assert result.exit_code == 0
    assert "Locale pack: au" in normalized_output
    assert not any(locale in normalized_output for locale in ("uk |", "sg |", "in ("))
    assert "2 = usage/locale error" in normalized_output
    assert "3 = detection unavailable" in normalized_output
