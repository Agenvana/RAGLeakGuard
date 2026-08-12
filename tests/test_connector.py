"""Synchronous fail-closed contract for disabled direct local Chroma access."""
import builtins
import inspect
import os
import traceback

import pytest

from ragleakguard.connectors import (
    CHROMA_DISABLED_MESSAGE,
    ChromaConnectorUnavailableError,
    read_chroma,
)


PRIVACY_CANARY = "hostile-chroma-path-privacy-canary"


class HostilePath:
    """Any attempted inspection records the prohibited operation and fails."""

    def __init__(self, events):
        object.__setattr__(self, "_events", events)

    def _fail(self, operation):
        object.__getattribute__(self, "_events").append(operation)
        raise AssertionError(f"{PRIVACY_CANARY}: prohibited operation {operation}")

    def __getattribute__(self, name):
        if name in {"_events", "_fail"}:
            return object.__getattribute__(self, name)
        return object.__getattribute__(self, "_fail")(f"attribute:{name}")

    def __getattr__(self, name):
        return self._fail(f"missing-attribute:{name}")

    def __fspath__(self):
        return self._fail("fspath")

    def __str__(self):
        return self._fail("str")

    def __repr__(self):
        return self._fail("repr")

    def __iter__(self):
        return self._fail("iter")

    def __bool__(self):
        return self._fail("bool")

    def __eq__(self, other):
        return self._fail("eq")

    def __hash__(self):
        return self._fail("hash")


def test_read_chroma_is_not_a_generator_and_raises_at_invocation():
    events = []
    hostile = HostilePath(events)

    assert not inspect.isgeneratorfunction(read_chroma)
    with pytest.raises(ChromaConnectorUnavailableError) as caught:
        read_chroma(hostile)

    assert events == []
    assert caught.value.args == (CHROMA_DISABLED_MESSAGE,)
    assert str(caught.value) == CHROMA_DISABLED_MESSAGE
    assert repr(caught.value) == (
        "ChromaConnectorUnavailableError(" + repr(CHROMA_DISABLED_MESSAGE) + ")"
    )
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert caught.value.__suppress_context__ is True


def test_read_chroma_ignores_path_and_collection_without_import_or_filesystem(
    monkeypatch,
):
    path_events = []
    collection_events = []
    import_events = []
    filesystem_events = []
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "chromadb" or name.startswith("chromadb."):
            import_events.append(name)
            raise AssertionError("Chroma must not be imported")
        return real_import(name, *args, **kwargs)

    def forbidden_filesystem(*args, **kwargs):
        filesystem_events.append((args, kwargs))
        raise AssertionError("filesystem must not be touched")

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(builtins, "open", forbidden_filesystem)
    monkeypatch.setattr(os, "fspath", forbidden_filesystem)
    monkeypatch.setattr(os, "stat", forbidden_filesystem)
    monkeypatch.setattr(os, "lstat", forbidden_filesystem)
    monkeypatch.setattr(os, "scandir", forbidden_filesystem)

    with pytest.raises(ChromaConnectorUnavailableError):
        read_chroma(HostilePath(path_events), HostilePath(collection_events))

    assert path_events == []
    assert collection_events == []
    assert import_events == []
    assert filesystem_events == []


def test_exception_rendering_is_static_and_contains_no_hostile_canary():
    events = []
    try:
        read_chroma(HostilePath(events))
    except ChromaConnectorUnavailableError as error:
        rendered = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        surfaces = [error.args, str(error), repr(error), rendered]
    else:  # pragma: no cover - the assertion documents the fail-closed requirement
        pytest.fail("read_chroma returned instead of failing synchronously")

    assert events == []
    assert all(PRIVACY_CANARY not in repr(surface) for surface in surfaces)
    assert "The above exception was the direct cause" not in rendered
    assert "During handling of the above exception" not in rendered
