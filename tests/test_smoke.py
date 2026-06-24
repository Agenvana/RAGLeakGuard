def test_version():
    import ragleakguard
    assert ragleakguard.__version__


def test_cli_imports():
    from ragleakguard.cli import app
    assert app is not None
