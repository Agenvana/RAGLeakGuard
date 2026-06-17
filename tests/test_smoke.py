def test_version():
    import vectorscan
    assert vectorscan.__version__


def test_cli_imports():
    from vectorscan.cli import app
    assert app is not None
