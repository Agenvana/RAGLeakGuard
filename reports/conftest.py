"""Pytest collection settings for the reports tree.

The research regression checks in ``findings/src/test_scam_kit.py`` import
the research script, which imports chromadb in-process. The product suite
in ``tests/`` asserts that chromadb is never imported into the test process
(``tests/test_chroma_snapshot_private.py``), so a repository-wide pytest run
must not collect the research module alongside the product tests.

The research checks still run when named explicitly:

    python -m unittest reports/findings/src/test_scam_kit.py
    python -m pytest reports/findings/src/test_scam_kit.py

Nothing here changes a product test or a product security assertion.
"""

collect_ignore = ["findings/src/test_scam_kit.py"]
