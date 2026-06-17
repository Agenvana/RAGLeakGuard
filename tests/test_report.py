def test_build_report_high_risk():
    from vectorscan.report import build_report

    md = build_report(
        {"AU_MEDICARE": 100, "EMAIL_ADDRESS": 100, "DATE_TIME": 50},
        n_records=100, n_flagged=100,
    )
    assert "# vectorscan" in md
    assert "AU_MEDICARE" in md
    assert "Risk level" in md
    assert "HIGH" in md  # Medicare (HIGH severity) + 100% of records flagged


def test_build_report_empty():
    from vectorscan.report import build_report

    md = build_report({}, n_records=10, n_flagged=0)
    assert "LOW" in md
