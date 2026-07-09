from health_analyzer.diagnostics import run_doctor


def test_doctor_reports_optional_private_configuration_without_secret_values(monkeypatch) -> None:
    monkeypatch.delenv("HEALTH_ANALYZER_PSEUDONYM_KEY", raising=False)
    monkeypatch.delenv("HEALTH_ANALYZER_PRIVATE_ROOTS", raising=False)
    report = run_doctor(__file__.rsplit("/tests/", 1)[0])
    assert report["status"] == "warn"
    serialized = str(report)
    assert "PSEUDONYM_KEY=" not in serialized
