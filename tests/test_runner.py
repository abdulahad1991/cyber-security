from unittest.mock import patch, MagicMock
import runner


SAMPLE_DATA = {
    "category": "vulnerabilities",
    "last_updated": "2026-01-01T00:00:00+00:00",
    "sources": [
        {
            "name": "CISA KEV",
            "type": "live",
            "data": {"description": "test", "entries": [{"cve_id": "CVE-001"}] * 5},
        }
    ],
}


def _fake_import(name, data=None):
    m = MagicMock()
    m.scrape.return_value = data or {**SAMPLE_DATA, "category": name}
    return m


def test_run_live_mode_calls_only_live_modules():
    called = []

    def fake_import(name):
        called.append(name)
        return _fake_import(name)

    with patch("runner._import_scraper", side_effect=fake_import):
        with patch("runner.write_json"):
            runner.run("live")

    assert set(called) == {"vulnerabilities", "threat_intel"}


def test_run_static_mode_calls_only_static_modules():
    called = []

    def fake_import(name):
        called.append(name)
        return _fake_import(name)

    with patch("runner._import_scraper", side_effect=fake_import):
        with patch("runner.write_json"):
            runner.run("static")

    assert set(called) == {"risk_compliance", "security_testing", "privacy", "ai_security"}


def test_run_all_mode_calls_all_six_modules():
    called = []

    def fake_import(name):
        called.append(name)
        return _fake_import(name)

    with patch("runner._import_scraper", side_effect=fake_import):
        with patch("runner.write_json"):
            runner.run("all")

    assert len(called) == 6


def test_run_failed_module_does_not_raise():
    def fake_import(name):
        m = MagicMock()
        m.scrape.side_effect = RuntimeError("network down")
        return m

    with patch("runner._import_scraper", side_effect=fake_import):
        with patch("runner.write_json"):
            results = runner.run("live")

    assert len(results["failed"]) == 2
    assert results["failed"][0]["error"] == "network down"


def test_run_writes_manifest():
    written = {}

    def capture_write(category, data):
        written[category] = data
        return f"/tmp/{category}.json"

    def fake_import(name):
        return _fake_import(name)

    with patch("runner._import_scraper", side_effect=fake_import):
        with patch("runner.write_json", side_effect=capture_write):
            runner.run("live")

    assert "manifest" in written
    assert "updated_at" in written["manifest"]
    assert "vulnerabilities" in written["manifest"]["categories"]
    assert "threat_intel" in written["manifest"]["categories"]


def test_run_returns_correct_scraped_count():
    with patch("runner._import_scraper", side_effect=lambda n: _fake_import(n)):
        with patch("runner.write_json"):
            results = runner.run("live")
    assert len(results["scraped"]) == 2
    assert len(results["failed"]) == 0
