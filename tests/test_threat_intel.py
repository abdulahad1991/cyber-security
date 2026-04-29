from unittest.mock import patch, MagicMock
import scrapers.threat_intel as ti


def _mock_text_resp(text):
    m = MagicMock()
    m.text = text
    m.raise_for_status.return_value = None
    return m


SAMPLE_FEED = """https://malicious1.example.com/login
https://phish2.example.com/bank
not-a-url
https://phish3.example.com/verify
"""

SAMPLE_APWG_HTML = """<html><body>
<h2>Phishing Trends</h2><p>Q1 2024 saw increased phishing activity.</p>
<h2>Reports</h2><p>Download our quarterly report here.</p>
</body></html>"""


def test_scrape_openphish_returns_correct_envelope():
    with patch("scrapers.threat_intel.fetch", return_value=_mock_text_resp(SAMPLE_FEED)):
        result = ti.scrape_openphish()
    assert result["name"] == "OpenPhish Community Feed"
    assert result["type"] == "live"
    assert "error" not in result


def test_scrape_openphish_filters_non_http_lines():
    with patch("scrapers.threat_intel.fetch", return_value=_mock_text_resp(SAMPLE_FEED)):
        result = ti.scrape_openphish()
    entries = result["data"]["entries"]
    assert all(e.startswith("http") for e in entries)
    assert "not-a-url" not in entries
    assert len(entries) == 3


def test_scrape_openphish_caps_entries_at_200():
    big_feed = "\n".join(f"https://phish{i}.example.com" for i in range(300))
    with patch("scrapers.threat_intel.fetch", return_value=_mock_text_resp(big_feed)):
        result = ti.scrape_openphish()
    assert len(result["data"]["entries"]) == 200
    assert result["data"]["total_count"] == 300


def test_scrape_openphish_returns_error_on_failure():
    with patch("scrapers.threat_intel.fetch", side_effect=Exception("timeout")):
        result = ti.scrape_openphish()
    assert "error" in result
    assert "timeout" in result["error"]


def test_scrape_apwg_returns_sections():
    with patch("scrapers.threat_intel.fetch", return_value=_mock_text_resp(SAMPLE_APWG_HTML)):
        result = ti.scrape_apwg()
    assert result["name"] == "APWG Resources"
    assert result["type"] == "static"
    assert len(result["data"]["sections"]) == 2
    assert result["data"]["sections"][0]["title"] == "Phishing Trends"


def test_scrape_apwg_returns_error_on_failure():
    with patch("scrapers.threat_intel.fetch", side_effect=Exception("404")):
        result = ti.scrape_apwg()
    assert "error" in result


def test_scrape_returns_category_envelope_with_two_sources():
    feed_resp = _mock_text_resp(SAMPLE_FEED)
    apwg_resp = _mock_text_resp(SAMPLE_APWG_HTML)
    with patch("scrapers.threat_intel.fetch", side_effect=[feed_resp, apwg_resp]):
        result = ti.scrape()
    assert result["category"] == "threat_intel"
    assert len(result["sources"]) == 2
