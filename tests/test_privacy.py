from unittest.mock import patch, MagicMock
import scrapers.privacy as prv


SAMPLE_HTML = """<html><body>
<h2>Article 5 — Principles</h2><p>Personal data shall be processed lawfully.</p>
<h2>Article 6 — Lawful Basis</h2><p>Processing requires a lawful basis under GDPR.</p>
</body></html>"""


def _mock_html(html):
    m = MagicMock()
    m.text = html
    m.raise_for_status.return_value = None
    return m


def test_scrape_returns_four_sources():
    with patch("scrapers.privacy.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = prv.scrape()
    assert result["category"] == "privacy"
    assert len(result["sources"]) == 4


def test_scrape_source_names_are_correct():
    with patch("scrapers.privacy.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = prv.scrape()
    names = [s["name"] for s in result["sources"]]
    assert "GDPR Full Text" in names
    assert "ICO DPIA Guide" in names
    assert "CCPA Text" in names
    assert "GDPR Enforcement Tracker" in names


def test_scrape_source_extracts_sections():
    with patch("scrapers.privacy.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = prv._scrape_source("GDPR", "https://example.com", "desc")
    assert result["data"]["sections"][0]["title"] == "Article 5 — Principles"
    assert "lawfully" in result["data"]["sections"][0]["content"]


def test_scrape_source_returns_error_on_failure():
    with patch("scrapers.privacy.fetch", side_effect=Exception("403 Forbidden")):
        result = prv._scrape_source("GDPR", "https://example.com", "desc")
    assert "error" in result
    assert "403 Forbidden" in result["error"]
