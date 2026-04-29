from unittest.mock import patch, MagicMock
import scrapers.security_testing as st


SAMPLE_HTML = """<html><body>
<h2>Grading Criteria</h2><p>An A+ grade requires HSTS with long max-age.</p>
<h2>Security Headers</h2><p>Content-Security-Policy is mandatory for A grade.</p>
</body></html>"""


def _mock_html(html):
    m = MagicMock()
    m.text = html
    m.raise_for_status.return_value = None
    return m


def test_scrape_returns_three_sources():
    with patch("scrapers.security_testing.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = st.scrape()
    assert result["category"] == "security_testing"
    assert len(result["sources"]) == 3


def test_scrape_source_names_are_correct():
    with patch("scrapers.security_testing.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = st.scrape()
    names = [s["name"] for s in result["sources"]]
    assert "Qualys SSL Labs API Docs" in names
    assert "Security Headers Reference" in names
    assert "HSTS Preload" in names


def test_scrape_source_extracts_sections():
    with patch("scrapers.security_testing.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = st._scrape_source("Test", "https://example.com", "desc")
    assert result["data"]["sections"][0]["title"] == "Grading Criteria"
    assert "A+" in result["data"]["sections"][0]["content"]


def test_scrape_source_returns_error_on_failure():
    with patch("scrapers.security_testing.fetch", side_effect=Exception("timeout")):
        result = st._scrape_source("Test", "https://example.com", "desc")
    assert "error" in result
    assert "timeout" in result["error"]
