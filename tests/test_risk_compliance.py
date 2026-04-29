from unittest.mock import patch, MagicMock
import scrapers.risk_compliance as rc


SAMPLE_HTML = """<html><body>
<h2>Risk Assessment Process</h2><p>Step 1: Identify threats and vulnerabilities.</p>
<h2>Risk Categories</h2><p>Risks are classified as high, medium, or low severity.</p>
</body></html>"""

LONG_HTML = "<html><body><h2>Section</h2><p>" + "x " * 2000 + "</p></body></html>"


def _mock_html(html):
    m = MagicMock()
    m.text = html
    m.raise_for_status.return_value = None
    return m


def test_scrape_source_returns_envelope():
    with patch("scrapers.risk_compliance.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = rc._scrape_source("NIST", "https://example.com", "A test source")
    assert result["name"] == "NIST"
    assert result["type"] == "static"
    assert "error" not in result
    assert "sections" in result["data"]
    assert "summary" in result["data"]
    assert "last_fetch" in result["data"]


def test_scrape_source_extracts_sections():
    with patch("scrapers.risk_compliance.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = rc._scrape_source("NIST", "https://example.com", "desc")
    assert len(result["data"]["sections"]) == 2
    assert result["data"]["sections"][0]["title"] == "Risk Assessment Process"
    assert "Identify threats" in result["data"]["sections"][0]["content"]


def test_scrape_source_truncates_summary_to_3000_chars():
    with patch("scrapers.risk_compliance.fetch", return_value=_mock_html(LONG_HTML)):
        result = rc._scrape_source("Test", "https://example.com", "desc")
    assert len(result["data"]["summary"]) <= 3000


def test_scrape_source_returns_error_dict_on_failure():
    with patch("scrapers.risk_compliance.fetch", side_effect=Exception("404 Not Found")):
        result = rc._scrape_source("Test", "https://example.com", "desc")
    assert "error" in result
    assert "404 Not Found" in result["error"]
    assert "data" not in result


def test_scrape_returns_four_sources():
    with patch("scrapers.risk_compliance.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = rc.scrape()
    assert result["category"] == "risk_compliance"
    assert "last_updated" in result
    assert len(result["sources"]) == 4


def test_scrape_source_names_are_correct():
    with patch("scrapers.risk_compliance.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = rc.scrape()
    names = [s["name"] for s in result["sources"]]
    assert "NIST SP 800-30 Risk Management" in names
    assert "PCI DSS Document Library" in names
    assert "ISO/IEC 27001 Control Mapping" in names
    assert "CIS Benchmarks" in names
