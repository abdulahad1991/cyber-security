from unittest.mock import patch, MagicMock
import scrapers.ai_security as ai


SAMPLE_HTML = """<html><body>
<h2>LLM01: Prompt Injection</h2><p>Attackers manipulate LLMs via crafted prompts.</p>
<h2>LLM02: Insecure Output Handling</h2><p>Downstream components trust LLM output without validation.</p>
</body></html>"""


def _mock_html(html):
    m = MagicMock()
    m.text = html
    m.raise_for_status.return_value = None
    return m


def test_scrape_returns_three_sources():
    with patch("scrapers.ai_security.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = ai.scrape()
    assert result["category"] == "ai_security"
    assert len(result["sources"]) == 3


def test_scrape_source_names_are_correct():
    with patch("scrapers.ai_security.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = ai.scrape()
    names = [s["name"] for s in result["sources"]]
    assert "OWASP LLM Top 10" in names
    assert "MITRE ATLAS Matrix" in names
    assert "NIST AI Risk Management Framework" in names


def test_scrape_source_extracts_sections():
    with patch("scrapers.ai_security.fetch", return_value=_mock_html(SAMPLE_HTML)):
        result = ai._scrape_source("OWASP", "https://example.com", "desc")
    assert result["data"]["sections"][0]["title"] == "LLM01: Prompt Injection"
    assert "crafted prompts" in result["data"]["sections"][0]["content"]


def test_scrape_source_returns_error_on_failure():
    with patch("scrapers.ai_security.fetch", side_effect=Exception("SSL error")):
        result = ai._scrape_source("OWASP", "https://example.com", "desc")
    assert "error" in result
    assert "SSL error" in result["error"]
