from unittest.mock import patch, MagicMock
import scrapers.ai_security as ai


SAMPLE_HTML = """<html><body>
<h2>LLM01: Prompt Injection</h2><p>Attackers manipulate LLMs via crafted prompts.</p>
<h2>LLM02: Insecure Output Handling</h2><p>Downstream components trust LLM output without validation.</p>
</body></html>"""

SAMPLE_ATLAS_YAML = """
matrices:
  - id: ATLAS
    name: ATLAS
    tactics:
      - id: AML.TA0001
        name: Reconnaissance
        description: Gather information about the target ML system.
      - id: AML.TA0002
        name: Resource Development
        description: Establish resources to support operations.
    techniques:
      - id: AML.T0000
        name: Search for Victim's Publicly Available Research Materials
        description: Adversaries may search for publicly available ML research.
        tactics:
          - AML.TA0001
      - id: AML.T0001
        name: Acquire Public ML Artifacts
        description: Adversaries may acquire pre-trained models or datasets.
        tactics:
          - AML.TA0002
"""


def _mock_html(html):
    m = MagicMock()
    m.text = html
    m.raise_for_status.return_value = None
    return m


def _mock_yaml_resp(text):
    m = MagicMock()
    m.text = text
    m.raise_for_status.return_value = None
    return m


def test_scrape_returns_three_sources():
    atlas_resp = _mock_yaml_resp(SAMPLE_ATLAS_YAML)
    html_resp = _mock_html(SAMPLE_HTML)
    with patch("scrapers.ai_security.fetch", side_effect=[html_resp, atlas_resp, html_resp]):
        result = ai.scrape()
    assert result["category"] == "ai_security"
    assert len(result["sources"]) == 3


def test_scrape_source_names_are_correct():
    atlas_resp = _mock_yaml_resp(SAMPLE_ATLAS_YAML)
    html_resp = _mock_html(SAMPLE_HTML)
    with patch("scrapers.ai_security.fetch", side_effect=[html_resp, atlas_resp, html_resp]):
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


def test_scrape_mitre_atlas_returns_tactics_and_techniques():
    with patch("scrapers.ai_security.fetch", return_value=_mock_yaml_resp(SAMPLE_ATLAS_YAML)):
        result = ai.scrape_mitre_atlas()
    assert result["name"] == "MITRE ATLAS Matrix"
    assert result["type"] == "static"
    assert "error" not in result
    data = result["data"]
    assert len(data["tactics"]) == 2
    assert data["tactics"][0]["id"] == "AML.TA0001"
    assert data["tactics"][0]["name"] == "Reconnaissance"
    assert len(data["techniques"]) == 2
    assert data["techniques"][0]["id"] == "AML.T0000"
    assert data["total_techniques"] == 2


def test_scrape_mitre_atlas_returns_error_on_failure():
    with patch("scrapers.ai_security.fetch", side_effect=Exception("connection refused")):
        result = ai.scrape_mitre_atlas()
    assert "error" in result
    assert "connection refused" in result["error"]
