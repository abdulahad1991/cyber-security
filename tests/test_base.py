import json
import os
import tempfile
from unittest.mock import patch, MagicMock
import pytest
import requests

import scrapers.base as base


def test_fetch_returns_response_on_success():
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    with patch("scrapers.base.requests.get", return_value=mock_resp) as mock_get:
        result = base.fetch("https://example.com")
    assert result is mock_resp
    mock_get.assert_called_once()


def test_fetch_retries_on_failure_then_succeeds():
    fail = MagicMock()
    fail.raise_for_status.side_effect = requests.RequestException("timeout")
    ok = MagicMock()
    ok.raise_for_status.return_value = None
    with patch("scrapers.base.requests.get", side_effect=[fail, ok]):
        with patch("scrapers.base.time.sleep"):
            result = base.fetch("https://example.com", retries=2, delay=0)
    assert result is ok


def test_fetch_raises_after_all_retries_exhausted():
    fail = MagicMock()
    fail.raise_for_status.side_effect = requests.RequestException("timeout")
    with patch("scrapers.base.requests.get", return_value=fail):
        with patch("scrapers.base.time.sleep"):
            with pytest.raises(requests.RequestException):
                base.fetch("https://example.com", retries=2, delay=0)


def test_html_to_text_strips_scripts_and_nav():
    html = "<html><nav>Skip</nav><script>var x=1</script><body><h1>Hello</h1><p>World</p></body></html>"
    result = base.html_to_text(html)
    assert "Hello" in result
    assert "World" in result
    assert "Skip" not in result
    assert "var x" not in result


def test_extract_sections_returns_title_and_content():
    html = """<html><body>
    <h2>Section A</h2><p>Content A</p>
    <h2>Section B</h2><p>Content B</p>
    </body></html>"""
    sections = base.extract_sections(html, "h2")
    assert len(sections) == 2
    assert sections[0]["title"] == "Section A"
    assert "Content A" in sections[0]["content"]
    assert sections[1]["title"] == "Section B"


def test_extract_sections_stops_at_next_heading():
    html = """<html><body>
    <h2>A</h2><p>Para A</p><p>Para A2</p>
    <h2>B</h2><p>Para B</p>
    </body></html>"""
    sections = base.extract_sections(html, "h2")
    assert "Para B" not in sections[0]["content"]


def test_extract_sections_auto_returns_h2_when_present():
    html = "<html><body><h2>A</h2><p>Content A</p></body></html>"
    sections = base.extract_sections_auto(html)
    assert sections[0]["title"] == "A"
    assert "Content A" in sections[0]["content"]


def test_extract_sections_auto_falls_back_to_h3():
    html = "<html><body><h3>B</h3><p>Content B</p></body></html>"
    sections = base.extract_sections_auto(html)
    assert sections[0]["title"] == "B"
    assert "Content B" in sections[0]["content"]


def test_extract_sections_auto_falls_back_to_h4():
    html = "<html><body><h4>C</h4><p>Content C</p></body></html>"
    sections = base.extract_sections_auto(html)
    assert sections[0]["title"] == "C"


def test_extract_sections_auto_returns_empty_when_no_headings():
    html = "<html><body><p>No headings here</p></body></html>"
    sections = base.extract_sections_auto(html)
    assert sections == []


def test_write_json_creates_file_with_correct_content():
    data = {"category": "test", "sources": []}
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("scrapers.base.DATA_DIR", tmpdir):
            path = base.write_json("test_cat", data)
        with open(path) as f:
            result = json.load(f)
    assert result == data
    assert path.endswith("test_cat.json")
