# Cybersecurity Data Scraper — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a modular Python scraper that fetches cybersecurity data from ~25 authoritative sources, outputs validated JSON files to `data/`, and auto-promotes them to GitHub Pages via three GitHub Actions workflows.

**Architecture:** Six category scraper modules under `scrapers/` each produce a consistent JSON envelope; `runner.py` orchestrates them by mode (`live`/`static`/`all`); `validate.py` gates promotion from `dev` → `main`; `promote.yml` auto-merges when validation passes, opens a PR for manual review when it fails.

**Tech Stack:** Python 3.11, requests, beautifulsoup4, lxml, pytest, GitHub Actions, GitHub Pages (served from `main` root)

---

## File Map

| File | Responsibility |
|---|---|
| `scrapers/__init__.py` | Empty package marker |
| `scrapers/base.py` | `fetch()`, `html_to_text()`, `extract_sections()`, `write_json()` |
| `scrapers/vulnerabilities.py` | CISA KEV JSON feed (live) |
| `scrapers/threat_intel.py` | OpenPhish feed + APWG resources (live) |
| `scrapers/risk_compliance.py` | NIST SP 800-30, PCI DSS, ISO 27001, CIS (static HTML) |
| `scrapers/security_testing.py` | SSL Labs docs, SecurityHeaders, HSTS Preload (static HTML) |
| `scrapers/privacy.py` | GDPR-info.eu, ICO, CCPA, Enforcement Tracker (static HTML) |
| `scrapers/ai_security.py` | OWASP LLM Top 10, MITRE ATLAS, NIST AI (static HTML) |
| `runner.py` | CLI orchestrator — `--mode live/static/all`, writes manifest.json |
| `validate.py` | Quality gate — 5 checks, exits 1 on failure |
| `data/.gitkeep` | Ensures data/ directory exists in git before first scrape |
| `tests/__init__.py` | Empty package marker |
| `tests/test_base.py` | Unit tests for base helpers |
| `tests/test_vulnerabilities.py` | Unit tests for CISA KEV scraper |
| `tests/test_threat_intel.py` | Unit tests for OpenPhish + APWG scrapers |
| `tests/test_risk_compliance.py` | Unit tests for static HTML scraper pattern |
| `tests/test_security_testing.py` | Unit tests for security testing scrapers |
| `tests/test_privacy.py` | Unit tests for privacy scrapers |
| `tests/test_ai_security.py` | Unit tests for AI security scrapers |
| `tests/test_runner.py` | Unit tests for runner orchestration |
| `tests/test_validate.py` | Unit tests for all 5 validation checks |
| `requirements.txt` | requests, beautifulsoup4, lxml |
| `requirements-dev.txt` | pytest, pytest-cov |
| `.gitignore` | Standard Python ignores |
| `.github/workflows/scrape_live.yml` | Cron every 6h → runs live scrapers → pushes data/ to dev |
| `.github/workflows/scrape_static.yml` | Cron weekly Sunday 02:00 UTC → runs static scrapers → pushes data/ to dev |
| `.github/workflows/promote.yml` | Triggered on dev push → validate → auto-merge to main or open PR |

---

## Task 1: Project Scaffold

**Files:**
- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Create: `.gitignore`
- Create: `scrapers/__init__.py`
- Create: `tests/__init__.py`
- Create: `data/.gitkeep`

- [ ] **Step 1: Create requirements.txt**

```
requests>=2.31
beautifulsoup4>=4.12
lxml>=5.0
```

- [ ] **Step 2: Create requirements-dev.txt**

```
pytest>=7.4
pytest-cov>=4.1
```

- [ ] **Step 3: Create .gitignore**

```
__pycache__/
*.pyc
*.pyo
.pytest_cache/
.coverage
htmlcov/
*.egg-info/
dist/
build/
venv/
.env
data/*.json
```

Note: `data/*.json` is in `.gitignore` on `main` — the JSON files live on `dev` and get promoted to `main` via merge. The `.gitkeep` file is committed explicitly.

- [ ] **Step 4: Create package markers and data dir placeholder**

Create `scrapers/__init__.py` — empty file.
Create `tests/__init__.py` — empty file.
Create `data/.gitkeep` — empty file.

- [ ] **Step 5: Install dev dependencies**

Run: `pip install -r requirements.txt -r requirements-dev.txt`
Expected: packages install without error

- [ ] **Step 6: Commit**

```bash
git add requirements.txt requirements-dev.txt .gitignore scrapers/__init__.py tests/__init__.py data/.gitkeep
git commit -m "chore: project scaffold — deps, gitignore, package structure"
```

---

## Task 2: scrapers/base.py

**Files:**
- Create: `tests/test_base.py`
- Create: `scrapers/base.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_base.py`:

```python
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


def test_write_json_creates_file_with_correct_content():
    data = {"category": "test", "sources": []}
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("scrapers.base.DATA_DIR", tmpdir):
            path = base.write_json("test_cat", data)
        with open(path) as f:
            result = json.load(f)
    assert result == data
    assert path.endswith("test_cat.json")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_base.py -v`
Expected: `ModuleNotFoundError` or `ImportError` — base.py does not exist yet

- [ ] **Step 3: Implement scrapers/base.py**

```python
import time
import json
import os
from typing import Any

import requests
from bs4 import BeautifulSoup

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")


def fetch(url: str, retries: int = 3, delay: float = 1.5, timeout: int = 30) -> requests.Response:
    headers = {"User-Agent": "XennTool-Scraper/1.0 (+https://xenntool.com)"}
    last_err: Exception = RuntimeError("No attempts made")
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            last_err = e
            if attempt < retries - 1:
                time.sleep(delay * (2 ** attempt))
    raise last_err


def html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    return " ".join(soup.get_text(" ", strip=True).split())


def extract_sections(html: str, heading_tag: str = "h2") -> list[dict]:
    soup = BeautifulSoup(html, "lxml")
    sections = []
    for heading in soup.find_all(heading_tag):
        title = heading.get_text(strip=True)
        parts = []
        for sibling in heading.find_next_siblings():
            if sibling.name == heading_tag:
                break
            text = sibling.get_text(" ", strip=True)
            if text:
                parts.append(text)
        sections.append({"title": title, "content": " ".join(parts)})
    return sections


def write_json(category: str, data: dict[str, Any]) -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, f"{category}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_base.py -v`
Expected: 7 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add scrapers/base.py tests/test_base.py
git commit -m "feat: add base scraper helpers — fetch, html_to_text, extract_sections, write_json"
```

---

## Task 3: scrapers/vulnerabilities.py

**Files:**
- Create: `tests/test_vulnerabilities.py`
- Create: `scrapers/vulnerabilities.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_vulnerabilities.py`:

```python
from unittest.mock import patch, MagicMock
import scrapers.vulnerabilities as vuln


SAMPLE_KEV = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-20353",
            "vendorProject": "Cisco",
            "product": "ASA and FTD",
            "vulnerabilityName": "Cisco ASA DoS Vulnerability",
            "dateAdded": "2024-04-24",
            "shortDescription": "A vulnerability in Cisco ASA software.",
            "dueDate": "2024-05-01",
        }
    ]
}


def _mock_json_resp(data):
    m = MagicMock()
    m.json.return_value = data
    m.raise_for_status.return_value = None
    return m


def test_scrape_cisa_kev_returns_correct_envelope():
    with patch("scrapers.vulnerabilities.fetch", return_value=_mock_json_resp(SAMPLE_KEV)):
        result = vuln.scrape_cisa_kev()
    assert result["name"] == "CISA Known Exploited Vulnerabilities"
    assert result["type"] == "live"
    assert "error" not in result


def test_scrape_cisa_kev_maps_fields_correctly():
    with patch("scrapers.vulnerabilities.fetch", return_value=_mock_json_resp(SAMPLE_KEV)):
        result = vuln.scrape_cisa_kev()
    entry = result["data"]["entries"][0]
    assert entry["cve_id"] == "CVE-2024-20353"
    assert entry["vendor"] == "Cisco"
    assert entry["product"] == "ASA and FTD"
    assert entry["description"] == "A vulnerability in Cisco ASA software."


def test_scrape_cisa_kev_returns_error_on_fetch_failure():
    with patch("scrapers.vulnerabilities.fetch", side_effect=Exception("network error")):
        result = vuln.scrape_cisa_kev()
    assert "error" in result
    assert "network error" in result["error"]


def test_scrape_cisa_kev_caps_entries_at_500():
    many = [
        {"cveID": f"CVE-2024-{i:05d}", "vendorProject": "Vendor", "product": "P",
         "vulnerabilityName": "V", "dateAdded": "2024-01-01",
         "shortDescription": "D", "dueDate": "2024-02-01"}
        for i in range(600)
    ]
    with patch("scrapers.vulnerabilities.fetch", return_value=_mock_json_resp({"vulnerabilities": many})):
        result = vuln.scrape_cisa_kev()
    assert len(result["data"]["entries"]) == 500
    assert result["data"]["total_count"] == 600


def test_scrape_returns_category_envelope():
    with patch("scrapers.vulnerabilities.fetch", return_value=_mock_json_resp(SAMPLE_KEV)):
        result = vuln.scrape()
    assert result["category"] == "vulnerabilities"
    assert "last_updated" in result
    assert len(result["sources"]) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_vulnerabilities.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement scrapers/vulnerabilities.py**

```python
from datetime import datetime, timezone

from scrapers.base import fetch

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def scrape_cisa_kev() -> dict:
    try:
        resp = fetch(CISA_KEV_URL)
        raw = resp.json()
        vulns = raw.get("vulnerabilities", [])
        entries = [
            {
                "cve_id": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "description": v.get("shortDescription"),
            }
            for v in vulns[:500]
        ]
        return {
            "name": "CISA Known Exploited Vulnerabilities",
            "url": CISA_KEV_URL,
            "type": "live",
            "data": {
                "description": "CISA catalog of vulnerabilities actively exploited in the wild",
                "entries": entries,
                "total_count": len(vulns),
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {
            "name": "CISA Known Exploited Vulnerabilities",
            "url": CISA_KEV_URL,
            "type": "live",
            "error": str(e),
        }


def scrape() -> dict:
    return {
        "category": "vulnerabilities",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "sources": [scrape_cisa_kev()],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_vulnerabilities.py -v`
Expected: 5 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add scrapers/vulnerabilities.py tests/test_vulnerabilities.py
git commit -m "feat: add CISA KEV vulnerabilities scraper"
```

---

## Task 4: scrapers/threat_intel.py

**Files:**
- Create: `tests/test_threat_intel.py`
- Create: `scrapers/threat_intel.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_threat_intel.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_threat_intel.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement scrapers/threat_intel.py**

```python
from datetime import datetime, timezone

from scrapers.base import fetch, extract_sections, html_to_text

OPENPHISH_URL = "https://openphish.com/feed.txt"
APWG_URL = "https://apwg.org/resources/"


def scrape_openphish() -> dict:
    try:
        resp = fetch(OPENPHISH_URL)
        lines = [ln.strip() for ln in resp.text.splitlines() if ln.strip().startswith("http")]
        return {
            "name": "OpenPhish Community Feed",
            "url": OPENPHISH_URL,
            "type": "live",
            "data": {
                "description": "Community-sourced phishing URL feed, updated multiple times daily",
                "entries": lines[:200],
                "total_count": len(lines),
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {
            "name": "OpenPhish Community Feed",
            "url": OPENPHISH_URL,
            "type": "live",
            "error": str(e),
        }


def scrape_apwg() -> dict:
    try:
        resp = fetch(APWG_URL)
        sections = extract_sections(resp.text, "h2")
        summary = html_to_text(resp.text)[:2000]
        return {
            "name": "APWG Resources",
            "url": APWG_URL,
            "type": "static",
            "data": {
                "description": "Anti-Phishing Working Group resources and phishing trend reports",
                "sections": sections[:10],
                "summary": summary,
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {
            "name": "APWG Resources",
            "url": APWG_URL,
            "type": "static",
            "error": str(e),
        }


def scrape() -> dict:
    return {
        "category": "threat_intel",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "sources": [scrape_openphish(), scrape_apwg()],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_threat_intel.py -v`
Expected: 7 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add scrapers/threat_intel.py tests/test_threat_intel.py
git commit -m "feat: add threat intelligence scraper — OpenPhish feed and APWG resources"
```

---

## Task 5: scrapers/risk_compliance.py

**Files:**
- Create: `tests/test_risk_compliance.py`
- Create: `scrapers/risk_compliance.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_risk_compliance.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_risk_compliance.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement scrapers/risk_compliance.py**

```python
from datetime import datetime, timezone

from scrapers.base import fetch, html_to_text, extract_sections

NIST_URL = "https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final"
PCI_URL = "https://www.pcisecuritystandards.org/document_library/"
ISO_URL = "https://www.iso27001security.com/html/iso27001.html"
CIS_URL = "https://www.cisecurity.org/benchmark/"


def _scrape_source(name: str, url: str, description: str) -> dict:
    try:
        resp = fetch(url)
        sections = extract_sections(resp.text, "h2")
        summary = html_to_text(resp.text)[:3000]
        return {
            "name": name,
            "url": url,
            "type": "static",
            "data": {
                "description": description,
                "sections": sections[:15],
                "summary": summary,
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {"name": name, "url": url, "type": "static", "error": str(e)}


def scrape() -> dict:
    return {
        "category": "risk_compliance",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "sources": [
            _scrape_source(
                "NIST SP 800-30 Risk Management", NIST_URL,
                "NIST guide for conducting risk assessments of information systems",
            ),
            _scrape_source(
                "PCI DSS Document Library", PCI_URL,
                "PCI Security Standards Council official documentation and compliance resources",
            ),
            _scrape_source(
                "ISO/IEC 27001 Control Mapping", ISO_URL,
                "ISO 27001 information security management standard control reference",
            ),
            _scrape_source(
                "CIS Benchmarks", CIS_URL,
                "Center for Internet Security configuration security benchmarks",
            ),
        ],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_risk_compliance.py -v`
Expected: 6 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add scrapers/risk_compliance.py tests/test_risk_compliance.py
git commit -m "feat: add risk and compliance scraper — NIST, PCI DSS, ISO 27001, CIS"
```

---

## Task 6: scrapers/security_testing.py

**Files:**
- Create: `tests/test_security_testing.py`
- Create: `scrapers/security_testing.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_security_testing.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_security_testing.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement scrapers/security_testing.py**

```python
from datetime import datetime, timezone

from scrapers.base import fetch, html_to_text, extract_sections

SSL_LABS_URL = "https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs.md"
SEC_HEADERS_URL = "https://securityheaders.com/"
HSTS_URL = "https://hstspreload.org/"


def _scrape_source(name: str, url: str, description: str) -> dict:
    try:
        resp = fetch(url)
        sections = extract_sections(resp.text, "h2")
        summary = html_to_text(resp.text)[:3000]
        return {
            "name": name,
            "url": url,
            "type": "static",
            "data": {
                "description": description,
                "sections": sections[:15],
                "summary": summary,
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {"name": name, "url": url, "type": "static", "error": str(e)}


def scrape() -> dict:
    return {
        "category": "security_testing",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "sources": [
            _scrape_source(
                "Qualys SSL Labs API Docs", SSL_LABS_URL,
                "SSL/TLS grading criteria and endpoint testing documentation",
            ),
            _scrape_source(
                "Security Headers Reference", SEC_HEADERS_URL,
                "HTTP security header grading rules and best practices",
            ),
            _scrape_source(
                "HSTS Preload", HSTS_URL,
                "HTTP Strict Transport Security preload list criteria and submission process",
            ),
        ],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_security_testing.py -v`
Expected: 4 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add scrapers/security_testing.py tests/test_security_testing.py
git commit -m "feat: add security testing scraper — SSL Labs, Security Headers, HSTS Preload"
```

---

## Task 7: scrapers/privacy.py

**Files:**
- Create: `tests/test_privacy.py`
- Create: `scrapers/privacy.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_privacy.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_privacy.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement scrapers/privacy.py**

```python
from datetime import datetime, timezone

from scrapers.base import fetch, html_to_text, extract_sections

GDPR_URL = "https://gdpr-info.eu/"
ICO_URL = (
    "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/"
    "accountability-and-governance/guide-to-data-protection-impact-assessments-dpias/"
)
CCPA_URL = "https://oag.ca.gov/privacy/ccpa"
ENFORCEMENT_URL = "https://www.enforcementtracker.com/"


def _scrape_source(name: str, url: str, description: str) -> dict:
    try:
        resp = fetch(url)
        sections = extract_sections(resp.text, "h2")
        summary = html_to_text(resp.text)[:3000]
        return {
            "name": name,
            "url": url,
            "type": "static",
            "data": {
                "description": description,
                "sections": sections[:15],
                "summary": summary,
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {"name": name, "url": url, "type": "static", "error": str(e)}


def scrape() -> dict:
    return {
        "category": "privacy",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "sources": [
            _scrape_source(
                "GDPR Full Text", GDPR_URL,
                "Official GDPR articles and recitals reference",
            ),
            _scrape_source(
                "ICO DPIA Guide", ICO_URL,
                "UK ICO guide to Data Protection Impact Assessments",
            ),
            _scrape_source(
                "CCPA Text", CCPA_URL,
                "California Consumer Privacy Act official text and regulations",
            ),
            _scrape_source(
                "GDPR Enforcement Tracker", ENFORCEMENT_URL,
                "Database of GDPR fines and enforcement actions across Europe",
            ),
        ],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_privacy.py -v`
Expected: 4 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add scrapers/privacy.py tests/test_privacy.py
git commit -m "feat: add privacy scraper — GDPR, ICO DPIA, CCPA, Enforcement Tracker"
```

---

## Task 8: scrapers/ai_security.py

**Files:**
- Create: `tests/test_ai_security.py`
- Create: `scrapers/ai_security.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ai_security.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_ai_security.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement scrapers/ai_security.py**

```python
from datetime import datetime, timezone

from scrapers.base import fetch, html_to_text, extract_sections

OWASP_LLM_URL = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
MITRE_ATLAS_URL = "https://atlas.mitre.org/matrices/ATLAS"
NIST_AI_URL = "https://www.nist.gov/itl/ai-risk-management-framework"


def _scrape_source(name: str, url: str, description: str) -> dict:
    try:
        resp = fetch(url)
        sections = extract_sections(resp.text, "h2")
        summary = html_to_text(resp.text)[:3000]
        return {
            "name": name,
            "url": url,
            "type": "static",
            "data": {
                "description": description,
                "sections": sections[:15],
                "summary": summary,
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {"name": name, "url": url, "type": "static", "error": str(e)}


def scrape() -> dict:
    return {
        "category": "ai_security",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "sources": [
            _scrape_source(
                "OWASP LLM Top 10", OWASP_LLM_URL,
                "OWASP Top 10 security risks for Large Language Model applications",
            ),
            _scrape_source(
                "MITRE ATLAS Matrix", MITRE_ATLAS_URL,
                "Adversarial Threat Landscape for AI Systems — tactics and techniques matrix",
            ),
            _scrape_source(
                "NIST AI Risk Management Framework", NIST_AI_URL,
                "NIST AI 100-1 framework for managing risks in AI systems",
            ),
        ],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_ai_security.py -v`
Expected: 4 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add scrapers/ai_security.py tests/test_ai_security.py
git commit -m "feat: add AI security scraper — OWASP LLM Top 10, MITRE ATLAS, NIST AI"
```

---

## Task 9: runner.py

**Files:**
- Create: `tests/test_runner.py`
- Create: `runner.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_runner.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_runner.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement runner.py**

```python
import argparse
import importlib
import json
import sys
from datetime import datetime, timezone

from scrapers.base import write_json

LIVE_MODULES = ["vulnerabilities", "threat_intel"]
STATIC_MODULES = ["risk_compliance", "security_testing", "privacy", "ai_security"]


def _import_scraper(name: str):
    return importlib.import_module(f"scrapers.{name}")


def run(mode: str) -> dict:
    modules = LIVE_MODULES if mode == "live" else STATIC_MODULES if mode == "static" else LIVE_MODULES + STATIC_MODULES
    results = {"scraped": [], "failed": [], "total_entries": 0}
    manifest_categories = {}

    for name in modules:
        print(f"Scraping {name}...")
        try:
            mod = _import_scraper(name)
            data = mod.scrape()
            path = write_json(name, data)
            entry_count = sum(
                len(s.get("data", {}).get("entries", []))
                for s in data.get("sources", [])
                if "error" not in s
            )
            results["scraped"].append(name)
            results["total_entries"] += entry_count
            manifest_categories[name] = {
                "last_updated": data.get("last_updated"),
                "source_count": len(data.get("sources", [])),
                "entry_count": entry_count,
            }
            print(f"  ✓ {name}: {entry_count} entries → {path}")
        except Exception as e:
            results["failed"].append({"module": name, "error": str(e)})
            print(f"  ✗ {name}: {e}", file=sys.stderr)

    manifest = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "categories": manifest_categories,
    }
    write_json("manifest", manifest)

    print(
        f"\nDone: {len(results['scraped'])} scraped, "
        f"{len(results['failed'])} failed, "
        f"{results['total_entries']} total entries"
    )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="XennTool cybersecurity data scraper")
    parser.add_argument(
        "--mode", choices=["live", "static", "all"], default="all",
        help="Which scrapers to run (default: all)"
    )
    args = parser.parse_args()
    run(args.mode)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_runner.py -v`
Expected: 6 tests PASSED

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -v`
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add runner.py tests/test_runner.py
git commit -m "feat: add runner orchestrator — --mode live/static/all, manifest.json output"
```

---

## Task 10: validate.py

**Files:**
- Create: `tests/test_validate.py`
- Create: `validate.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_validate.py`:

```python
import json
import os
import tempfile
from datetime import datetime, timezone, timedelta

import validate


def _write(d, filename, data):
    with open(os.path.join(d, filename), "w") as f:
        json.dump(data, f)


def _make_source(name, entries=None, error=None):
    s = {"name": name, "type": "live"}
    if error:
        s["error"] = error
    else:
        s["data"] = {"entries": entries or []}
    return s


def _write_full_valid_set(d, vulns=150, threat=60):
    cats = {
        "risk_compliance": {"category": "risk_compliance", "last_updated": "2026-01-01T00:00:00+00:00",
                             "sources": [_make_source("NIST")]},
        "security_testing": {"category": "security_testing", "last_updated": "2026-01-01T00:00:00+00:00",
                              "sources": [_make_source("SSL")]},
        "privacy": {"category": "privacy", "last_updated": "2026-01-01T00:00:00+00:00",
                    "sources": [_make_source("GDPR")]},
        "ai_security": {"category": "ai_security", "last_updated": "2026-01-01T00:00:00+00:00",
                        "sources": [_make_source("OWASP")]},
        "threat_intel": {"category": "threat_intel", "last_updated": "2026-01-01T00:00:00+00:00",
                         "sources": [_make_source("OpenPhish", entries=["url"] * threat)]},
        "vulnerabilities": {"category": "vulnerabilities", "last_updated": "2026-01-01T00:00:00+00:00",
                            "sources": [_make_source("CISA", entries=[{"cve_id": "CVE-001"}] * vulns)]},
    }
    for name, data in cats.items():
        _write(d, f"{name}.json", data)
    _write(d, "manifest.json", {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "categories": {},
    })


def test_passes_with_valid_complete_data():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        result = validate.validate(d)
    assert result["passed"] is True
    assert result["errors"] == []


def test_fails_when_required_file_missing():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        os.remove(os.path.join(d, "privacy.json"))
        result = validate.validate(d)
    assert result["passed"] is False
    assert any("privacy.json" in e for e in result["errors"])


def test_fails_when_envelope_key_missing():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        _write(d, "privacy.json", {"category": "privacy", "sources": []})
        result = validate.validate(d)
    assert result["passed"] is False
    assert any("last_updated" in e for e in result["errors"])


def test_fails_when_vulnerabilities_below_minimum():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d, vulns=50)
        result = validate.validate(d)
    assert result["passed"] is False
    assert any("vulnerabilities" in e and "minimum" in e for e in result["errors"])


def test_fails_when_threat_intel_below_minimum():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d, threat=10)
        result = validate.validate(d)
    assert result["passed"] is False
    assert any("threat_intel" in e and "minimum" in e for e in result["errors"])


def test_fails_when_all_sources_have_errors():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        _write(d, "threat_intel.json", {
            "category": "threat_intel",
            "last_updated": "2026-01-01T00:00:00+00:00",
            "sources": [
                _make_source("OpenPhish", error="timeout"),
                _make_source("APWG", error="404"),
            ],
        })
        result = validate.validate(d)
    assert result["passed"] is False
    assert any("all sources failed" in e for e in result["errors"])


def test_warns_when_manifest_is_stale():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        stale = (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat()
        _write(d, "manifest.json", {"updated_at": stale, "categories": {}})
        result = validate.validate(d)
    assert any("old" in w or ">7h" in w or "8h" in w for w in result["warnings"])


def test_summary_string_includes_pass_or_fail():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        result = validate.validate(d)
    assert "PASS" in result["summary"] or "FAIL" in result["summary"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_validate.py -v`
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement validate.py**

```python
import json
import os
import sys
from datetime import datetime, timezone, timedelta

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

REQUIRED_CATEGORIES = [
    "risk_compliance",
    "security_testing",
    "privacy",
    "threat_intel",
    "ai_security",
    "vulnerabilities",
]

LIVE_MINIMUMS = {
    "threat_intel": 50,
    "vulnerabilities": 100,
}


def _count_entries(data: dict) -> int:
    return sum(
        len(s.get("data", {}).get("entries", []))
        for s in data.get("sources", [])
        if "error" not in s
    )


def validate(data_dir: str = DATA_DIR) -> dict:
    errors: list[str] = []
    warnings: list[str] = []

    for cat in REQUIRED_CATEGORIES:
        path = os.path.join(data_dir, f"{cat}.json")
        if not os.path.exists(path):
            errors.append(f"Missing file: {cat}.json")
            continue
        if os.path.getsize(path) == 0:
            errors.append(f"Empty file: {cat}.json")
            continue

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON in {cat}.json: {e}")
            continue

        for key in ("category", "last_updated", "sources"):
            if key not in data:
                errors.append(f"{cat}.json missing required key: '{key}'")

        if cat in LIVE_MINIMUMS:
            count = _count_entries(data)
            minimum = LIVE_MINIMUMS[cat]
            if count < minimum:
                errors.append(
                    f"{cat}.json has {count} entries, minimum is {minimum}"
                )

        sources = data.get("sources", [])
        if sources and all("error" in s for s in sources):
            errors.append(f"{cat}.json: all sources failed (all have error keys)")

    manifest_path = os.path.join(data_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        warnings.append("manifest.json is missing")
    else:
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
            updated_at = datetime.fromisoformat(manifest["updated_at"])
            age = datetime.now(timezone.utc) - updated_at
            if age > timedelta(hours=7):
                hours = int(age.total_seconds() // 3600)
                warnings.append(f"manifest.json is {hours}h old (>7h threshold)")
        except (ValueError, KeyError, TypeError):
            warnings.append("manifest.json has an invalid or missing updated_at timestamp")

    passed = len(errors) == 0
    return {
        "passed": passed,
        "errors": errors,
        "warnings": warnings,
        "summary": f"{'PASS' if passed else 'FAIL'}: {len(errors)} errors, {len(warnings)} warnings",
    }


def main() -> None:
    result = validate()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_validate.py -v`
Expected: 8 tests PASSED

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: all tests PASS. Note the count — it should be 40+ tests total.

- [ ] **Step 6: Commit**

```bash
git add validate.py tests/test_validate.py
git commit -m "feat: add validation gate — 5 quality checks, structured JSON output, exits 1 on failure"
```

---

## Task 11: .github/workflows/scrape_live.yml

**Files:**
- Create: `.github/workflows/scrape_live.yml`

- [ ] **Step 1: Create the workflows directory**

```bash
mkdir -p .github/workflows
```

- [ ] **Step 2: Create .github/workflows/scrape_live.yml**

```yaml
name: Scrape Live Data

on:
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:

permissions:
  contents: write

jobs:
  scrape:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout dev branch
        uses: actions/checkout@v4
        with:
          ref: dev
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Merge latest main into dev
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git fetch origin main
          git merge origin/main --no-edit --strategy-option=ours

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run live scrapers
        run: python runner.py --mode live

      - name: Commit and push data to dev
        run: |
          git add data/
          git diff --staged --quiet && { echo "No data changes to commit"; exit 0; }
          git commit -m "chore: live scrape $(date -u +%Y-%m-%dT%H:%M:%SZ)"
          git push origin dev
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/scrape_live.yml
git commit -m "ci: add scrape_live workflow — runs every 6h, commits data to dev"
```

---

## Task 12: .github/workflows/scrape_static.yml

**Files:**
- Create: `.github/workflows/scrape_static.yml`

- [ ] **Step 1: Create .github/workflows/scrape_static.yml**

```yaml
name: Scrape Static Data

on:
  schedule:
    - cron: '0 2 * * 0'
  workflow_dispatch:

permissions:
  contents: write

jobs:
  scrape:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout dev branch
        uses: actions/checkout@v4
        with:
          ref: dev
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Merge latest main into dev
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git fetch origin main
          git merge origin/main --no-edit --strategy-option=ours

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run static scrapers
        run: python runner.py --mode static

      - name: Commit and push data to dev
        run: |
          git add data/
          git diff --staged --quiet && { echo "No data changes to commit"; exit 0; }
          git commit -m "chore: static scrape $(date -u +%Y-%m-%dT%H:%M:%SZ)"
          git push origin dev
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/scrape_static.yml
git commit -m "ci: add scrape_static workflow — runs weekly Sunday 02:00 UTC, commits data to dev"
```

---

## Task 13: .github/workflows/promote.yml

**Files:**
- Create: `.github/workflows/promote.yml`

- [ ] **Step 1: Create .github/workflows/promote.yml**

```yaml
name: Validate and Promote to Main

on:
  push:
    branches:
      - dev

permissions:
  contents: write
  pull-requests: write

jobs:
  validate-and-promote:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout dev
        uses: actions/checkout@v4
        with:
          ref: dev
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run validation
        id: validate
        run: |
          python validate.py > validation_result.json || true
          cat validation_result.json
          PASSED=$(python -c "import json; d=json.load(open('validation_result.json')); print(str(d['passed']).lower())")
          echo "passed=$PASSED" >> $GITHUB_OUTPUT

      - name: Merge dev into main (validation passed)
        if: steps.validate.outputs.passed == 'true'
        run: |
          git config user.name "abdulahad1991"
          git config user.email "abdulahad1991@gmail.com"
          git fetch origin main
          git checkout main
          git merge dev --no-edit
          git push origin main
          echo "Promoted dev → main successfully"

      - name: Open PR for manual review (validation failed)
        if: steps.validate.outputs.passed == 'false'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          SUMMARY=$(python -c "
          import json
          with open('validation_result.json') as f:
              r = json.load(f)
          lines = [r['summary']]
          lines += ['- ERROR: ' + e for e in r['errors']]
          lines += ['- WARN: ' + w for w in r['warnings']]
          print('\n'.join(lines))
          ")
          gh pr create \
            --base main \
            --head dev \
            --title "Data update (validation failed — manual review needed)" \
            --body "## Validation Failed

          ${SUMMARY}

          Please review the errors above before merging." \
            2>/dev/null || echo "PR already exists — skipping creation"
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/promote.yml
git commit -m "ci: add promote workflow — validates on dev push, auto-merges to main or opens PR on failure"
```

---

## Task 14: Dev Branch Setup and GitHub Pages

**Files:** No new files — git and GitHub configuration

- [ ] **Step 1: Push main to GitHub**

```bash
git push origin main
```

Expected: branch `main` appears at `https://github.com/abdulahad1991/cyber-security`

- [ ] **Step 2: Create and push dev branch from main**

```bash
git checkout -b dev
git push origin dev
git checkout main
```

Expected: branch `dev` appears on GitHub

- [ ] **Step 3: Enable GitHub Pages via GitHub CLI**

```bash
gh api repos/abdulahad1991/cyber-security/pages \
  --method POST \
  --field source='{"branch":"main","path":"/"}' \
  --silent && echo "Pages enabled" || echo "Pages may already be configured — check repo settings"
```

Expected: GitHub Pages enabled, serving from `main` root. URL: `https://abdulahad1991.github.io/cyber-security/`

- [ ] **Step 4: Trigger the first full scrape manually**

On GitHub, go to Actions → "Scrape Static Data" → Run workflow (on `dev`).
Then go to Actions → "Scrape Live Data" → Run workflow (on `dev`).

Wait for both to complete. Then go to Actions → "Validate and Promote to Main" — it should trigger automatically when `dev` is pushed.

- [ ] **Step 5: Verify data is live on GitHub Pages**

Run:
```bash
curl -s https://abdulahad1991.github.io/cyber-security/data/manifest.json | python -m json.tool
```

Expected: JSON with `updated_at`, `mode`, and `categories` keys

- [ ] **Step 6: Verify individual category files**

```bash
curl -s https://abdulahad1991.github.io/cyber-security/data/vulnerabilities.json | python -c "
import json, sys
d = json.load(sys.stdin)
print('Category:', d['category'])
print('Sources:', len(d['sources']))
print('Entries:', sum(len(s.get('data',{}).get('entries',[])) for s in d['sources'] if 'error' not in s))
"
```

Expected: `Category: vulnerabilities`, `Sources: 1`, `Entries: 100+`

- [ ] **Step 7: Final commit — push design docs to main**

```bash
git add docs/
git commit -m "docs: add design spec and implementation plan" 2>/dev/null || echo "docs already committed"
git push origin main
```

---

## Self-Review Checklist

**Spec coverage:**
- ✓ Six category scrapers (risk_compliance, security_testing, privacy, threat_intel, ai_security, vulnerabilities)
- ✓ runner.py with --mode live/static/all
- ✓ validate.py with all 5 checks
- ✓ scrape_live.yml (every 6h, dev branch)
- ✓ scrape_static.yml (weekly Sunday 02:00 UTC, dev branch)
- ✓ promote.yml (validates on dev push, auto-merges or opens PR)
- ✓ GitHub Pages from main root
- ✓ Consistent JSON envelope across all categories
- ✓ manifest.json with timestamps
- ✓ Error isolation — one failed source does not stop others
- ✓ Tests cover all modules with mocked HTTP (no live requests in tests)
- ✓ Dev branch created and pushed

**Type consistency:** `_scrape_source()` signature is identical in risk_compliance, security_testing, privacy, and ai_security. `scrape()` in all modules returns `{"category": str, "last_updated": str, "sources": list}`. `write_json(category, data)` used consistently in runner.py.

**No placeholders:** All code blocks are complete and runnable. No TBD, TODO, or "similar to above" references.
