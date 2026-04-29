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
