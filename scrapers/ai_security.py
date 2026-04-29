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
