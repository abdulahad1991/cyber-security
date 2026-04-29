import yaml
from datetime import datetime, timezone

from scrapers.base import fetch, html_to_text, extract_sections

OWASP_LLM_URL = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
MITRE_ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
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


def scrape_mitre_atlas() -> dict:
    try:
        resp = fetch(MITRE_ATLAS_URL)
        data = yaml.safe_load(resp.text)
        matrices = data.get("matrices", [])
        tactics = []
        techniques = []
        for matrix in matrices:
            for tactic in matrix.get("tactics", []):
                tactics.append({
                    "id": tactic.get("id", ""),
                    "name": tactic.get("name", ""),
                    "description": (tactic.get("description") or "")[:500],
                })
            for technique in matrix.get("techniques", []):
                desc = technique.get("description") or ""
                techniques.append({
                    "id": technique.get("id", ""),
                    "name": technique.get("name", ""),
                    "description": desc[:500],
                    "tactics": technique.get("tactics", []),
                })
        return {
            "name": "MITRE ATLAS Matrix",
            "url": MITRE_ATLAS_URL,
            "type": "static",
            "data": {
                "description": "Adversarial Threat Landscape for AI Systems — tactics and techniques matrix",
                "tactics": tactics,
                "techniques": techniques[:100],
                "total_techniques": len(techniques),
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {"name": "MITRE ATLAS Matrix", "url": MITRE_ATLAS_URL, "type": "static", "error": str(e)}


def scrape() -> dict:
    return {
        "category": "ai_security",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "sources": [
            _scrape_source(
                "OWASP LLM Top 10", OWASP_LLM_URL,
                "OWASP Top 10 security risks for Large Language Model applications",
            ),
            scrape_mitre_atlas(),
            _scrape_source(
                "NIST AI Risk Management Framework", NIST_AI_URL,
                "NIST AI 100-1 framework for managing risks in AI systems",
            ),
        ],
    }
