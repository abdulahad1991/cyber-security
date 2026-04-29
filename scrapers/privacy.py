from datetime import datetime, timezone

from scrapers.base import fetch, html_to_text, extract_sections_auto

GDPR_URL = "https://gdpr-info.eu/"
ICO_URL = "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/"
CCPA_URL = "https://oag.ca.gov/privacy/ccpa"
ENFORCEMENT_URL = "https://www.enforcementtracker.com/"


def _scrape_source(name: str, url: str, description: str) -> dict:
    try:
        resp = fetch(url)
        sections = extract_sections_auto(resp.text)
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
