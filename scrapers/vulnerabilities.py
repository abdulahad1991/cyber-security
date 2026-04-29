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
