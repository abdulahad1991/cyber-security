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
