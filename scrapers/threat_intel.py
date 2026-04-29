import csv
import io
from datetime import datetime, timezone

from scrapers.base import fetch, extract_sections, html_to_text

OPENPHISH_URL = "https://openphish.com/feed.txt"
APWG_URL = "https://apwg.org/resources/"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


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


def scrape_urlhaus() -> dict:
    try:
        resp = fetch(URLHAUS_URL)
        lines = [ln for ln in resp.text.splitlines() if not ln.startswith("#") and ln.strip()]
        reader = csv.DictReader(
            io.StringIO("\n".join(lines)),
            fieldnames=["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"],
        )
        entries = []
        for row in reader:
            entries.append({
                "id": row["id"].strip('"'),
                "dateadded": row["dateadded"].strip('"'),
                "url": row["url"].strip('"'),
                "url_status": row["url_status"].strip('"'),
                "threat": row["threat"].strip('"'),
                "tags": row["tags"].strip('"'),
            })
            if len(entries) >= 300:
                break
        return {
            "name": "URLhaus Malware URL Feed",
            "url": URLHAUS_URL,
            "type": "live",
            "data": {
                "description": "abuse.ch URLhaus feed of recently reported malware distribution URLs",
                "entries": entries,
                "total_count": len(entries),
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {"name": "URLhaus Malware URL Feed", "url": URLHAUS_URL, "type": "live", "error": str(e)}


def scrape_threatfox() -> dict:
    try:
        resp = fetch(THREATFOX_URL)
        raw = resp.json()
        entries = []
        for ioc_id, item in raw.items():
            if not isinstance(item, dict):
                continue
            entries.append({
                "id": ioc_id,
                "ioc_value": item.get("ioc_value", ""),
                "ioc_type": item.get("ioc_type", ""),
                "threat_type": item.get("threat_type", ""),
                "malware": item.get("malware_printable") or item.get("malware", ""),
                "confidence_level": item.get("confidence_level"),
                "first_seen": item.get("first_seen_utc", ""),
            })
            if len(entries) >= 200:
                break
        return {
            "name": "ThreatFox IOC Feed",
            "url": THREATFOX_URL,
            "type": "live",
            "data": {
                "description": "abuse.ch ThreatFox recent indicators of compromise (domains, IPs, URLs, hashes)",
                "entries": entries,
                "total_count": len(entries),
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {"name": "ThreatFox IOC Feed", "url": THREATFOX_URL, "type": "live", "error": str(e)}


def scrape_feodo() -> dict:
    try:
        resp = fetch(FEODO_URL)
        raw = resp.json()
        entries = [
            {
                "ip_address": item.get("ip_address", ""),
                "port": item.get("port"),
                "status": item.get("status", ""),
                "malware": item.get("malware", ""),
                "country": item.get("country", ""),
                "first_seen": item.get("first_seen", ""),
                "last_online": item.get("last_online", ""),
            }
            for item in raw
            if isinstance(item, dict)
        ]
        return {
            "name": "Feodo Tracker C2 Botnet IPs",
            "url": FEODO_URL,
            "type": "live",
            "data": {
                "description": "abuse.ch Feodo Tracker list of active C2 botnet infrastructure IP addresses",
                "entries": entries[:300],
                "total_count": len(entries),
                "last_fetch": datetime.now(timezone.utc).isoformat(),
            },
        }
    except Exception as e:
        return {"name": "Feodo Tracker C2 Botnet IPs", "url": FEODO_URL, "type": "live", "error": str(e)}


def scrape() -> dict:
    return {
        "category": "threat_intel",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "sources": [
            scrape_openphish(),
            scrape_apwg(),
            scrape_urlhaus(),
            scrape_threatfox(),
            scrape_feodo(),
        ],
    }
