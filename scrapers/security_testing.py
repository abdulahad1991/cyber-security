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
