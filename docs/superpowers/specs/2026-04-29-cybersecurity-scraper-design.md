# Cybersecurity Data Scraper — Design Spec
**Date:** 2026-04-29  
**Repo:** https://github.com/abdulahad1991/cyber-security  
**Pages URL:** https://abdulahad1991.github.io/cyber-security/data/

---

## Overview

A Python-based web scraper that gathers cybersecurity reference content and live threat data from ~30 authoritative sources, producing JSON files served via GitHub Pages. The XennTool Cybersecurity & Risk section consumes these JSON files to power its 40+ tools across 7 categories.

---

## Repository Structure

```
cyber-security/
├── scrapers/
│   ├── __init__.py
│   ├── base.py               # shared fetch/retry/clean helpers
│   ├── risk_compliance.py    # NIST, PCI DSS, ISO 27001, CIS
│   ├── security_testing.py   # SSL Labs docs, SecurityHeaders, HSTS
│   ├── privacy.py            # GDPR, ICO, CCPA, Enforcement Tracker
│   ├── threat_intel.py       # PhishTank, OpenPhish, APWG
│   ├── ai_security.py        # OWASP LLM Top 10, MITRE ATLAS, NIST AI
│   └── vulnerabilities.py    # MITRE CVE, CISA KEV, HaveIBeenPwned
├── runner.py                 # orchestrates all scrapers, writes JSON
├── validate.py               # data quality checks before promotion
├── data/                     # scraper output — published via gh-pages
│   ├── risk_compliance.json
│   ├── security_testing.json
│   ├── privacy.json
│   ├── threat_intel.json
│   ├── ai_security.json
│   ├── vulnerabilities.json
│   └── manifest.json         # last_updated timestamps + source counts
├── .github/
│   └── workflows/
│       ├── scrape_live.yml   # every 6h → dev branch
│       ├── scrape_static.yml # weekly Sunday 02:00 UTC → dev branch
│       └── promote.yml       # validate → PR → auto-merge → gh-pages
├── requirements.txt
└── docs/superpowers/specs/
```

---

## Data Format

Every JSON file follows a consistent envelope:

```json
{
  "category": "threat_intel",
  "last_updated": "2026-04-29T06:00:00Z",
  "sources": [
    {
      "name": "PhishTank",
      "url": "https://www.phishtank.com/developer_info.php",
      "type": "live",
      "data": {
        "description": "Community-verified phishing URL database",
        "entries": [...],
        "total_count": 12453,
        "last_fetch": "2026-04-29T06:00:00Z"
      }
    }
  ]
}
```

`manifest.json` contains a summary of all categories with timestamps and entry counts so XennTool can display "last updated" badges without fetching each file.

---

## Scraper Modules

| Module | Type | Sources | Method |
|---|---|---|---|
| `risk_compliance.py` | static | NIST SP 800-30, PCI DSS doc library, ISO 27001, CIS Benchmarks | HTML parse — headings, summaries, control lists |
| `security_testing.py` | static | SSL Labs API docs, SecurityHeaders.com, HSTS Preload | Markdown/HTML parse — grading criteria, header rules |
| `privacy.py` | static | GDPR-info.eu, ICO DPIA guide, CCPA text, Enforcement Tracker | HTML parse — article text, fine records |
| `threat_intel.py` | live | PhishTank JSON feed, OpenPhish text feed, APWG resources | Direct feed fetch — structured data |
| `ai_security.py` | static | OWASP LLM Top 10, MITRE ATLAS, NIST AI 100-1 | HTML parse — risk names, descriptions, mitigations |
| `vulnerabilities.py` | live | CISA KEV catalog (JSON), MITRE CVE downloads | Direct JSON/CSV fetch — structured entries |

### base.py responsibilities
- Rate-limited `fetch(url, retries=3, delay=1.5)` with exponential backoff
- HTML-to-clean-text via BeautifulSoup
- `write_json(category, data)` — saves to `data/` directory
- Per-source error catching — a failed source returns an error object, does not raise

---

## runner.py

Accepts `--mode live` or `--mode static` (or `--mode all`).

- Imports and runs the relevant scraper modules
- Aggregates results into per-category JSON files
- Writes `manifest.json` with timestamps
- Exits 0 even if individual sources fail (errors are embedded in output)
- Prints a summary: sources scraped, sources failed, total entries written

---

## GitHub Actions Workflows

### scrape_live.yml
- **Trigger:** `cron: '0 */6 * * *'` (every 6 hours) + `workflow_dispatch`
- **Branch:** runs on `main`, commits data to `dev`
- **Runs:** `runner.py --mode live`
- **Targets:** `threat_intel`, `vulnerabilities`

### scrape_static.yml
- **Trigger:** `cron: '0 2 * * 0'` (weekly, Sunday 02:00 UTC) + `workflow_dispatch`
- **Branch:** runs on `main`, commits data to `dev`
- **Runs:** `runner.py --mode static`
- **Targets:** `risk_compliance`, `security_testing`, `privacy`, `ai_security`

### promote.yml
- **Trigger:** push to `dev` branch
- **Steps:**
  1. Run `validate.py` — checks listed below
  2. If validation passes: open PR from `dev` → `main`, auto-merge
  3. Merge to `main` triggers GitHub Pages deployment from `main`
  4. If validation fails: PR stays open, workflow posts failure summary as PR comment

---

## validate.py

Checks run before promotion to main:

1. All 6 expected JSON files exist in `data/` and are non-empty
2. Each file has required envelope keys: `category`, `last_updated`, `sources`
3. Live feed minimums: `threat_intel` entries > 50, `vulnerabilities` entries > 100
4. No source entry contains only an error object (all-failure detection)
5. `manifest.json` exists and has an `updated_at` timestamp within the last 7 hours (for live runs)

Exits 0 on pass, 1 on fail. Output is a structured JSON summary that the workflow posts as a PR comment.

---

## GitHub Pages Configuration

- Pages served from `main` branch root
- `data/` directory is publicly accessible at `https://abdulahad1991.github.io/cyber-security/data/`
- CORS is open by default on GitHub Pages (no config needed)
- XennTool fetches: `fetch("https://abdulahad1991.github.io/cyber-security/data/{category}.json")`

---

## Dependencies (requirements.txt)

```
requests>=2.31
beautifulsoup4>=4.12
lxml>=5.0
```

No heavy frameworks. Python 3.10+ standard library handles JSON, CSV, argparse.

---

## Error Handling Philosophy

- Individual source failures are logged and embedded in output — they do not stop other scrapers
- A scrape run that produces partial data is better than no data
- Validation gate on `dev → main` ensures broken data never reaches GitHub Pages
- Stale data (from a previous successful run) remains live until new valid data replaces it

---

## Out of Scope

- A frontend UI (XennTool UI lives in a separate repo)
- Authentication/API keys for sources (all targeted sources have public endpoints)
- JavaScript-rendered pages (all targeted sources serve static HTML or structured feeds)
- HaveIBeenPwned API (requires API key — excluded for now, can be added later with secret)
