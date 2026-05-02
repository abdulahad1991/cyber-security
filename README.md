# Cyber Security Intelligence

Automated threat intelligence and vulnerability data aggregator. Scrapes, validates, and publishes structured security data across multiple domains.

## Data Coverage

| Domain | File |
|--------|------|
| Threat Intelligence | `data/threat_intel.json` |
| Vulnerabilities | `data/vulnerabilities.json` |
| AI Security | `data/ai_security.json` |
| Privacy | `data/privacy.json` |
| Risk & Compliance | `data/risk_compliance.json` |
| Security Testing | `data/security_testing.json` |

## How It Works

- **Live scrape** — runs every 6 hours, commits fresh data to `dev`
- **Static scrape** — runs every Sunday, updates reference datasets on `dev`
- **Promote** — on every push to `dev`, validates data and auto-merges to `main` if checks pass; opens a PR for manual review if they fail

## Local Setup

```bash
pip install -r requirements.txt
python3 runner.py --mode live
python3 runner.py --mode static
python3 validate.py
```

## Branches

- `main` — stable, validated data
- `dev` — active scraping target, promoted to main on success
