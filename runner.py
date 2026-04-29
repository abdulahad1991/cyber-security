import argparse
import importlib
import sys
from datetime import datetime, timezone

from scrapers.base import write_json

LIVE_MODULES = ["vulnerabilities", "threat_intel"]
STATIC_MODULES = ["risk_compliance", "security_testing", "privacy", "ai_security"]


def _import_scraper(name: str):
    return importlib.import_module(f"scrapers.{name}")


def run(mode: str) -> dict:
    if mode == "live":
        modules = LIVE_MODULES
    elif mode == "static":
        modules = STATIC_MODULES
    else:
        modules = LIVE_MODULES + STATIC_MODULES

    results = {"scraped": [], "failed": [], "total_entries": 0}
    manifest_categories = {}

    for name in modules:
        print(f"Scraping {name}...")
        try:
            mod = _import_scraper(name)
            data = mod.scrape()
            path = write_json(name, data)
            entry_count = sum(
                len(s.get("data", {}).get("entries", []))
                for s in data.get("sources", [])
                if "error" not in s
            )
            results["scraped"].append(name)
            results["total_entries"] += entry_count
            manifest_categories[name] = {
                "last_updated": data.get("last_updated"),
                "source_count": len(data.get("sources", [])),
                "entry_count": entry_count,
            }
            print(f"  ✓ {name}: {entry_count} entries → {path}")
        except Exception as e:
            results["failed"].append({"module": name, "error": str(e)})
            print(f"  ✗ {name}: {e}", file=sys.stderr)

    manifest = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "categories": manifest_categories,
    }
    write_json("manifest", manifest)

    print(
        f"\nDone: {len(results['scraped'])} scraped, "
        f"{len(results['failed'])} failed, "
        f"{results['total_entries']} total entries"
    )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="XennTool cybersecurity data scraper")
    parser.add_argument(
        "--mode", choices=["live", "static", "all"], default="all",
        help="Which scrapers to run (default: all)"
    )
    args = parser.parse_args()
    run(args.mode)


if __name__ == "__main__":
    main()
