import json
import os
import sys
from datetime import datetime, timezone, timedelta

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

REQUIRED_CATEGORIES = [
    "risk_compliance",
    "security_testing",
    "privacy",
    "threat_intel",
    "ai_security",
    "vulnerabilities",
]

LIVE_MINIMUMS = {
    "threat_intel": 200,
    "vulnerabilities": 100,
}


def _count_entries(data: dict) -> int:
    return sum(
        len(s.get("data", {}).get("entries", []))
        for s in data.get("sources", [])
        if "error" not in s
    )


def validate(data_dir: str = DATA_DIR) -> dict:
    errors: list[str] = []
    warnings: list[str] = []

    for cat in REQUIRED_CATEGORIES:
        path = os.path.join(data_dir, f"{cat}.json")
        if not os.path.exists(path):
            errors.append(f"Missing file: {cat}.json")
            continue
        if os.path.getsize(path) == 0:
            errors.append(f"Empty file: {cat}.json")
            continue

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON in {cat}.json: {e}")
            continue

        for key in ("category", "last_updated", "sources"):
            if key not in data:
                errors.append(f"{cat}.json missing required key: '{key}'")

        if cat in LIVE_MINIMUMS:
            count = _count_entries(data)
            minimum = LIVE_MINIMUMS[cat]
            if count < minimum:
                errors.append(
                    f"{cat}.json has {count} entries, minimum is {minimum}"
                )

        sources = data.get("sources", [])
        if sources and all("error" in s for s in sources):
            errors.append(f"{cat}.json: all sources failed (all have error keys)")

    manifest_path = os.path.join(data_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        warnings.append("manifest.json is missing")
    else:
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
            updated_at = datetime.fromisoformat(manifest["updated_at"])
            age = datetime.now(timezone.utc) - updated_at
            if age > timedelta(hours=7):
                hours = int(age.total_seconds() // 3600)
                warnings.append(f"manifest.json is {hours}h old (>7h threshold)")
        except (ValueError, KeyError, TypeError):
            warnings.append("manifest.json has an invalid or missing updated_at timestamp")

    passed = len(errors) == 0
    return {
        "passed": passed,
        "errors": errors,
        "warnings": warnings,
        "summary": f"{'PASS' if passed else 'FAIL'}: {len(errors)} errors, {len(warnings)} warnings",
    }


def main() -> None:
    result = validate()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
