import json
import os
import tempfile
from datetime import datetime, timezone, timedelta

import validate


def _write(d, filename, data):
    with open(os.path.join(d, filename), "w") as f:
        json.dump(data, f)


def _make_source(name, entries=None, error=None):
    s = {"name": name, "type": "live"}
    if error:
        s["error"] = error
    else:
        s["data"] = {"entries": entries or []}
    return s


def _write_full_valid_set(d, vulns=150, threat=250):
    cats = {
        "risk_compliance": {"category": "risk_compliance", "last_updated": "2026-01-01T00:00:00+00:00",
                             "sources": [_make_source("NIST")]},
        "security_testing": {"category": "security_testing", "last_updated": "2026-01-01T00:00:00+00:00",
                              "sources": [_make_source("SSL")]},
        "privacy": {"category": "privacy", "last_updated": "2026-01-01T00:00:00+00:00",
                    "sources": [_make_source("GDPR")]},
        "ai_security": {"category": "ai_security", "last_updated": "2026-01-01T00:00:00+00:00",
                        "sources": [_make_source("OWASP")]},
        "threat_intel": {"category": "threat_intel", "last_updated": "2026-01-01T00:00:00+00:00",
                         "sources": [_make_source("OpenPhish", entries=["url"] * threat)]},
        "vulnerabilities": {"category": "vulnerabilities", "last_updated": "2026-01-01T00:00:00+00:00",
                            "sources": [_make_source("CISA", entries=[{"cve_id": "CVE-001"}] * vulns)]},
    }
    for name, data in cats.items():
        _write(d, f"{name}.json", data)
    _write(d, "manifest.json", {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "categories": {},
    })


def test_passes_with_valid_complete_data():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        result = validate.validate(d)
    assert result["passed"] is True
    assert result["errors"] == []


def test_fails_when_required_file_missing():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        os.remove(os.path.join(d, "privacy.json"))
        result = validate.validate(d)
    assert result["passed"] is False
    assert any("privacy.json" in e for e in result["errors"])


def test_fails_when_envelope_key_missing():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        _write(d, "privacy.json", {"category": "privacy", "sources": []})
        result = validate.validate(d)
    assert result["passed"] is False
    assert any("last_updated" in e for e in result["errors"])


def test_fails_when_vulnerabilities_below_minimum():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d, vulns=50)
        result = validate.validate(d)
    assert result["passed"] is False
    assert any("vulnerabilities" in e and "minimum" in e for e in result["errors"])


def test_fails_when_threat_intel_below_minimum():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d, threat=10)
        result = validate.validate(d)
    assert result["passed"] is False
    assert any("threat_intel" in e and "minimum" in e for e in result["errors"])


def test_fails_when_all_sources_have_errors():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        _write(d, "threat_intel.json", {
            "category": "threat_intel",
            "last_updated": "2026-01-01T00:00:00+00:00",
            "sources": [
                _make_source("OpenPhish", error="timeout"),
                _make_source("APWG", error="404"),
            ],
        })
        result = validate.validate(d)
    assert result["passed"] is False
    assert any("all sources failed" in e for e in result["errors"])


def test_warns_when_manifest_is_stale():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        stale = (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat()
        _write(d, "manifest.json", {"updated_at": stale, "categories": {}})
        result = validate.validate(d)
    assert any("old" in w or ">7h" in w or "8h" in w for w in result["warnings"])


def test_summary_string_includes_pass_or_fail():
    with tempfile.TemporaryDirectory() as d:
        _write_full_valid_set(d)
        result = validate.validate(d)
    assert "PASS" in result["summary"] or "FAIL" in result["summary"]
