from unittest.mock import patch, MagicMock
import scrapers.vulnerabilities as vuln


SAMPLE_KEV = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-20353",
            "vendorProject": "Cisco",
            "product": "ASA and FTD",
            "vulnerabilityName": "Cisco ASA DoS Vulnerability",
            "dateAdded": "2024-04-24",
            "shortDescription": "A vulnerability in Cisco ASA software.",
            "dueDate": "2024-05-01",
        }
    ]
}


def _mock_json_resp(data):
    m = MagicMock()
    m.json.return_value = data
    m.raise_for_status.return_value = None
    return m


def test_scrape_cisa_kev_returns_correct_envelope():
    with patch("scrapers.vulnerabilities.fetch", return_value=_mock_json_resp(SAMPLE_KEV)):
        result = vuln.scrape_cisa_kev()
    assert result["name"] == "CISA Known Exploited Vulnerabilities"
    assert result["type"] == "live"
    assert "error" not in result


def test_scrape_cisa_kev_maps_fields_correctly():
    with patch("scrapers.vulnerabilities.fetch", return_value=_mock_json_resp(SAMPLE_KEV)):
        result = vuln.scrape_cisa_kev()
    entry = result["data"]["entries"][0]
    assert entry["cve_id"] == "CVE-2024-20353"
    assert entry["vendor"] == "Cisco"
    assert entry["product"] == "ASA and FTD"
    assert entry["description"] == "A vulnerability in Cisco ASA software."


def test_scrape_cisa_kev_returns_error_on_fetch_failure():
    with patch("scrapers.vulnerabilities.fetch", side_effect=Exception("network error")):
        result = vuln.scrape_cisa_kev()
    assert "error" in result
    assert "network error" in result["error"]


def test_scrape_cisa_kev_caps_entries_at_500():
    many = [
        {"cveID": f"CVE-2024-{i:05d}", "vendorProject": "Vendor", "product": "P",
         "vulnerabilityName": "V", "dateAdded": "2024-01-01",
         "shortDescription": "D", "dueDate": "2024-02-01"}
        for i in range(600)
    ]
    with patch("scrapers.vulnerabilities.fetch", return_value=_mock_json_resp({"vulnerabilities": many})):
        result = vuln.scrape_cisa_kev()
    assert len(result["data"]["entries"]) == 500
    assert result["data"]["total_count"] == 600


def test_scrape_returns_category_envelope():
    with patch("scrapers.vulnerabilities.fetch", return_value=_mock_json_resp(SAMPLE_KEV)):
        result = vuln.scrape()
    assert result["category"] == "vulnerabilities"
    assert "last_updated" in result
    assert len(result["sources"]) == 1
