from unittest.mock import patch, MagicMock
import scrapers.threat_intel as ti


def _mock_text_resp(text):
    m = MagicMock()
    m.text = text
    m.raise_for_status.return_value = None
    return m


def _mock_json_resp(data):
    m = MagicMock()
    m.json.return_value = data
    m.raise_for_status.return_value = None
    return m


SAMPLE_FEED = """https://malicious1.example.com/login
https://phish2.example.com/bank
not-a-url
https://phish3.example.com/verify
"""

SAMPLE_APWG_HTML = """<html><body>
<h2>Phishing Trends</h2><p>Q1 2024 saw increased phishing activity.</p>
<h2>Reports</h2><p>Download our quarterly report here.</p>
</body></html>"""

SAMPLE_URLHAUS_CSV = """################################################################
# abuse.ch URLhaus Database Dump
################################################################
#
"3001","2026-04-29 10:00:00","https://evil.example.com/malware","online","2026-04-29 10:00:00","malware_download","Emotet","https://urlhaus.abuse.ch/url/3001/","reporter1"
"3002","2026-04-29 09:00:00","http://bad.example.org/payload","online","2026-04-29 09:00:00","malware_download","Mozi","https://urlhaus.abuse.ch/url/3002/","reporter2"
"""

SAMPLE_THREATFOX_JSON = {
    "1001": {
        "ioc_value": "malware.example.com",
        "ioc_type": "domain",
        "threat_type": "payload_delivery",
        "malware": "emotet",
        "malware_printable": "Emotet",
        "confidence_level": 90,
        "first_seen_utc": "2026-04-29 08:00:00",
    },
    "1002": {
        "ioc_value": "192.0.2.1",
        "ioc_type": "ip:port",
        "threat_type": "c2",
        "malware": "cobalt_strike",
        "malware_printable": "Cobalt Strike",
        "confidence_level": 100,
        "first_seen_utc": "2026-04-29 07:00:00",
    },
}

SAMPLE_FEODO_JSON = [
    {
        "ip_address": "1.2.3.4",
        "port": 8080,
        "status": "online",
        "malware": "Emotet",
        "country": "US",
        "first_seen": "2026-01-01",
        "last_online": "2026-04-29",
    },
    {
        "ip_address": "5.6.7.8",
        "port": 443,
        "status": "offline",
        "malware": "QakBot",
        "country": "DE",
        "first_seen": "2026-02-01",
        "last_online": "2026-04-28",
    },
]


def test_scrape_openphish_returns_correct_envelope():
    with patch("scrapers.threat_intel.fetch", return_value=_mock_text_resp(SAMPLE_FEED)):
        result = ti.scrape_openphish()
    assert result["name"] == "OpenPhish Community Feed"
    assert result["type"] == "live"
    assert "error" not in result


def test_scrape_openphish_filters_non_http_lines():
    with patch("scrapers.threat_intel.fetch", return_value=_mock_text_resp(SAMPLE_FEED)):
        result = ti.scrape_openphish()
    entries = result["data"]["entries"]
    assert all(e.startswith("http") for e in entries)
    assert "not-a-url" not in entries
    assert len(entries) == 3


def test_scrape_openphish_caps_entries_at_200():
    big_feed = "\n".join(f"https://phish{i}.example.com" for i in range(300))
    with patch("scrapers.threat_intel.fetch", return_value=_mock_text_resp(big_feed)):
        result = ti.scrape_openphish()
    assert len(result["data"]["entries"]) == 200
    assert result["data"]["total_count"] == 300


def test_scrape_openphish_returns_error_on_failure():
    with patch("scrapers.threat_intel.fetch", side_effect=Exception("timeout")):
        result = ti.scrape_openphish()
    assert "error" in result
    assert "timeout" in result["error"]


def test_scrape_apwg_returns_sections():
    with patch("scrapers.threat_intel.fetch", return_value=_mock_text_resp(SAMPLE_APWG_HTML)):
        result = ti.scrape_apwg()
    assert result["name"] == "APWG Resources"
    assert result["type"] == "static"
    assert len(result["data"]["sections"]) == 2
    assert result["data"]["sections"][0]["title"] == "Phishing Trends"


def test_scrape_apwg_returns_error_on_failure():
    with patch("scrapers.threat_intel.fetch", side_effect=Exception("404")):
        result = ti.scrape_apwg()
    assert "error" in result


def test_scrape_urlhaus_returns_entries():
    with patch("scrapers.threat_intel.fetch", return_value=_mock_text_resp(SAMPLE_URLHAUS_CSV)):
        result = ti.scrape_urlhaus()
    assert result["name"] == "URLhaus Malware URL Feed"
    assert result["type"] == "live"
    assert "error" not in result
    entries = result["data"]["entries"]
    assert len(entries) == 2
    assert entries[0]["url"] == "https://evil.example.com/malware"
    assert entries[0]["threat"] == "malware_download"


def test_scrape_urlhaus_caps_at_300():
    rows = "\n".join(
        f'"3{i}","2026-04-29","https://evil{i}.example.com","online","2026-04-29","malware_download","tag","https://urlhaus.abuse.ch/url/{i}/","rep"'
        for i in range(400)
    )
    with patch("scrapers.threat_intel.fetch", return_value=_mock_text_resp(rows)):
        result = ti.scrape_urlhaus()
    assert len(result["data"]["entries"]) == 300


def test_scrape_urlhaus_returns_error_on_failure():
    with patch("scrapers.threat_intel.fetch", side_effect=Exception("connect error")):
        result = ti.scrape_urlhaus()
    assert "error" in result


def test_scrape_threatfox_returns_entries():
    with patch("scrapers.threat_intel.fetch", return_value=_mock_json_resp(SAMPLE_THREATFOX_JSON)):
        result = ti.scrape_threatfox()
    assert result["name"] == "ThreatFox IOC Feed"
    assert result["type"] == "live"
    assert "error" not in result
    entries = result["data"]["entries"]
    assert len(entries) == 2
    malwares = [e["malware"] for e in entries]
    assert "Emotet" in malwares


def test_scrape_threatfox_returns_error_on_failure():
    with patch("scrapers.threat_intel.fetch", side_effect=Exception("timeout")):
        result = ti.scrape_threatfox()
    assert "error" in result


def test_scrape_feodo_returns_entries():
    with patch("scrapers.threat_intel.fetch", return_value=_mock_json_resp(SAMPLE_FEODO_JSON)):
        result = ti.scrape_feodo()
    assert result["name"] == "Feodo Tracker C2 Botnet IPs"
    assert result["type"] == "live"
    assert "error" not in result
    entries = result["data"]["entries"]
    assert len(entries) == 2
    assert entries[0]["ip_address"] == "1.2.3.4"
    assert entries[0]["malware"] == "Emotet"


def test_scrape_feodo_caps_at_300():
    big = [{"ip_address": f"1.2.3.{i}", "port": 80, "status": "online", "malware": "X", "country": "US", "first_seen": "", "last_online": ""} for i in range(400)]
    with patch("scrapers.threat_intel.fetch", return_value=_mock_json_resp(big)):
        result = ti.scrape_feodo()
    assert len(result["data"]["entries"]) == 300
    assert result["data"]["total_count"] == 400


def test_scrape_feodo_returns_error_on_failure():
    with patch("scrapers.threat_intel.fetch", side_effect=Exception("DNS")):
        result = ti.scrape_feodo()
    assert "error" in result


def test_scrape_returns_five_sources():
    responses = [
        _mock_text_resp(SAMPLE_FEED),
        _mock_text_resp(SAMPLE_APWG_HTML),
        _mock_text_resp(SAMPLE_URLHAUS_CSV),
        _mock_json_resp(SAMPLE_THREATFOX_JSON),
        _mock_json_resp(SAMPLE_FEODO_JSON),
    ]
    with patch("scrapers.threat_intel.fetch", side_effect=responses):
        result = ti.scrape()
    assert result["category"] == "threat_intel"
    assert len(result["sources"]) == 5
