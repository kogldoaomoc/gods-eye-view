from casefile import adapters
from casefile.adapters.maigret import MaigretAdapter
from casefile.adapters.phoneinfoga import PhoneInfogaAdapter
from casefile.adapters.sherlock import SherlockAdapter
from casefile.adapters.spiderfoot import SpiderFootAdapter
from casefile.adapters.theharvester import TheHarvesterAdapter


def _by_type(result, entity_type):
    return [e for e in result.entities if e["type"] == entity_type]


def test_registry_default_routing():
    assert adapters.default_tools("username") == ["maigret", "sherlock"]
    assert adapters.default_tools("domain") == ["theharvester", "spiderfoot"]
    assert "spiderfoot" in adapters.tools_for("ip")


def test_spiderfoot_normalizes_events_and_coordinates():
    native = [
        {"type": "IP Address", "data": "203.0.113.7", "source": "example.com"},
        {"type": "Email Address", "data": "ceo@example.com", "source": "example.com"},
        {"type": "Physical Coordinates", "data": "52.37,4.89", "source": "203.0.113.7"},
        {"type": "Account on External Site", "data": "GitHub\n<SFURL>https://github.com/acme</SFURL>", "source": "example.com"},
    ]
    result = SpiderFootAdapter().normalize(native, "example.com", "domain")
    ips = _by_type(result, "ip")
    assert ips and ips[0]["value"] == "203.0.113.7"
    assert ips[0]["geo"]["lat"] == 52.37
    assert any(e["value"] == "https://github.com/acme" for e in _by_type(result, "account"))
    assert _by_type(result, "email")[0]["value"] == "ceo@example.com"


def test_theharvester_hosts_emails_and_shodan():
    native = {
        "emails": ["a@example.com", "b@example.com"],
        "hosts": ["www.example.com:203.0.113.7", "mail.example.com"],
        "ips": ["203.0.113.8"],
        "shodan": [{"value": "203.0.113.7", "details": {"latitude": 52.37, "longitude": 4.89, "country_code": "NL"}}],
    }
    result = TheHarvesterAdapter().normalize(native, "example.com", "domain")
    assert len(_by_type(result, "email")) == 2
    hosts = {e["value"] for e in _by_type(result, "host")}
    assert hosts == {"www.example.com", "mail.example.com"}
    geo_ips = [e for e in _by_type(result, "ip") if "geo" in e]
    assert geo_ips and geo_ips[0]["geo"]["country"] == "NL"


def test_sherlock_parses_found_lines():
    native = "[+] GitHub: https://github.com/jdoe\n[*] Checking...\n[+] Reddit: https://reddit.com/u/jdoe\n"
    result = SherlockAdapter().normalize(native, "jdoe", "username")
    accounts = _by_type(result, "account")
    assert {a["value"] for a in accounts} == {"https://github.com/jdoe", "https://reddit.com/u/jdoe"}
    assert all(link["relation"] == "same_as" for link in result.links)


def test_maigret_reads_simple_report():
    native = {
        "GitHub": {"status": "Claimed", "url_user": "https://github.com/jdoe", "ids": {"location": "Berlin"}},
        "Nope": {"status": "Available"},
    }
    result = MaigretAdapter().normalize(native, "jdoe", "username")
    assert len(_by_type(result, "account")) == 1
    assert _by_type(result, "address")[0]["value"] == "Berlin"


def test_phoneinfoga_sets_country_geo():
    native = "Number: +14155550100\nValid: true\nCountry: United States\nCarrier: Example Mobile\n"
    result = PhoneInfogaAdapter().normalize(native, "+14155550100", "phone")
    phone = result.entities[0]
    assert phone["type"] == "phone"
    assert phone["geo"]["country"] == "US"
    assert phone["geo"]["precision"] == "country"
