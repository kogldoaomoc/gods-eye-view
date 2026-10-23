import pytest

from casefile import adapters
from casefile.adapters.base import AdapterError
from casefile.adapters.maigret import MaigretAdapter
from casefile.adapters.phoneinfoga import PhoneInfogaAdapter
from casefile.adapters.sherlock import SherlockAdapter
from casefile.adapters.spiderfoot import SpiderFootAdapter
from casefile.adapters.theharvester import TheHarvesterAdapter


def _by_type(result, entity_type):
    return [e for e in result.entities if e["type"] == entity_type]


def test_registry_default_routing():
    assert adapters.default_tools("username") == ["maigret", "sherlock"]
    assert adapters.default_tools("email") == ["theharvester"]
    assert adapters.default_tools("domain") == ["theharvester", "spiderfoot"]
    assert adapters.default_tools("person") == []
    assert adapters.default_tools("organization") == []
    assert "organization" not in SpiderFootAdapter.accepts
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


def test_theharvester_v5_report_shape():
    # Trimmed from a real theHarvester 5.0.0 run against example.com.
    native = {
        "cmd": "-d example.com -b crtsh,certspotter,hackertarget,rapiddns,otx,duckduckgo -f harvest",
        "hosts": ["0.example.com", "09bc4233abde.example.com", "103-213-249-189.example.com"],
        "ips": ["103.119.109.221", "103.136.70.104"],
        "shodan": [],
    }
    result = TheHarvesterAdapter().normalize(native, "example.com", "domain")
    assert len(_by_type(result, "host")) == 3
    assert len(_by_type(result, "ip")) == 2
    assert len(_by_type(result, "domain")) == 1


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


class _Process:
    def __init__(self, stdout="[]"):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


class _Ctx:
    def __init__(self, workdir=None):
        self.env = {}
        self.workdir = workdir
        self.args = None

    def run_process(self, args):
        self.args = list(args)
        return _Process()


def test_spiderfoot_refuses_a_target_its_cli_would_reclassify(monkeypatch):
    adapter = SpiderFootAdapter()
    monkeypatch.setattr(adapter, "binary", lambda env: "sf.py")
    ctx = _Ctx()
    assert adapter.run("Example.COM", "domain", ctx) == []
    assert ctx.env["SPIDERFOOT_TARGET_TYPE"] == "INTERNET_NAME"
    assert ctx.args[1:3] == ["-s", "Example.COM"]

    for selector, selector_type in (
        ("victim@example.com", "domain"),
        ("Jane Doe", "domain"),
        ("Jane Doe", "organization"),
        ("victim_handle", "host"),
        ("+14155550199", "host"),
    ):
        blocked = _Ctx()
        with pytest.raises(AdapterError, match="target type"):
            adapter.run(selector, selector_type, blocked)
        assert blocked.args is None

    person = _Ctx()
    adapter.run("Jane Doe", "person", person)
    assert person.env["SPIDERFOOT_TARGET_TYPE"] == "HUMAN_NAME"
    assert person.args[1:3] == ["-s", "Jane Doe"]


def test_theharvester_domain_flag_is_a_hostname(monkeypatch, tmp_path):
    adapter = TheHarvesterAdapter()
    monkeypatch.setattr(adapter, "binary", lambda env: "theHarvester")

    def run_process(args):
        ctx.args = list(args)
        (ctx.workdir / "harvest.json").write_text("{}", encoding="utf-8")
        return _Process("{}")

    ctx = _Ctx(tmp_path)
    ctx.run_process = run_process
    assert adapter.run("victim@example.com", "email", ctx) == {}
    assert ctx.args[1:3] == ["-d", "example.com"]

    blocked = _Ctx(tmp_path)
    blocked.run_process = run_process
    with pytest.raises(AdapterError, match="hostname"):
        adapter.run("victim@example.com", "domain", blocked)
    assert blocked.args is None
