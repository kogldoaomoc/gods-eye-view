"""theHarvester adapter.

Runs ``theHarvester -d DOMAIN -b SOURCES -f OUT`` and reads ``OUT.json``. Its
keys are ``emails``, ``hosts`` (``name`` or ``name:ip``), ``ips``, ``asns``,
``urls``, ``people``, ``linkedin_people``, ``twitter_people`` and ``shodan``.
"""

from __future__ import annotations

import json

from .base import Adapter, AdapterError, Result

# Sources that work without API keys. Override with CASEFILE_THEHARVESTER_SOURCES.
DEFAULT_SOURCES = "crtsh,certspotter,hackertarget,rapiddns,otx,duckduckgo"


class TheHarvesterAdapter(Adapter):
    name = "theharvester"
    title = "theHarvester"
    accepts = ("domain", "email")
    binaries = ("theHarvester", "theharvester")
    binary_env = "CASEFILE_THEHARVESTER_BIN"
    homepage = "https://github.com/laramies/theHarvester"
    licence = "GPL-2.0"
    timeout_s = 900
    confidence = 0.55

    def run(self, selector, selector_type, ctx):
        binary = self.binary(ctx.env)
        if not binary:
            raise AdapterError("theHarvester is not installed")
        domain = selector.rsplit("@", 1)[-1] if selector_type == "email" else selector
        sources = ctx.env.get("CASEFILE_THEHARVESTER_SOURCES", DEFAULT_SOURCES)
        completed = ctx.run_process([binary, "-d", domain, "-b", sources, "-f", "harvest"])
        report = ctx.workdir / "harvest.json"
        if not report.exists():
            raise AdapterError(completed.stderr.strip()[:300] or "theHarvester wrote no report")
        try:
            return json.loads(report.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise AdapterError(f"could not read theHarvester report: {error}") from None

    def normalize(self, native, selector, selector_type):
        result = Result()
        domain_value = selector.rsplit("@", 1)[-1] if selector_type == "email" else selector
        domain = result.add("domain", domain_value)
        data = native if isinstance(native, dict) else {}

        for email in _as_list(data.get("emails")):
            result.link(domain, result.add("email", email), "registered_with")
        for host in _as_list(data.get("hosts")):
            name, _, ip = str(host).partition(":")
            host_entity = result.add("host", name)
            result.link(domain, host_entity, "owns")
            if ip:
                result.link(host_entity, result.add("ip", ip), "resolves_to")
        for ip in _as_list(data.get("ips")):
            result.link(domain, result.add("ip", ip), "resolves_to")
        for asn in _as_list(data.get("asns")):
            result.link(domain, result.add("organization", str(asn), label=str(asn)), "member_of")
        for person in _as_list(data.get("people")) + _as_list(data.get("linkedin_people")):
            result.link(domain, result.add("person", _person_name(person)), "member_of")

        for host in _as_list(data.get("shodan")):
            _apply_shodan(result, domain, host)
        return result


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _person_name(person) -> str:
    if isinstance(person, dict):
        return str(person.get("name") or person.get("fullName") or person).strip()
    return str(person).strip()


def _apply_shodan(result: Result, domain, host):
    # theHarvester's ``shodan`` rows are ``{"value": ip, "details": {...}}``.
    if not isinstance(host, dict):
        return
    details = host.get("details") or {}
    ip_value = host.get("value") or details.get("ip_str")
    if not ip_value:
        return
    geo = None
    lat, lon = details.get("latitude"), details.get("longitude")
    if lat is not None and lon is not None:
        geo = {"lat": lat, "lon": lon, "precision": "city", "method": "shodan", "country": details.get("country_code")}
    result.link(domain, result.add("ip", str(ip_value), geo=geo), "resolves_to")
