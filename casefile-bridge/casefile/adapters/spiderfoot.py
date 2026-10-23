"""SpiderFoot adapter.

Runs the SpiderFoot CLI with JSON output (``sf.py -s TARGET -o json -q -u ...``)
and maps its events to entities. SpiderFoot wraps many other sources, so it is
the broad-scan tool; the dedicated adapters answer single questions faster.
The entity hash removes duplicates between them.

In ``-o json`` output each event's ``type`` is the event's human description
("IP Address"), not its code ("IP_ADDRESS"); both are accepted.
"""

from __future__ import annotations

import json
import re

from .base import Adapter, AdapterError, Result

_USE_CASE = {"domain": "footprint", "host": "footprint"}

# (code, description, entity type, relation from the scan target).
_EVENTS = (
    ("EMAILADDR", "Email Address", "email", "mentions"),
    ("EMAILADDR_COMPROMISED", "Hacked Email Address", "email", "mentions"),
    ("DOMAIN_NAME", "Domain Name", "domain", "owns"),
    ("INTERNET_NAME", "Internet Name", "host", "resolves_to"),
    ("IP_ADDRESS", "IP Address", "ip", "resolves_to"),
    ("IPV6_ADDRESS", "IPv6 Address", "ip", "resolves_to"),
    ("USERNAME", "Username", "username", "mentions"),
    ("ACCOUNT_EXTERNAL_OWNED", "Account on External Site", "account", "owns"),
    ("SOCIAL_MEDIA", "Social Media Presence", "account", "owns"),
    ("HUMAN_NAME", "Human Name", "person", "mentions"),
    ("COMPANY_NAME", "Company Name", "organization", "member_of"),
    ("PHONE_NUMBER", "Phone Number", "phone", "registered_with"),
    ("PHONE_NUMBER_COMPROMISED", "Phone Number Compromised", "phone", "registered_with"),
    ("PHYSICAL_ADDRESS", "Physical Address", "address", "located_at"),
)
_EVENT_MAP: dict[str, tuple[str, str, str]] = {}
for _code, _label, _etype, _relation in _EVENTS:
    _EVENT_MAP[_code] = _EVENT_MAP[_label] = (_code, _etype, _relation)

_COORDINATES = {"PHYSICAL_COORDINATES", "Physical Coordinates"}
_GEOINFO = {"GEOINFO", "Physical Location"}
_SFURL_RE = re.compile(r"<SFURL>(.*?)</SFURL>", re.S)


def _clean(data: str) -> str:
    return _SFURL_RE.sub(r"\1", data).strip()


def _account_url(raw: str) -> str | None:
    match = _SFURL_RE.search(raw)
    if match:
        return match.group(1).strip()
    for token in raw.split():
        if token.startswith(("http://", "https://")):
            return token.strip()
    return None


# SpiderFoot event types. The CLI has no target-type flag; it guesses from
# the -s string (and quotes anything without a dot). These are the types we
# will allow that guess to return.
_TARGET_TYPES = {
    "domain": "INTERNET_NAME",
    "host": "INTERNET_NAME",
    "email": "EMAILADDR",
    "phone": "PHONE_NUMBER",
    "username": "USERNAME",
    "person": "HUMAN_NAME",
}
# Same order SpiderFootHelpers.targetTypeFromString uses. The CLI matches
# these case-insensitively.
_DETECTED_TYPES = (
    (re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$", re.IGNORECASE), "IP_ADDRESS"),
    (re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}/\d+$", re.IGNORECASE), "NETBLOCK_OWNER"),
    (re.compile(r"^.*@.*$", re.IGNORECASE), "EMAILADDR"),
    (re.compile(r"^\+[0-9]+$", re.IGNORECASE), "PHONE_NUMBER"),
    (re.compile(r"^\"[^\"\n]*\s[^\"\n]*\"$", re.IGNORECASE), "HUMAN_NAME"),
    (re.compile(r"^\".+\"$", re.IGNORECASE), "USERNAME"),
    (re.compile(r"^[0-9]+$", re.IGNORECASE), "BGP_AS_OWNER"),
    (re.compile(r"^[0-9a-f:]+$", re.IGNORECASE), "IPV6_ADDRESS"),
    (re.compile(r"^[0-9a-f:]+::/[0-9]+$", re.IGNORECASE), "NETBLOCKV6_OWNER"),
    (
        re.compile(
            r"^(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])(?:\.(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9]))+$",
            re.IGNORECASE,
        ),
        "INTERNET_NAME",
    ),
)


def spiderfoot_target_type(selector_type: str, selector: str) -> str | None:
    """The SpiderFoot event type for a selector we have already classified."""
    if selector_type == "ip":
        text = selector.strip()
        if ":" in text and "/" in text:
            return "NETBLOCKV6_OWNER"
        if "/" in text:
            return "NETBLOCK_OWNER"
        if ":" in text:
            return "IPV6_ADDRESS"
        return "IP_ADDRESS"
    return _TARGET_TYPES.get(selector_type)


def spiderfoot_detected_type(selector: str) -> str | None:
    """What ``sf.py`` would decide after its quoting step."""
    target = selector.strip()
    if " " in target:
        target = f'"{target}"'
    if "." not in target and not target.startswith("+") and '"' not in target:
        target = f'"{target}"'
    for pattern, name in _DETECTED_TYPES:
        if pattern.search(target):
            return name
    return None


class SpiderFootAdapter(Adapter):
    name = "spiderfoot"
    title = "SpiderFoot"
    accepts = ("domain", "email", "ip", "host", "username", "person", "phone")
    binaries = ("sf.py", "spiderfoot")
    binary_env = "CASEFILE_SPIDERFOOT_BIN"
    homepage = "https://github.com/smicallef/spiderfoot"
    licence = "MIT"
    timeout_s = 1800
    confidence = 0.6

    def run(self, selector, selector_type, ctx):
        binary = self.binary(ctx.env)
        if not binary:
            raise AdapterError("SpiderFoot is not installed")
        # sf.py classifies -s itself, and quotes a target with no dot into a
        # username or a human name. Only start it when that classification is
        # the type we already decided, and pass that type on the process.
        target_type = spiderfoot_target_type(selector_type, selector)
        if not target_type or spiderfoot_detected_type(selector) != target_type:
            raise AdapterError("SpiderFoot target type does not match the selector")
        ctx.env["SPIDERFOOT_TARGET_TYPE"] = target_type
        args = [binary, "-s", selector, "-o", "json", "-q", "-u", _USE_CASE.get(selector_type, "investigate")]
        completed = ctx.run_process(args)
        text = completed.stdout.strip()
        if not text:
            if completed.returncode != 0:
                raise AdapterError(completed.stderr.strip()[:300] or "SpiderFoot failed")
            return []
        try:
            return json.loads(text)
        except json.JSONDecodeError as error:
            raise AdapterError(f"could not parse SpiderFoot JSON: {error}") from None

    def normalize(self, native, selector, selector_type):
        result = Result()
        target = result.add(selector_type, selector)
        coords: dict[str, dict] = {}
        for event in native if isinstance(native, list) else []:
            etype = event.get("type")
            raw = event.get("data")
            if not isinstance(raw, str) or not raw.strip():
                continue
            data = _clean(raw)
            source = event.get("source")
            if etype in _COORDINATES:
                geo = _parse_coords(data)
                if geo and source:
                    coords[source] = geo
                continue
            if etype in _GEOINFO:
                address = result.add("address", data)
                result.link(_find(result, source), address, "located_at")
                continue
            mapping = _EVENT_MAP.get(etype)
            if not mapping:
                continue
            code, entity_type, relation = mapping
            attrs = {"flag": "compromised"} if code.endswith("_COMPROMISED") else None
            if entity_type == "account":
                url = _account_url(raw)
                entity = result.add("account", url or data, label=data.splitlines()[0].strip() or data, attrs=attrs)
            else:
                entity = result.add(entity_type, data, attrs=attrs)
            result.link(target, entity, relation)
        _attach_coords(result, coords, target)
        return result


def _parse_coords(data: str) -> dict | None:
    try:
        lat_text, lon_text = data.split(",", 1)
        return {"lat": float(lat_text), "lon": float(lon_text), "precision": "city", "method": "spiderfoot"}
    except (ValueError, TypeError):
        return None


def _find(result: Result, value):
    if not value:
        return None
    for entity in result.entities:
        if entity["value"] == value:
            return entity
    return None


def _attach_coords(result: Result, coords: dict[str, dict], target):
    if not coords:
        return
    for index, entity in enumerate(result.entities):
        if "geo" not in entity and entity["value"] in coords:
            result.entities[index] = {**entity, "geo": coords[entity["value"]]}
    if target is not None:
        for index, entity in enumerate(result.entities):
            if entity["id"] == target["id"] and "geo" not in entity:
                result.entities[index] = {**entity, "geo": next(iter(coords.values()))}
                break
