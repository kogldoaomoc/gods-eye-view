"""Entity, observation and link schema shared by every adapter.

Every tool's output is normalized into these records before it is stored or
sent to God's Eye View. Entity IDs are derived from the entity's type and
normalized value, so the same email found by three tools is one entity.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone

ENTITY_TYPES = (
    "person",
    "username",
    "account",
    "email",
    "phone",
    "domain",
    "host",
    "ip",
    "organization",
    "address",
    "place",
    "breach",
    "image",
)

RELATIONS = (
    "registered_with",
    "resolves_to",
    "located_at",
    "same_as",
    "breached_in",
    "member_of",
    "hosts",
    "owns",
    "mentions",
)

# Ordered from most to least precise. Only the first two are drawn as pins.
PRECISIONS = ("exact", "address", "street", "city", "region", "country")
PIN_PRECISIONS = frozenset({"exact", "address"})

# Fallback uncertainty radius when a tool reports a precision but no radius.
DEFAULT_RADIUS_M = {
    "exact": 10,
    "address": 30,
    "street": 300,
    "city": 15_000,
    "region": 150_000,
    "country": None,
}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_WHITESPACE_RE = re.compile(r"\s+")


class SchemaError(ValueError):
    """A value cannot be normalized into the requested entity type."""


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_domain(value: str) -> str:
    text = value.strip().rstrip(".").lower()
    if text.startswith(("http://", "https://")):
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split(":", 1)[0]
    if not text or "." not in text:
        raise SchemaError(f"not a domain: {value!r}")
    try:
        ascii_text = text.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise SchemaError(f"not a domain: {value!r}") from error
    if not all(_DOMAIN_LABEL_RE.match(label) for label in ascii_text.split(".")):
        raise SchemaError(f"not a domain: {value!r}")
    return ascii_text


def _normalize_phone(value: str, region: str | None = None) -> str:
    try:
        import phonenumbers  # type: ignore[import-not-found]
    except ImportError:
        phonenumbers = None
    if phonenumbers is not None:
        try:
            parsed = phonenumbers.parse(value, region)
        except phonenumbers.NumberParseException as error:
            raise SchemaError(f"not a phone number: {value!r}") from error
        if not phonenumbers.is_possible_number(parsed):
            raise SchemaError(f"not a phone number: {value!r}")
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    text = value.strip()
    if text.startswith("00"):
        text = "+" + text[2:]
    digits = re.sub(r"\D", "", text)
    # Without libphonenumber a national number cannot be given a country code,
    # so only international input is accepted.
    if not text.startswith("+") or not 7 <= len(digits) <= 15:
        raise SchemaError(f"phone numbers need a +country prefix: {value!r}")
    return "+" + digits


def normalize_value(entity_type: str, value: str, *, region: str | None = None) -> str:
    """Return the canonical form of ``value`` for ``entity_type``."""
    if entity_type not in ENTITY_TYPES:
        raise SchemaError(f"unknown entity type: {entity_type!r}")
    if not isinstance(value, str):
        value = str(value)
    text = value.strip()
    if not text:
        raise SchemaError("empty value")
    if entity_type == "email":
        text = text.lower()
        if text.startswith("mailto:"):
            text = text[7:]
        if not _EMAIL_RE.match(text):
            raise SchemaError(f"not an email: {value!r}")
        local, domain = text.rsplit("@", 1)
        return f"{local}@{_normalize_domain(domain)}"
    if entity_type == "phone":
        return _normalize_phone(text, region)
    if entity_type in ("domain", "host"):
        return _normalize_domain(text)
    if entity_type == "ip":
        try:
            if "/" in text:
                return str(ipaddress.ip_network(text, strict=False))
            return str(ipaddress.ip_address(text))
        except ValueError as error:
            raise SchemaError(f"not an IP address: {value!r}") from error
    if entity_type == "username":
        return text.lstrip("@")
    return _WHITESPACE_RE.sub(" ", text)


def match_key(entity_type: str, normalized: str) -> str:
    """The part of a normalized value that decides identity.

    Usernames and accounts keep their case for display but match
    case-insensitively, as most platforms treat them.
    """
    if entity_type in ("username", "account", "person", "organization", "address", "place"):
        return normalized.casefold()
    return normalized


def entity_id(entity_type: str, normalized: str) -> str:
    digest = hashlib.sha256(f"{entity_type}\x1f{match_key(entity_type, normalized)}".encode()).hexdigest()
    return f"ent_{digest[:24]}"


def normalize_geo(geo: dict | None) -> dict | None:
    """Validate a geo block, filling the default radius for its precision."""
    if not geo:
        return None
    precision = geo.get("precision")
    if precision not in PRECISIONS:
        raise SchemaError(f"geo precision must be one of {PRECISIONS}: {precision!r}")
    result: dict = {"precision": precision, "method": str(geo.get("method") or "unknown")}
    lat, lon = geo.get("lat"), geo.get("lon")
    if lat is not None or lon is not None:
        try:
            lat, lon = float(lat), float(lon)
        except (TypeError, ValueError) as error:
            raise SchemaError("geo lat/lon must be numbers") from error
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise SchemaError(f"geo out of range: {lat}, {lon}")
        # Null Island is what broken geolocation reports, not a location.
        if lat == 0 and lon == 0:
            return None
        result["lat"], result["lon"] = round(lat, 6), round(lon, 6)
    country = geo.get("country")
    if country:
        result["country"] = str(country).upper()[:2]
    region = geo.get("region")
    if region:
        result["region"] = str(region)
    if "lat" not in result and "country" not in result:
        raise SchemaError("geo needs coordinates or a country")
    radius = geo.get("radiusM", DEFAULT_RADIUS_M[precision])
    if radius is not None:
        result["radiusM"] = max(0, int(radius))
    return result


def make_entity(
    entity_type: str,
    value: str,
    *,
    label: str | None = None,
    geo: dict | None = None,
    attrs: dict | None = None,
    region: str | None = None,
) -> dict:
    normalized = normalize_value(entity_type, value, region=region)
    entity = {
        "id": entity_id(entity_type, normalized),
        "type": entity_type,
        "value": normalized,
        "label": label or normalized,
    }
    geo_block = normalize_geo(geo)
    if geo_block:
        entity["geo"] = geo_block
    if attrs:
        entity["attrs"] = {key: val for key, val in attrs.items() if val not in (None, "", [], {})}
    return entity


def make_observation(
    tool: str,
    *,
    query: str,
    tool_version: str | None = None,
    confidence: float = 0.5,
    raw: str | None = None,
    at: str | None = None,
    ownership: str | None = None,
) -> dict:
    observation = {
        "tool": tool,
        "toolVersion": tool_version,
        "query": query,
        "at": at or now_iso(),
        "confidence": max(0.0, min(1.0, float(confidence))),
        "raw": raw,
    }
    if ownership:
        observation["ownership"] = ownership
    return observation


def make_link(source_id: str, target_id: str, relation: str) -> dict:
    if relation not in RELATIONS:
        raise SchemaError(f"unknown relation: {relation!r}")
    digest = hashlib.sha256(f"{source_id}\x1f{relation}\x1f{target_id}".encode()).hexdigest()
    return {"id": f"lnk_{digest[:24]}", "source": source_id, "target": target_id, "relation": relation}


_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,20}$")
_DOMAIN_RE = re.compile(r"^(?:https?://)?([a-z0-9-]+\.)+[a-z]{2,}(?:[/:].*)?$", re.I)
# A dotted hostname. SpiderFoot quotes any target with no dot and then
# classifies that quoted string as a username or a person's name.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
_ASN_RE = re.compile(r"^AS[0-9]{1,10}$", re.IGNORECASE)
_CERT_RE = re.compile(
    r"^(?:(?:sha1|sha256|sha384|sha512|md5):)?(?:[0-9a-f]{32,128}|(?:[0-9a-f]{2}:){15,63}[0-9a-f]{2})$",
    re.IGNORECASE,
)
INFRASTRUCTURE_TYPES = frozenset({"domain", "host", "ip", "asn", "cert"})


def validate_infrastructure(selector_type: str, value: str) -> str:
    """Accept an infrastructure selector only when it really is one.

    Domains and hosts must be dotted hostnames. IPs must parse. ASNs look
    like ``AS64500``. Certs are a hex hash or a colon-separated fingerprint.
    Quotes, spaces, ``@`` and a leading ``+`` are rejected for all of these.
    """
    if selector_type not in INFRASTRUCTURE_TYPES:
        raise SchemaError(f"not an infrastructure selector: {selector_type!r}")
    if not isinstance(value, str):
        raise SchemaError("selector is required")
    text = value.strip()
    if not text or text[0] == "+" or any(ch in text for ch in "\"'@ \t\r\n"):
        raise SchemaError("selector does not match its type")
    if selector_type in ("domain", "host"):
        if not _HOSTNAME_RE.match(text):
            raise SchemaError("domain and host selectors must be a hostname")
        return text
    if selector_type == "ip":
        try:
            if "/" in text:
                return str(ipaddress.ip_network(text, strict=False))
            return str(ipaddress.ip_address(text))
        except ValueError as error:
            raise SchemaError(f"not an IP address: {value!r}") from error
    if selector_type == "asn":
        if not _ASN_RE.match(text):
            raise SchemaError("ASN selectors must look like AS64500")
        return text.upper()
    if not _CERT_RE.match(text):
        raise SchemaError("cert selectors must be a fingerprint or hash")
    return text.lower()


def detect_selector(text: str) -> str:
    """Guess the entity type of pasted text. Mirrors ``src/sources/casefile.js``."""
    value = text.strip()
    if not value:
        raise SchemaError("empty selector")
    if _EMAIL_RE.match(value) or value.lower().startswith("mailto:"):
        return "email"
    if _IPV4_RE.match(value) or (":" in value and _is_ipv6(value)):
        return "ip"
    if value.startswith("@"):
        return "username"
    if _PHONE_RE.match(value) and sum(ch.isdigit() for ch in value) >= 7:
        return "phone"
    if _DOMAIN_RE.match(value) and " " not in value:
        return "domain"
    if " " in value:
        return "address" if any(ch.isdigit() for ch in value) else "person"
    return "username"


def _is_ipv6(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False
