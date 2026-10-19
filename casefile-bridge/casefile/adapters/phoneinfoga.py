"""PhoneInfoga adapter.

Validates and describes a phone number: country, carrier and line type. A phone
number only ever yields a country (and sometimes a region), never a street pin,
so the number resolves to a country outline on the globe.

PhoneInfoga's CLI prints a text report; the relevant lines are parsed for the
country. For a plausible E.164 the schema geocoder's ``libphonenumber`` path
supplies the country as a fallback.
"""

from __future__ import annotations

import re

from .base import Adapter, AdapterError, Result

_COUNTRY_RE = re.compile(r"(?i)country[^:]*:\s*(.+)")
_CARRIER_RE = re.compile(r"(?i)carrier[^:]*:\s*(.+)")


class PhoneInfogaAdapter(Adapter):
    name = "phoneinfoga"
    title = "PhoneInfoga"
    accepts = ("phone",)
    binaries = ("phoneinfoga",)
    binary_env = "CASEFILE_PHONEINFOGA_BIN"
    homepage = "https://github.com/sundowndev/phoneinfoga"
    licence = "GPL-3.0"
    timeout_s = 300
    confidence = 0.55

    def run(self, selector, selector_type, ctx):
        binary = self.binary(ctx.env)
        if not binary:
            raise AdapterError("PhoneInfoga is not installed")
        completed = ctx.run_process([binary, "scan", "-n", selector])
        if not completed.stdout.strip() and completed.returncode != 0:
            raise AdapterError(completed.stderr.strip()[:300] or "PhoneInfoga failed")
        return completed.stdout

    def normalize(self, native, selector, selector_type):
        result = Result()
        text = str(native)
        attrs = {}
        carrier = _CARRIER_RE.search(text)
        if carrier:
            attrs["carrier"] = carrier.group(1).strip()
        country_text = ""
        country = _COUNTRY_RE.search(text)
        if country:
            country_text = country.group(1).strip()
            attrs["country"] = country_text
        geo = None
        code = _country_code(country_text)
        if code:
            geo = {"precision": "country", "country": code, "method": "phoneinfoga"}
        result.add("phone", selector, geo=geo, attrs=attrs or None)
        return result


# A small name->ISO map; libphonenumber (via the geo resolver) is the primary
# source of a phone's country, this only reads PhoneInfoga's own text.
_COUNTRY_CODES = {
    "united states": "US",
    "united kingdom": "GB",
    "canada": "CA",
    "australia": "AU",
    "france": "FR",
    "germany": "DE",
    "india": "IN",
    "spain": "ES",
    "italy": "IT",
    "netherlands": "NL",
    "brazil": "BR",
    "mexico": "MX",
    "japan": "JP",
}


def _country_code(text: str) -> str | None:
    value = re.sub(r"\(.*?\)", "", text).strip().lower()
    if len(value) == 2 and value.isalpha():
        return value.upper()
    return _COUNTRY_CODES.get(value)
