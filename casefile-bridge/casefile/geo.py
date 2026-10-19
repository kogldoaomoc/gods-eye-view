"""Attach geography to entities that a tool reported without it.

Resolution order, first match wins:

1. Coordinates in the tool output (adapters set these directly).
2. An address or place string, geocoded through God's Eye View's own
   ``/api/geocode`` route, which serializes and caches Nominatim requests.
3. An IP: a local GeoLite2 database when ``CASEFILE_GEOLITE2_DB`` names one.
   Precision is never better than ``city``.
4. A phone: its country, and region where libphonenumber knows it.
5. Nothing. The entity stays off the map.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.parse
import urllib.request

from . import schema

GEOCODE_TIMEOUT_S = 15

# Nominatim-derived framing types (src/nominatimGeocode.js) to a precision.
_TYPE_PRECISION = (
    ("country", "country", None),
    ("administrative_area_level_1", "region", None),
    ("administrative_area_level_2", "region", 50_000),
    ("locality", "city", None),
    ("neighborhood", "city", 3_000),
    ("postal_code", "city", 3_000),
    ("route", "street", None),
)


def precision_from_types(types: list[str]) -> tuple[str, int | None]:
    for type_name, precision, radius in _TYPE_PRECISION:
        if type_name in types:
            return precision, radius
    return "address", None


class Geocoder:
    """Forward geocoding through a running God's Eye View server."""

    def __init__(self, base_url: str | None, *, opener=None):
        self.base_url = (base_url or "").rstrip("/")
        self._opener = opener or urllib.request.urlopen
        self._cache: dict[str, dict | None] = {}
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return bool(self.base_url)

    def geocode(self, query: str) -> dict | None:
        text = " ".join(query.split())
        if not self.available or not text or len(text) > 200:
            return None
        key = text.casefold()
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        url = f"{self.base_url}/api/geocode?{urllib.parse.urlencode({'q': text})}"
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with self._opener(request, timeout=GEOCODE_TIMEOUT_S) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError):
            # Not cached: a busy or offline geocoder is worth retrying later.
            return None
        geo = _geo_from_geocode_payload(payload)
        with self._lock:
            self._cache[key] = geo
        return geo


def _geo_from_geocode_payload(payload: dict) -> dict | None:
    results = payload.get("results") if isinstance(payload, dict) else None
    if not results:
        return None
    hit = results[0]
    location = (hit.get("geometry") or {}).get("location") or {}
    if location.get("lat") is None or location.get("lng") is None:
        return None
    precision, radius = precision_from_types(hit.get("types") or [])
    geo = {"lat": location["lat"], "lon": location["lng"], "precision": precision, "method": "gev-geocode"}
    if radius is not None:
        geo["radiusM"] = radius
    return geo


class GeoLite:
    """Optional IP geolocation from a local MaxMind GeoLite2-City database."""

    def __init__(self, db_path: str | None):
        self._reader = None
        if not db_path:
            return
        try:
            import geoip2.database  # type: ignore[import-not-found]

            self._reader = geoip2.database.Reader(db_path)
        except (ImportError, OSError, ValueError):
            self._reader = None

    @property
    def available(self) -> bool:
        return self._reader is not None

    def lookup(self, ip: str) -> dict | None:
        if not self._reader:
            return None
        try:
            city = self._reader.city(ip)
        except Exception:  # geoip2 raises AddressNotFoundError and ValueError
            return None
        location = city.location
        if location.latitude is None or location.longitude is None:
            return None
        radius_km = location.accuracy_radius or 50
        return {
            "lat": location.latitude,
            "lon": location.longitude,
            # GeoLite2 coordinates are a city-level estimate at best.
            "precision": "city",
            "radiusM": max(15_000, int(radius_km) * 1000),
            "country": city.country.iso_code,
            "method": "geolite2",
        }


def phone_geo(e164: str) -> dict | None:
    try:
        import phonenumbers  # type: ignore[import-not-found]
        from phonenumbers import geocoder as phone_geocoder  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        parsed = phonenumbers.parse(e164, None)
    except phonenumbers.NumberParseException:
        return None
    country = phonenumbers.region_code_for_number(parsed)
    if not country or country == "ZZ":
        return None
    geo = {"precision": "country", "country": country, "method": "libphonenumber"}
    description = phone_geocoder.description_for_number(parsed, "en")
    if description and description.casefold() not in {country.casefold()}:
        geo["region"] = description
    return geo


class GeoResolver:
    """Fill in ``geo`` for entities that have none."""

    def __init__(self, geocoder: Geocoder | None = None, geolite: GeoLite | None = None):
        self.geocoder = geocoder or Geocoder(os.environ.get("GEV_URL", "http://127.0.0.1:4173"))
        self.geolite = geolite or GeoLite(os.environ.get("CASEFILE_GEOLITE2_DB"))

    def resolve(self, entity: dict) -> dict:
        if entity.get("geo"):
            return entity
        geo = None
        if entity["type"] in ("address", "place"):
            geo = self.geocoder.geocode(entity["value"])
        elif entity["type"] == "ip":
            geo = self.geolite.lookup(entity["value"])
        elif entity["type"] == "phone":
            geo = phone_geo(entity["value"])
        if geo:
            try:
                normalized = schema.normalize_geo(geo)
            except schema.SchemaError:
                normalized = None
            if normalized:
                entity = {**entity, "geo": normalized}
        return entity
