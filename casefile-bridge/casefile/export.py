"""Export a case's geographic entities as GeoJSON.

The output drops straight into God's Eye View's file import
(``src/data/geoFileImport.js`` accepts ``.geojson``), so a case is usable on
the globe before any app change ships. Every feature carries its provenance:
the tools that found it, when, and a confidence, so a finding can be traced.
"""

from __future__ import annotations

from . import schema
from .store import CaseStore

# Entities whose precision is coarser than a point render as a circle or
# outline in the layer; the GeoJSON keeps the point plus a radius so a plain
# GeoJSON viewer still shows something, and the layer can upgrade it.
_ICONS = {
    "ip": "server",
    "host": "server",
    "domain": "globe",
    "email": "mail",
    "phone": "phone",
    "person": "person",
    "username": "at",
    "account": "at",
    "organization": "building",
    "address": "pin",
    "place": "pin",
    "image": "image",
}


def entity_to_feature(entity: dict) -> dict | None:
    geo = entity.get("geo")
    if not geo or "lat" not in geo:
        return None
    observations = entity.get("observations", [])
    tools = sorted({obs["tool"] for obs in observations})
    ownership = _ownership(observations)
    properties = {
        "id": entity["id"],
        "type": entity["type"],
        "label": entity["label"],
        "value": entity["value"],
        "confidence": entity.get("confidence"),
        "precision": geo.get("precision"),
        "radiusM": geo.get("radiusM"),
        "geoMethod": geo.get("method"),
        "tools": ", ".join(tools) if tools else None,
        "firstSeen": entity.get("firstSeen"),
        "lastSeen": entity.get("lastSeen"),
        "verified": entity.get("verified"),
        "ownership": ownership,
        "icon": _ICONS.get(entity["type"], "pin"),
    }
    return {
        "type": "Feature",
        "geometry": {"type": "Point", "coordinates": [geo["lon"], geo["lat"]]},
        "properties": {key: val for key, val in properties.items() if val is not None},
    }


def _ownership(observations: list[dict]) -> str | None:
    """Cross-platform hits stay unverified when any observation says so."""
    values = [obs.get("ownership") for obs in observations if obs.get("ownership")]
    if "unverified" in values:
        return "unverified"
    if "verified" in values:
        return "verified"
    return None


def case_to_geojson(store: CaseStore, *, include_hidden: bool = False, min_confidence: float = 0.0) -> dict:
    features = []
    for summary in store.query_entities(include_hidden=include_hidden, min_confidence=min_confidence, limit=10000):
        if not summary.get("geo"):
            continue
        entity = store.get_entity(summary["id"]) or summary
        feature = entity_to_feature(entity)
        if feature:
            features.append(feature)
    return {
        "type": "FeatureCollection",
        "generator": "casefile-bridge",
        "generatedAt": schema.now_iso(),
        "features": features,
    }
