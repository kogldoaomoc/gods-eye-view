from casefile import schema
from casefile.export import case_to_geojson
from casefile.store import CaseRegistry


def test_export_only_geographic_entities_with_provenance(tmp_path):
    registry = CaseRegistry(tmp_path)
    case = registry.create("case")
    store = registry.store(case["id"])
    located = schema.make_entity("ip", "203.0.113.7", geo={"lat": 52.37, "lon": 4.89, "precision": "city"})
    floating = schema.make_entity("email", "a@example.com")
    store.ingest([located, floating], [], schema.make_observation("spiderfoot", query="example.com", confidence=0.7))
    geojson = case_to_geojson(store)
    assert geojson["type"] == "FeatureCollection"
    assert len(geojson["features"]) == 1
    feature = geojson["features"][0]
    assert feature["geometry"]["coordinates"] == [4.89, 52.37]
    assert feature["properties"]["tools"] == "spiderfoot"
    assert feature["properties"]["precision"] == "city"
    assert "ownership" not in feature["properties"]
    registry.close()


def test_export_marks_cross_platform_hits_unverified(tmp_path):
    registry = CaseRegistry(tmp_path)
    case = registry.create("case")
    store = registry.store(case["id"])
    account = schema.make_entity(
        "account", "https://reddit.com/u/jdoe", geo={"lat": 52.37, "lon": 4.89, "precision": "city"}
    )
    store.ingest(
        [account],
        [],
        schema.make_observation("sherlock", query="jdoe", ownership="verified", at="2020-01-01T00:00:00Z"),
    )
    store.ingest(
        [account],
        [],
        schema.make_observation("maigret", query="jdoe", ownership="unverified", at="2020-01-01T00:00:01Z"),
    )
    feature = case_to_geojson(store)["features"][0]
    assert feature["properties"]["ownership"] == "unverified"
    registry.close()
