from casefile import schema
from casefile.store import CaseRegistry


def _obs(tool="spiderfoot", confidence=0.6):
    return schema.make_observation(tool, query="example.com", confidence=confidence)


def test_create_list_and_delete_case(tmp_path):
    registry = CaseRegistry(tmp_path)
    case = registry.create("Op Northwind")
    assert case["id"].startswith("case_")
    assert any(c["id"] == case["id"] for c in registry.list_cases())
    assert registry.delete(case["id"]) is True
    assert registry.list_cases() == []
    registry.close()


def test_ingest_merges_duplicate_entities(tmp_path):
    registry = CaseRegistry(tmp_path)
    case = registry.create("case")
    store = registry.store(case["id"])
    email = schema.make_entity("email", "a@example.com")
    store.ingest([email], [], _obs("spiderfoot"))
    store.ingest([email], [], _obs("theharvester"))
    entities = store.query_entities()
    assert len(entities) == 1
    full = store.get_entity(entities[0]["id"])
    assert {o["tool"] for o in full["observations"]} == {"spiderfoot", "theharvester"}
    registry.close()


def test_bbox_query_uses_rtree(tmp_path):
    registry = CaseRegistry(tmp_path)
    case = registry.create("case")
    store = registry.store(case["id"])
    amsterdam = schema.make_entity("ip", "203.0.113.7", geo={"lat": 52.37, "lon": 4.89, "precision": "city"})
    sydney = schema.make_entity("ip", "198.51.100.3", geo={"lat": -33.86, "lon": 151.2, "precision": "city"})
    store.ingest([amsterdam, sydney], [], _obs())
    in_europe = store.query_entities(bbox=(0.0, 45.0, 10.0, 55.0))
    assert [e["value"] for e in in_europe] == ["203.0.113.7"]
    registry.close()


def test_confidence_filter_and_hide(tmp_path):
    registry = CaseRegistry(tmp_path)
    case = registry.create("case")
    store = registry.store(case["id"])
    entity = schema.make_entity("domain", "example.com")
    store.ingest([entity], [], _obs(confidence=0.3))
    assert store.query_entities(min_confidence=0.5) == []
    assert len(store.query_entities(min_confidence=0.2)) == 1
    store.set_flag(entity["id"], hidden=True)
    assert store.query_entities() == []
    assert len(store.query_entities(include_hidden=True)) == 1
    registry.close()


def test_better_geo_replaces_coarser(tmp_path):
    registry = CaseRegistry(tmp_path)
    case = registry.create("case")
    store = registry.store(case["id"])
    coarse = schema.make_entity("ip", "203.0.113.7", geo={"lat": 52.0, "lon": 4.0, "precision": "country", "country": "NL"})
    fine = schema.make_entity("ip", "203.0.113.7", geo={"lat": 52.37, "lon": 4.89, "precision": "city"})
    store.ingest([coarse], [], _obs())
    store.ingest([fine], [], _obs())
    entity = store.get_entity(coarse["id"])
    assert entity["geo"]["precision"] == "city"
    registry.close()
