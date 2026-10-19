from casefile import schema


def test_email_normalization_is_case_and_punycode_stable():
    a = schema.make_entity("email", "Alice@Example.COM")
    b = schema.make_entity("email", "alice@example.com")
    assert a["value"] == "alice@example.com"
    assert a["id"] == b["id"]


def test_same_username_different_case_is_one_entity():
    a = schema.make_entity("username", "@JohnDoe")
    b = schema.make_entity("username", "johndoe")
    assert a["value"] == "JohnDoe"  # display keeps case
    assert a["id"] == b["id"]  # identity ignores case


def test_ip_and_netblock_normalize():
    assert schema.make_entity("ip", "203.0.113.7")["value"] == "203.0.113.7"
    assert schema.make_entity("ip", "203.0.113.0/24")["value"] == "203.0.113.0/24"


def test_phone_requires_country_without_library():
    try:
        import phonenumbers  # noqa: F401

        has_lib = True
    except ImportError:
        has_lib = False
    if has_lib:
        assert schema.make_entity("phone", "+1 (415) 555-0100")["value"] == "+14155550100"
    else:
        import pytest

        with pytest.raises(schema.SchemaError):
            schema.normalize_value("phone", "(415) 555-0100")
        assert schema.normalize_value("phone", "+1 415 555 0100") == "+14155550100"


def test_geo_null_island_is_dropped():
    entity = schema.make_entity("ip", "203.0.113.7", geo={"lat": 0, "lon": 0, "precision": "city"})
    assert "geo" not in entity


def test_geo_default_radius_fills_in():
    geo = schema.normalize_geo({"lat": 52.1, "lon": 4.3, "precision": "city"})
    assert geo["radiusM"] == schema.DEFAULT_RADIUS_M["city"]


def test_country_only_geo_is_allowed():
    geo = schema.normalize_geo({"precision": "country", "country": "us"})
    assert geo["country"] == "US"
    assert "lat" not in geo


def test_detect_selector():
    assert schema.detect_selector("alice@example.com") == "email"
    assert schema.detect_selector("203.0.113.7") == "ip"
    assert schema.detect_selector("@handle") == "username"
    assert schema.detect_selector("example.com") == "domain"
    assert schema.detect_selector("+1 415 555 0100") == "phone"
    assert schema.detect_selector("Jane Roe") == "person"
    assert schema.detect_selector("10 Downing Street London") == "address"


def test_link_id_is_deterministic():
    a = schema.entity_id("domain", "example.com")
    b = schema.entity_id("ip", "203.0.113.7")
    assert schema.make_link(a, b, "resolves_to")["id"] == schema.make_link(a, b, "resolves_to")["id"]
