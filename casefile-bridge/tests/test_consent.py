"""Verified consent: proof of control before Sherlock, Maigret and PhoneInfoga."""

import json
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from casefile.adapters.maigret import MaigretAdapter
from casefile.adapters.phoneinfoga import PhoneInfogaAdapter
from casefile.adapters.sherlock import SherlockAdapter
from casefile.adapters.spiderfoot import SpiderFootAdapter
from casefile.adapters.theharvester import TheHarvesterAdapter
from casefile.consent import ConsentError, ConsentRequired, ConsentService
from casefile.delivery import (
    ConsoleSmsSender,
    DeliveryError,
    EnvOAuthProvider,
    HttpProfileFetcher,
    OAuthRegistry,
    SmtpEmailSender,
)
from casefile.jobs import Job, JobRunner
from casefile.server import make_server
from casefile.store import CaseRegistry
from test_server import _request

PHONE = "+14155550100"
EMAIL = "Owner@Example.com"
EMAIL_NORMAL = "owner@example.com"


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class RecordingEmail:
    def __init__(self):
        self.sent = []

    def send(self, to, subject, body):
        self.sent.append({"to": to, "subject": subject, "body": body})


class RecordingSms:
    def __init__(self):
        self.sent = []

    def send(self, to, body):
        self.sent.append({"to": to, "body": body})


class FakeProfiles:
    def __init__(self):
        self.pages = {}

    def supports(self, platform):
        return platform in {"github", "gitlab", "reddit", "x", "twitter"}

    def fetch_text(self, platform, username):
        key = (platform, username)
        if key not in self.pages:
            raise DeliveryError("could not fetch the public profile")
        return self.pages[key]


class FakeOAuth:
    name = "github"

    def __init__(self):
        self.subject = "jdoe"

    def authorization_url(self, *, state, redirect_uri):
        return f"https://github.example/authorize?state={state}&redirect_uri={redirect_uri}"

    def identity(self, *, code, redirect_uri):
        if code != "good-code":
            raise DeliveryError("oauth sign-in was not accepted")
        return self.subject


def _otp(body):
    return re.search(r"\b(\d{6})\b", body).group(1)


def _service(tmp_path, **kwargs):
    email = RecordingEmail()
    sms = RecordingSms()
    profiles = kwargs.pop("profiles", None) or FakeProfiles()
    provider = FakeOAuth()
    clock = kwargs.pop("clock", None)
    service = ConsentService(
        tmp_path / "consent.sqlite",
        salt=kwargs.pop("salt", "test-salt"),
        email=email,
        sms=sms,
        profiles=profiles,
        oauth=OAuthRegistry([provider], redirect_uri="https://case.test/callback"),
        clock=clock,
        **kwargs,
    )
    return service, email, sms, profiles, provider


def _package(service, case_id, identifiers):
    return service.create_package(case_id, {"identifiers": identifiers})


def _http(tmp_path, **kwargs):
    service, email, sms, profiles, provider = _service(tmp_path, **kwargs)
    httpd = make_server(str(tmp_path), port=0, workers=1, consent=service)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, base, service, email, sms, profiles, provider


def _case(base):
    status, case = _request(base, "POST", "/api/cases", {"name": "Office"})
    assert status == 201
    return case["id"]


def _wait_done(base, case_id):
    last = None
    for _ in range(100):
        status, payload = _request(base, "GET", f"/api/cases/{case_id}/jobs")
        last = payload
        jobs = payload.get("jobs") or []
        if jobs and all(job["state"] in ("done", "failed", "cancelled") for job in jobs):
            return jobs
        time.sleep(0.05)
    raise AssertionError(last)


@pytest.fixture
def inert_tools(monkeypatch):
    calls = []

    def run(self, selector, selector_type, ctx):
        calls.append(self.name)
        if self.name in ("theharvester", "maigret"):
            return {}
        if self.name == "spiderfoot":
            return []
        return ""

    for cls in (SherlockAdapter, MaigretAdapter, PhoneInfogaAdapter, SpiderFootAdapter, TheHarvesterAdapter):
        monkeypatch.setattr(cls, "run", run)
    return calls


def test_verified_phone_allows_phoneinfoga_and_unverified_is_refused(tmp_path, inert_tools):
    httpd, base, service, _email, sms, _profiles, _provider = _http(tmp_path)
    try:
        case_id = _case(base)
        status, refused = _request(
            base, "POST", f"/api/cases/{case_id}/jobs", {"selector": PHONE, "tools": ["phoneinfoga"]}
        )
        assert status == 403
        assert "no verified consent" in refused["error"]
        assert refused["refused"][0]["tool"] == "phoneinfoga"
        assert refused["refused"][0]["consentId"] is None
        assert _request(base, "GET", f"/api/cases/{case_id}/jobs")[1]["jobs"] == []

        status, package = _request(
            base,
            "POST",
            f"/api/cases/{case_id}/verifications",
            {"identifiers": [{"type": "phone", "value": PHONE, "method": "sms_code", "tools": ["phoneinfoga"]}]},
        )
        assert status == 201
        assert package["verifications"][0]["status"] == "pending"
        assert "profileCode" not in package["verifications"][0]
        code = _otp(sms.sent[0]["body"])
        status, confirmed = _request(
            base,
            "POST",
            f"/api/cases/{case_id}/verifications/{package['verifications'][0]['id']}/confirm",
            {"code": code},
        )
        assert status == 200
        assert confirmed["consent"]["tools"] == ["phoneinfoga"]
        assert PHONE not in json.dumps(confirmed["consent"])

        status, allowed = _request(
            base, "POST", f"/api/cases/{case_id}/jobs", {"selector": PHONE, "tools": ["phoneinfoga"]}
        )
        assert status == 202
        jobs = _wait_done(base, case_id)
        assert jobs[0]["tool"] == "phoneinfoga"
        assert "consent" not in jobs[0]["message"]
        assert inert_tools == ["phoneinfoga"]
        results = {entry["result"] for entry in service.audit_entries(case_id)}
        assert results == {"allowed", "refused"}
    finally:
        httpd.shutdown()
        httpd.bridge.close()


def test_wrong_code_does_not_grant_consent(tmp_path):
    service, _email, sms, _profiles, _provider = _service(tmp_path)
    case_id = "case_0123456789ab"
    package = _package(service, case_id, [{"type": "phone", "value": PHONE, "method": "sms_code"}])
    code = _otp(sms.sent[0]["body"])
    wrong = "000000" if code != "000000" else "000001"
    with pytest.raises(ConsentError, match="wrong"):
        service.confirm(case_id, package[0]["id"], code=wrong)
    assert service.list_consents(case_id) == []
    decision = service.evaluate(case_id, "phoneinfoga", PHONE, "phone")
    assert decision.ok is False
    assert decision.reason == "no verified consent for this identifier"
    service.close()


def test_expired_code_is_refused(tmp_path):
    clock = Clock()
    service, _email, sms, _profiles, _provider = _service(tmp_path, clock=clock)
    case_id = "case_0123456789ab"
    package = _package(service, case_id, [{"type": "phone", "value": PHONE, "method": "sms_code"}])
    code = _otp(sms.sent[0]["body"])
    clock.advance(15 * 60 + 1)
    with pytest.raises(ConsentError, match="expired"):
        service.confirm(case_id, package[0]["id"], code=code)
    assert service.list_consents(case_id) == []
    service.close()


def test_expired_consent_is_refused(tmp_path):
    clock = Clock()
    service, _email, sms, _profiles, _provider = _service(tmp_path, clock=clock, consent_ttl_s=60)
    case_id = "case_0123456789ab"
    package = _package(service, case_id, [{"type": "phone", "value": PHONE, "method": "sms_code", "tools": ["phoneinfoga"]}])
    service.confirm(case_id, package[0]["id"], code=_otp(sms.sent[0]["body"]))
    assert service.evaluate(case_id, "phoneinfoga", PHONE, "phone").ok is True
    clock.advance(61)
    decision = service.evaluate(case_id, "phoneinfoga", PHONE, "phone")
    assert decision.ok is False
    assert decision.reason == "consent has expired"
    assert decision.consent_id
    service.close()


def test_revoked_consent_is_refused_and_listed(tmp_path):
    httpd, base, service, _email, sms, _profiles, _provider = _http(tmp_path)
    try:
        case_id = _case(base)
        status, package = _request(
            base,
            "POST",
            f"/api/cases/{case_id}/verifications",
            {"identifiers": [{"type": "phone", "value": PHONE, "method": "sms_code", "tools": ["phoneinfoga"]}]},
        )
        assert status == 201
        status, confirmed = _request(
            base,
            "POST",
            f"/api/cases/{case_id}/verifications/{package['verifications'][0]['id']}/confirm",
            {"code": _otp(sms.sent[0]["body"])},
        )
        consent_id = confirmed["consent"]["id"]
        status, listing = _request(base, "GET", f"/api/cases/{case_id}/consents")
        assert status == 200
        assert listing["consents"][0]["id"] == consent_id
        assert listing["consents"][0]["revokedAt"] is None
        assert PHONE not in json.dumps(listing)

        status, revoked = _request(base, "POST", f"/api/cases/{case_id}/consents/{consent_id}/revoke", {})
        assert status == 200
        assert revoked["consent"]["revokedAt"]
        status, refused = _request(
            base, "POST", f"/api/cases/{case_id}/jobs", {"selector": PHONE, "tools": ["phoneinfoga"]}
        )
        assert status == 403
        assert "revoked" in refused["error"]
        assert refused["refused"][0]["consentId"] == consent_id
    finally:
        httpd.shutdown()
        httpd.bridge.close()


def test_tool_outside_consent_scope_is_refused(tmp_path):
    service, _email, _sms, profiles, _provider = _service(tmp_path)
    case_id = "case_0123456789ab"
    package = _package(
        service,
        case_id,
        [{"type": "username", "value": "@JDoe", "method": "profile_code", "platform": "github", "tools": ["sherlock"]}],
    )
    code = package[0]["profileCode"]
    profiles.pages[("github", "JDoe")] = f"bio {code}"
    consent = service.confirm(case_id, package[0]["id"], code=code)
    assert consent["tools"] == ["sherlock"]
    assert service.evaluate(case_id, "sherlock", "jdoe", "username").ok is True
    decision = service.evaluate(case_id, "maigret", "jdoe", "username")
    assert decision.ok is False
    assert decision.reason == "consent does not cover maigret"
    assert decision.consent_id == consent["id"]
    service.close()


def test_batch_verifies_each_identifier_independently(tmp_path):
    service, email, sms, profiles, _provider = _service(tmp_path)
    case_id = "case_0123456789ab"
    checklist = _package(
        service,
        case_id,
        [
            {"type": "email", "value": EMAIL, "method": "email_code", "tools": ["sherlock"]},
            {"type": "phone", "value": "+1 415 555 0100", "method": "sms_code", "tools": ["phoneinfoga"]},
            {"type": "username", "value": "jdoe", "method": "profile_code", "platform": "github", "tools": ["maigret", "sherlock"]},
        ],
    )
    assert [item["status"] for item in checklist] == ["pending", "pending", "pending"]
    assert [item["method"] for item in checklist] == ["email_code", "sms_code", "profile_code"]
    assert len({item["id"] for item in checklist}) == 3
    service.confirm(case_id, checklist[1]["id"], code=_otp(sms.sent[0]["body"]))
    assert service.evaluate(case_id, "phoneinfoga", PHONE, "phone").ok is True
    assert service.evaluate(case_id, "sherlock", "jdoe", "username").reason == "no verified consent for this identifier"
    assert service.list_consents(case_id)[0]["identifierType"] == "phone"
    assert EMAIL_NORMAL not in json.dumps(service.list_consents(case_id))
    # The other two codes were still delivered, and only to their own identifiers.
    assert [message["to"] for message in email.sent] == [EMAIL_NORMAL]
    assert [message["to"] for message in sms.sent] == [PHONE]
    assert checklist[2]["profileCode"]
    assert profiles.pages == {}
    service.close()


def test_codes_are_sent_only_to_the_identifier_itself(tmp_path):
    service, email, sms, _profiles, _provider = _service(tmp_path)
    case_id = "case_0123456789ab"
    _package(
        service,
        case_id,
        [
            {"type": "email", "value": EMAIL, "method": "email_code"},
            {"type": "phone", "value": PHONE, "method": "sms_code"},
        ],
    )
    assert email.sent[0]["to"] == EMAIL_NORMAL
    assert sms.sent[0]["to"] == PHONE
    assert PHONE not in email.sent[0]["body"]
    assert EMAIL_NORMAL not in sms.sent[0]["body"]
    assert _otp(email.sent[0]["body"]) != _otp(sms.sent[0]["body"])
    with pytest.raises(ConsentError, match="identifier itself"):
        _package(
            service,
            case_id,
            [{"type": "email", "value": "other@example.com", "method": "email_code", "deliverTo": "evil@example.com"}],
        )
    with pytest.raises(ConsentError, match="staff attestation"):
        _package(service, case_id, [{"type": "email", "value": "other@example.com", "method": "attestation"}])
    with pytest.raises(ConsentError, match="identifier itself"):
        service.create_package(
            case_id,
            {"contact": PHONE, "identifiers": [{"type": "email", "value": "other@example.com", "method": "email_code"}]},
        )
    assert [message["to"] for message in email.sent] == [EMAIL_NORMAL]
    assert [message["to"] for message in sms.sent] == [PHONE]
    service.close()


def test_consent_record_stores_a_salted_hash_not_the_raw_identifier(tmp_path):
    service, email, _sms, _profiles, _provider = _service(tmp_path, salt="salt-a")
    case_id = "case_0123456789ab"
    package = _package(service, case_id, [{"type": "email", "value": EMAIL, "method": "email_code", "tools": ["sherlock"]}])
    consent = service.confirm(case_id, package[0]["id"], code=_otp(email.sent[0]["body"]))
    assert consent["identifierHash"] != EMAIL_NORMAL
    assert consent["caseId"] == case_id
    assert consent["method"] == "email_code"
    assert consent["verifiedAt"]
    assert consent["expiresAt"]
    assert consent["revokedAt"] is None
    with sqlite3.connect(service.path) as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(consents)")]
        assert "destination" not in columns
        assert "platform" in columns
        stored = " ".join(
            "" if value is None else str(value) for row in conn.execute("SELECT * FROM consents") for value in row
        )
        verification = conn.execute(
            "SELECT destination, masked, identifier_hash, code_expires_at, expires_at FROM verifications"
        ).fetchone()
    assert EMAIL_NORMAL not in stored
    assert "Owner@Example.com" not in stored
    assert verification[0] == ""
    assert EMAIL_NORMAL not in (verification[1] or "")
    assert verification[2]
    assert verification[3] < verification[4]
    other, *_rest = _service(tmp_path / "other", salt="salt-b")
    other_package = _package(other, case_id, [{"type": "email", "value": EMAIL, "method": "email_code"}])
    other_consent = other.confirm(case_id, other_package[0]["id"], code=_otp(_rest[0].sent[0]["body"]))
    assert other_consent["identifierHash"] != consent["identifierHash"]
    other.close()
    service.close()


def test_audit_log_records_allowed_and_refused_and_is_append_only(tmp_path):
    service, _email, sms, _profiles, _provider = _service(tmp_path)
    case_id = "case_0123456789ab"
    refused = service.evaluate(case_id, "phoneinfoga", PHONE, "phone")
    service.audit(case_id, refused.consent_id, "phoneinfoga", "refused")
    package = _package(service, case_id, [{"type": "phone", "value": PHONE, "method": "sms_code", "tools": ["phoneinfoga"]}])
    consent = service.confirm(case_id, package[0]["id"], code=_otp(sms.sent[0]["body"]))
    decision = service.authorize(case_id, "phoneinfoga", PHONE, "phone", actor="desk.1")
    entries = service.audit_entries(case_id)
    assert [entry["result"] for entry in entries] == ["refused", "allowed"]
    assert entries[0]["consentId"] is None
    assert entries[1]["consentId"] == consent["id"]
    assert entries[0]["tool"] == "phoneinfoga"
    assert entries[0]["at"] and entries[1]["at"]
    assert entries[0]["actor"] == "local"
    assert entries[1]["actor"] == "desk.1"
    assert entries[1]["selectorHash"] == decision.selector_hash
    assert entries[1]["selectorHash"]
    assert PHONE not in entries[1]["selectorHash"]
    service.audit(case_id, None, "phoneinfoga", "refused", actor="not a valid id", selector_hash="abc")
    assert service.audit_entries(case_id)[-1]["actor"] == "local"
    with sqlite3.connect(service.path) as conn:
        conn.execute("PRAGMA recursive_triggers=ON")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM consent_audit")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE consent_audit SET result='allowed'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "INSERT OR REPLACE INTO consent_audit"
                "(id, case_id, consent_id, tool, selector_hash, actor, at, result)"
                " VALUES(?, ?, NULL, 'phoneinfoga', 'abc', 'local', '2020-01-01T00:00:00Z', 'refused')",
                (entries[0]["id"], case_id),
            )
    assert [entry["result"] for entry in service.audit_entries(case_id)] == ["refused", "allowed", "refused"]
    service.close()


def test_code_is_single_use_and_sends_are_rate_limited(tmp_path):
    service, _email, sms, _profiles, _provider = _service(tmp_path, max_sends=2)
    case_id = "case_0123456789ab"
    first = _package(service, case_id, [{"type": "phone", "value": PHONE, "method": "sms_code"}])
    code = _otp(sms.sent[0]["body"])
    service.confirm(case_id, first[0]["id"], code=code)
    with pytest.raises(ConsentError, match="already been used"):
        service.confirm(case_id, first[0]["id"], code=code)
    _package(service, case_id, [{"type": "phone", "value": PHONE, "method": "sms_code"}])
    with pytest.raises(ConsentError, match="too many") as error:
        _package(service, case_id, [{"type": "phone", "value": PHONE, "method": "sms_code"}])
    assert error.value.status == 429
    assert len(sms.sent) == 2
    service.close()


def test_profile_code_and_oauth_are_both_per_username(tmp_path):
    service, _email, _sms, profiles, provider = _service(tmp_path)
    case_id = "case_0123456789ab"
    profile = _package(
        service,
        case_id,
        [{"type": "username", "value": "jdoe", "method": "profile_code", "platform": "github", "tools": ["maigret"]}],
    )
    with pytest.raises(ConsentError, match="public profile"):
        service.confirm(case_id, profile[0]["id"], code=profile[0]["profileCode"])
    profiles.pages[("github", "jdoe")] = "name only"
    with pytest.raises(ConsentError, match="not found"):
        service.confirm(case_id, profile[0]["id"], code=profile[0]["profileCode"])
    profiles.pages[("github", "jdoe")] = f"posted {profile[0]['profileCode']} here"
    consent = service.confirm(case_id, profile[0]["id"], code=profile[0]["profileCode"])
    assert consent["method"] == "profile_code"

    oauth = _package(
        service,
        case_id,
        [{"type": "username", "value": "JDoe", "method": "oauth", "platform": "github", "tools": ["sherlock"]}],
    )[0]
    assert oauth["authorizationUrl"].startswith("https://github.example/authorize?")
    assert "client_secret" not in oauth["authorizationUrl"]
    provider.subject = "someone-else"
    with pytest.raises(ConsentError, match="does not match"):
        service.confirm(case_id, oauth["id"], oauth_code="good-code", state=oauth["state"])
    provider.subject = "jdoe"
    signed = service.confirm(case_id, oauth["id"], oauth_code="good-code", state=oauth["state"])
    assert signed["method"] == "oauth"
    assert service.evaluate(case_id, "sherlock", "@jdoe", "username").ok is True
    service.close()


def test_job_queue_refuses_before_the_adapter_runs(tmp_path, inert_tools):
    service, *_rest = _service(tmp_path)
    registry = CaseRegistry(tmp_path)
    case = registry.create("queue")
    runner = JobRunner(registry, workers=1, consent=service)
    try:
        with pytest.raises(ConsentRequired, match="no verified consent"):
            runner.submit(case["id"], PHONE, ["phoneinfoga"], selector_type="phone")
        job = Job(
            id="job_0123456789ab",
            case_id=case["id"],
            tool="phoneinfoga",
            selector=PHONE,
            selector_type="phone",
        )
        with pytest.raises(ConsentRequired):
            runner._execute(job)
        assert inert_tools == []
        assert runner.jobs_for(case["id"]) == []
    finally:
        runner.stop()
        service.close()
        registry.close()


def test_infrastructure_adapters_still_run_without_consent(tmp_path, inert_tools):
    httpd, base, _service_obj, _email, _sms, _profiles, _provider = _http(tmp_path)
    try:
        case_id = _case(base)
        for selector, tools, selector_type in (
            ("example.com", ["theharvester", "spiderfoot"], "domain"),
            ("mail.example.com", ["spiderfoot"], "host"),
            ("203.0.113.7", ["spiderfoot"], "ip"),
            ("AS64496", ["spiderfoot"], "asn"),
            ("abc123", ["spiderfoot"], "cert"),
        ):
            status, payload = _request(
                base,
                "POST",
                f"/api/cases/{case_id}/jobs",
                {"selector": selector, "tools": tools, "selectorType": selector_type},
            )
            assert status == 202, payload
            if selector_type in ("asn", "cert"):
                assert payload["jobs"] == []
            else:
                assert payload["jobs"]
        jobs = _wait_done(base, case_id)
        assert all("consent" not in job["message"] for job in jobs)
        assert "phoneinfoga" not in inert_tools
        assert "sherlock" not in inert_tools
        assert "spiderfoot" in inert_tools
        assert "theharvester" in inert_tools
    finally:
        httpd.shutdown()
        httpd.bridge.close()


def test_smtp_and_console_sms_do_not_log_secrets(monkeypatch, capsys):
    monkeypatch.setenv("CASEFILE_SMTP_HOST", "smtp.test")
    monkeypatch.setenv("CASEFILE_SMTP_FROM", "bridge@example.com")
    monkeypatch.setenv("CASEFILE_SMTP_USER", "bridge@example.com")
    monkeypatch.setenv("CASEFILE_SMTP_PASSWORD", "smtp-password-secret")

    class Boom:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("login failed for smtp-password-secret")

    monkeypatch.setattr("casefile.delivery.smtplib.SMTP", Boom)
    with pytest.raises(DeliveryError, match="email delivery failed") as caught:
        SmtpEmailSender().send("person@example.com", "Your verification code", "Your verification code is 123456.")
    assert "smtp-password-secret" not in str(caught.value)

    monkeypatch.setenv("CASEFILE_OAUTH_GITHUB_CLIENT_ID", "public-client")
    monkeypatch.setenv("CASEFILE_OAUTH_GITHUB_CLIENT_SECRET", "oauth-client-secret")
    monkeypatch.setenv("CASEFILE_OAUTH_GITHUB_AUTHORIZE_URL", "https://github.example/authorize")
    monkeypatch.setenv("CASEFILE_OAUTH_GITHUB_TOKEN_URL", "https://github.example/token")
    monkeypatch.setenv("CASEFILE_OAUTH_GITHUB_USERINFO_URL", "https://github.example/user")
    provider = EnvOAuthProvider("github")
    url = provider.authorization_url(state="state-1", redirect_uri="https://case.test/callback")
    assert "public-client" in url
    assert "oauth-client-secret" not in url

    sms = ConsoleSmsSender()
    sms.send(PHONE, "Your verification code is 654321. It expires in 15 minutes.")
    logged = capsys.readouterr().err
    assert "654321" not in logged
    assert PHONE not in logged
    assert "•" in logged
    assert sms.sent[0][0] == PHONE
    assert sms.sent[0][1].startswith("Your verification code is 654321")


def test_consent_does_not_cross_cases(tmp_path):
    service, _email, sms, _profiles, _provider = _service(tmp_path)
    first = "case_0123456789ab"
    second = "case_abcdefabcdef"
    package = _package(service, first, [{"type": "phone", "value": PHONE, "method": "sms_code", "tools": ["phoneinfoga"]}])
    service.confirm(first, package[0]["id"], code=_otp(sms.sent[0]["body"]))
    assert service.evaluate(second, "phoneinfoga", PHONE, "phone").reason == "no verified consent for this identifier"
    service.close()


def test_person_identifier_selectors_require_consent_for_any_tool(tmp_path, inert_tools):
    httpd, base, service, email, _sms, _profiles, _provider = _http(tmp_path)
    try:
        case_id = _case(base)
        refused_jobs = (
            ("alice@example.com", ["theharvester"], "email"),
            ("alice@example.com", ["spiderfoot"], "email"),
            (PHONE, ["spiderfoot"], "phone"),
            ("jdoe", ["spiderfoot"], "username"),
            ("Jane Roe", ["spiderfoot"], "person"),
        )
        for selector, tools, selector_type in refused_jobs:
            status, payload = _request(
                base,
                "POST",
                f"/api/cases/{case_id}/jobs",
                {"selector": selector, "tools": tools, "selectorType": selector_type},
            )
            assert status == 403, payload
            assert payload["refused"][0]["tool"] == tools[0]
            if selector_type == "person":
                assert "person name" in payload["error"]
        status, empty = _request(base, "POST", f"/api/cases/{case_id}/jobs", {"selector": "Jane Roe"})
        assert status == 202, empty
        assert empty["jobs"] == []
        assert _request(base, "GET", f"/api/cases/{case_id}/jobs")[1]["jobs"] == []

        status, rejected = _request(
            base,
            "POST",
            f"/api/cases/{case_id}/verifications",
            {"identifiers": [{"type": "person", "value": "Jane Roe", "method": "email_code"}]},
        )
        assert status == 400
        assert "person name" in rejected["error"]

        status, package = _request(
            base,
            "POST",
            f"/api/cases/{case_id}/verifications",
            {
                "identifiers": [
                    {
                        "type": "email",
                        "value": "alice@example.com",
                        "method": "email_code",
                        "tools": ["theharvester", "spiderfoot"],
                    }
                ]
            },
        )
        assert status == 201
        assert "alice@example.com" not in json.dumps(package)
        assert package["verifications"][0]["identifierMasked"].endswith("@example.com")
        service.confirm(case_id, package["verifications"][0]["id"], code=_otp(email.sent[0]["body"]))
        status, allowed = _request(
            base,
            "POST",
            f"/api/cases/{case_id}/jobs",
            {"selector": "alice@example.com", "tools": ["theharvester", "spiderfoot"], "selectorType": "email"},
        )
        assert status == 202, allowed
        jobs = _wait_done(base, case_id)
        assert {job["tool"] for job in jobs} == {"theharvester", "spiderfoot"}
        assert "phoneinfoga" not in inert_tools
    finally:
        httpd.shutdown()
        httpd.bridge.close()


def test_nfkc_and_casefold_collapse_equivalent_identifiers(tmp_path):
    service, email, _sms, profiles, _provider = _service(tmp_path)
    case_id = "case_0123456789ab"
    username = _package(
        service,
        case_id,
        [{"type": "username", "value": "straße", "method": "profile_code", "platform": "github", "tools": ["sherlock"]}],
    )
    profiles.pages[("github", "straße")] = username[0]["profileCode"]
    service.confirm(case_id, username[0]["id"], code=username[0]["profileCode"])
    assert service.evaluate(case_id, "sherlock", "strasse", "username").ok is True
    assert service.evaluate(case_id, "sherlock", "STRASSE", "username").ok is True

    ligature = "ﬁle@example.com"
    package = _package(service, case_id, [{"type": "email", "value": ligature, "method": "email_code", "tools": ["theharvester"]}])
    assert "file@example.com" not in json.dumps(package)
    service.confirm(case_id, package[0]["id"], code=_otp(email.sent[0]["body"]))
    assert service.evaluate(case_id, "theharvester", "file@example.com", "email").ok is True
    assert service.evaluate(case_id, "theharvester", "FILE@example.com", "email").ok is True
    service.close()


def test_confirm_attempts_are_atomic(tmp_path):
    service, _email, sms, _profiles, _provider = _service(tmp_path, max_attempts=5)
    case_id = "case_0123456789ab"
    package = _package(service, case_id, [{"type": "phone", "value": PHONE, "method": "sms_code"}])
    code = _otp(sms.sent[0]["body"])
    wrong = "000000" if code != "000000" else "000001"
    barrier = threading.Barrier(12)
    errors = []

    def attempt():
        barrier.wait()
        try:
            service.confirm(case_id, package[0]["id"], code=wrong)
        except ConsentError as error:
            errors.append(str(error))

    threads = [threading.Thread(target=attempt) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum("wrong" in error for error in errors) == 5
    assert sum("too many" in error for error in errors) == 7
    with sqlite3.connect(service.path) as conn:
        attempts = conn.execute("SELECT attempts FROM verifications").fetchone()[0]
    assert attempts == 5
    service.close()


def test_case_and_global_send_limits_reject_the_batch(tmp_path):
    service, _email, sms, _profiles, _provider = _service(tmp_path, max_sends=20, max_case_sends=2, max_global_sends=100)
    case_id = "case_0123456789ab"
    _package(service, case_id, [{"type": "phone", "value": "+14155550101", "method": "sms_code"}])
    _package(service, case_id, [{"type": "phone", "value": "+14155550102", "method": "sms_code"}])
    with pytest.raises(ConsentError, match="this case") as case_limit:
        _package(service, case_id, [{"type": "phone", "value": "+14155550103", "method": "sms_code"}])
    assert case_limit.value.status == 429
    assert len(sms.sent) == 2

    other, _email2, sms2, _profiles2, _provider2 = _service(
        tmp_path / "global", max_sends=20, max_case_sends=50, max_global_sends=2
    )
    _package(other, "case_0123456789ab", [{"type": "phone", "value": "+14155550111", "method": "sms_code"}])
    _package(other, "case_abcdefabcdef", [{"type": "phone", "value": "+14155550112", "method": "sms_code"}])
    with pytest.raises(ConsentError, match="too many verification messages") as global_limit:
        _package(other, "case_fedcbafedcba", [{"type": "phone", "value": "+14155550113", "method": "sms_code"}])
    assert global_limit.value.status == 429
    assert "identifier" not in str(global_limit.value)
    assert "case" not in str(global_limit.value)
    assert len(sms2.sent) == 2
    other.close()
    service.close()


def test_expired_verification_keeps_only_a_hash_and_a_mask(tmp_path):
    clock = Clock()
    service, _email, sms, _profiles, _provider = _service(tmp_path, clock=clock)
    case_id = "case_0123456789ab"
    package = _package(service, case_id, [{"type": "phone", "value": PHONE, "method": "sms_code"}])
    assert package[0]["identifierMasked"] != PHONE
    assert PHONE not in package[0]["identifierMasked"]
    assert "identifier" not in package[0]
    listed = service.list_verifications(case_id)
    assert PHONE not in json.dumps(listed)
    with sqlite3.connect(service.path) as conn:
        before = conn.execute("SELECT destination, masked, identifier_hash FROM verifications").fetchone()
    assert before[0] == PHONE
    clock.advance(15 * 60 + 1)
    service.sweep()
    with sqlite3.connect(service.path) as conn:
        after = conn.execute("SELECT destination, masked, identifier_hash FROM verifications").fetchone()
    assert after[0] == ""
    assert after[1] == before[1]
    assert after[2] == before[2]
    assert PHONE not in after[1]
    service.close()


def test_profile_fetch_rejects_redirects_paths_and_deadlines():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/slow"):
                time.sleep(1)
                body = b"too late"
            elif self.path.startswith("/away"):
                self.send_response(302)
                self.send_header("Location", "http://example.com/stolen")
                self.end_headers()
                return
            elif self.path.startswith("/hop"):
                self.send_response(302)
                host = self.headers.get("Host")
                self.send_header("Location", f"http://{host}/landed")
                self.end_headers()
                return
            else:
                body = b"landed profile"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    base = f"http://127.0.0.1:{port}"
    try:
        fetcher = HttpProfileFetcher(deadline_s=20)
        assert fetcher._fetch_limited(f"{base}/hop") == "landed profile"
        with pytest.raises(DeliveryError):
            fetcher._fetch_limited(f"{base}/away")
        slow = HttpProfileFetcher(deadline_s=0.2)
        with pytest.raises(DeliveryError):
            slow._fetch_limited(f"{base}/slow")
        for name in (".", "..", ".hidden", "a/b", "a\\b", "a..b", "a%2e", "a b"):
            with pytest.raises(DeliveryError):
                fetcher.fetch_text("github", name)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_gitlab_and_x_are_not_profile_code_platforms(tmp_path):
    service, *_rest = _service(tmp_path, profiles=HttpProfileFetcher())
    case_id = "case_0123456789ab"
    for platform in ("gitlab", "x", "twitter"):
        with pytest.raises(ConsentError, match="oauth") as error:
            _package(
                service,
                case_id,
                [{"type": "username", "value": "jdoe", "method": "profile_code", "platform": platform}],
            )
        assert error.value.status == 400
    service.close()


def test_operator_header_is_stored_on_the_audit(tmp_path, inert_tools):
    httpd, base, service, _email, _sms, _profiles, _provider = _http(tmp_path)
    try:
        case_id = _case(base)
        request = urllib.request.Request(
            base + f"/api/cases/{case_id}/jobs",
            data=json.dumps({"selector": PHONE, "tools": ["phoneinfoga"]}).encode(),
            method="POST",
        )
        request.add_header("Content-Type", "application/json")
        request.add_header("X-Casefile-Operator", "desk.1")
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        assert caught.value.code == 403
        assert service.audit_entries(case_id)[-1]["actor"] == "desk.1"
        request.add_header("X-Casefile-Operator", "has spaces")
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError:
            pass
        assert service.audit_entries(case_id)[-1]["actor"] == "local"
        assert inert_tools == []
    finally:
        httpd.shutdown()
        httpd.bridge.close()


def test_cross_platform_hits_are_ownership_unverified(tmp_path, monkeypatch):
    service, _email, _sms, profiles, _provider = _service(tmp_path)
    case_id_holder = {}
    registry = CaseRegistry(tmp_path)
    case = registry.create("ownership")
    case_id_holder["id"] = case["id"]
    package = _package(
        service,
        case["id"],
        [{"type": "username", "value": "jdoe", "method": "profile_code", "platform": "github", "tools": ["sherlock", "maigret"]}],
    )
    assert package[0]["platform"] == "github"
    profiles.pages[("github", "jdoe")] = package[0]["profileCode"]
    consent = service.confirm(case["id"], package[0]["id"], code=package[0]["profileCode"])
    assert consent["platform"] == "github"

    monkeypatch.setattr(
        SherlockAdapter,
        "run",
        lambda self, selector, selector_type, ctx: "[+] GitHub: https://github.com/jdoe\n[+] Reddit: https://reddit.com/u/jdoe\n",
    )
    monkeypatch.setattr(
        MaigretAdapter,
        "run",
        lambda self, selector, selector_type, ctx: {
            "GitHub": {"status": "Claimed", "url_user": "https://github.com/jdoe"},
            "Reddit": {"status": "Claimed", "url_user": "https://reddit.com/u/jdoe"},
        },
    )
    runner = JobRunner(registry, workers=1, consent=service)
    try:
        runner.submit(case["id"], "jdoe", ["sherlock", "maigret"], selector_type="username", actor="desk.1")
        jobs = []
        for _ in range(100):
            jobs = runner.jobs_for(case["id"])
            if jobs and all(job["state"] in ("done", "failed", "cancelled") for job in jobs):
                break
            time.sleep(0.05)
        assert [job["state"] for job in jobs] == ["done", "done"]
        store = registry.store(case["id"])
        by_value = {}
        for summary in store.query_entities(limit=20):
            entity = store.get_entity(summary["id"])
            by_value[entity["value"]] = entity
        assert {obs["ownership"] for obs in by_value["jdoe"]["observations"]} == {"verified"}
        github = by_value["https://github.com/jdoe"]
        reddit = by_value["https://reddit.com/u/jdoe"]
        assert {obs["ownership"] for obs in github["observations"]} == {"verified"}
        assert {obs["ownership"] for obs in reddit["observations"]} == {"unverified"}
        assert "jdoe" not in json.dumps(service.audit_entries(case["id"])[-1]["selectorHash"])
        assert service.audit_entries(case["id"])[-1]["actor"] == "desk.1"
    finally:
        runner.stop()
        service.close()
        registry.close()
