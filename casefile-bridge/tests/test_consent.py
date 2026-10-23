"""Verified consent: proof of control before Sherlock, Maigret and PhoneInfoga."""

import json
import re
import sqlite3
import threading
import time

import pytest

from casefile.adapters.maigret import MaigretAdapter
from casefile.adapters.phoneinfoga import PhoneInfogaAdapter
from casefile.adapters.sherlock import SherlockAdapter
from casefile.adapters.spiderfoot import SpiderFootAdapter
from casefile.adapters.theharvester import TheHarvesterAdapter
from casefile.consent import ConsentError, ConsentRequired, ConsentService
from casefile.delivery import ConsoleSmsSender, DeliveryError, EnvOAuthProvider, OAuthRegistry, SmtpEmailSender
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
    profiles = FakeProfiles()
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
        stored = " ".join(
            "" if value is None else str(value) for row in conn.execute("SELECT * FROM consents") for value in row
        )
    assert EMAIL_NORMAL not in stored
    assert "Owner@Example.com" not in stored
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
    service.authorize(case_id, "phoneinfoga", PHONE, "phone")
    entries = service.audit_entries(case_id)
    assert [entry["result"] for entry in entries] == ["refused", "allowed"]
    assert entries[0]["consentId"] is None
    assert entries[1]["consentId"] == consent["id"]
    assert entries[0]["tool"] == "phoneinfoga"
    assert entries[0]["at"] and entries[1]["at"]
    with sqlite3.connect(service.path) as conn:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM consent_audit")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE consent_audit SET result='allowed'")
    assert [entry["result"] for entry in service.audit_entries(case_id)] == ["refused", "allowed"]
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
            ("alice@example.com", ["theharvester"], "email"),
            ("jdoe", ["spiderfoot"], "username"),
        ):
            status, payload = _request(
                base,
                "POST",
                f"/api/cases/{case_id}/jobs",
                {"selector": selector, "tools": tools, "selectorType": selector_type},
            )
            assert status == 202, payload
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
    assert PHONE in logged
    assert sms.sent[0][1].startswith("Your verification code is 654321")


def test_consent_does_not_cross_cases(tmp_path):
    service, _email, sms, _profiles, _provider = _service(tmp_path)
    first = "case_0123456789ab"
    second = "case_abcdefabcdef"
    package = _package(service, first, [{"type": "phone", "value": PHONE, "method": "sms_code", "tools": ["phoneinfoga"]}])
    service.confirm(first, package[0]["id"], code=_otp(sms.sent[0]["body"]))
    assert service.evaluate(second, "phoneinfoga", PHONE, "phone").reason == "no verified consent for this identifier"
    service.close()
