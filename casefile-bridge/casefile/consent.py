"""Verified-consent gate for person-identifier lookups.

A client hands over a data package of their own identifiers. The bridge opens
one verification per identifier and delivers every code at once, each code to
that identifier and nowhere else. Staff type the codes the client reads back.
The stored consent record keeps a salted hash of the identifier, never the
raw value, and never a name.

The gate is the selector type, not a tool list. Any tool aimed at a username,
email, phone or person name needs a consent that names that tool. Domain,
host, IP, ASN and cert lookups do not. Adapter modules do not import this
module; the job runner and the HTTP server both call the gate.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import schema
from .delivery import (
    PROFILE_TEXT_UNAVAILABLE,
    DeliveryError,
    HttpProfileFetcher,
    OAuthRegistry,
    SmtpEmailSender,
    mask_identifier,
    oauth_from_env,
    profile_username_ok,
    sms_from_env,
)

# Person-identifier selectors. A future adapter that accepts one of these is
# gated even if this set of tools grows. Infrastructure selectors are absent.
GATED_SELECTOR_TYPES = frozenset({"username", "email", "phone", "person"})
IDENTIFIER_TYPES = frozenset({"email", "phone", "username"})
_ACTOR_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
METHODS_FOR = {
    "email": frozenset({"email_code"}),
    "phone": frozenset({"sms_code"}),
    "username": frozenset({"profile_code", "oauth"}),
}
ATTESTATION_METHODS = frozenset({"attestation", "staff", "witness", "manual", "alternate", "alternate_contact"})
DEFAULT_TOOLS = {
    "username": ["maigret", "sherlock"],
    "phone": ["phoneinfoga"],
    "email": ["theharvester"],
}
_ITEM_KEYS = frozenset({"type", "value", "method", "tools", "platform"})
_ENVELOPE_KEYS = frozenset({"identifiers"})
_FORBIDDEN = frozenset({
    "contact",
    "alternate",
    "alternatecontact",
    "notify",
    "attestation",
    "deliverto",
    "cc",
    "bcc",
    "witness",
    "staff",
    "client",
    "clientname",
    "name",
    "email",
    "phone",
    "username",
})
_CASE_ID_RE = re.compile(r"^case_[a-z0-9]{12}$")
_PLATFORM_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_CODE_TTL_S = 15 * 60
_CONSENT_TTL_S = 24 * 3600
_MAX_ATTEMPTS = 5
_MAX_SENDS = 5
_MAX_CASE_SENDS = 50
_MAX_GLOBAL_SENDS = 200
_SEND_WINDOW_S = 3600
_MAX_PACKAGE = 50
_SWEEP_INTERVAL_S = 60

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verifications (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  identifier_hash TEXT NOT NULL,
  identifier_type TEXT NOT NULL,
  destination TEXT NOT NULL,
  masked TEXT NOT NULL,
  method TEXT NOT NULL,
  platform TEXT,
  oauth_state TEXT,
  redirect_uri TEXT,
  code_hash TEXT,
  tools TEXT NOT NULL,
  created_at TEXT NOT NULL,
  code_expires_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS verifications_hash ON verifications(identifier_hash, created_at);
CREATE INDEX IF NOT EXISTS verifications_case ON verifications(case_id, created_at);
CREATE TABLE IF NOT EXISTS consents (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  identifier_hash TEXT NOT NULL,
  identifier_type TEXT NOT NULL,
  method TEXT NOT NULL,
  platform TEXT,
  verified_at TEXT NOT NULL,
  tools TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS consents_lookup ON consents(case_id, identifier_hash);
CREATE TABLE IF NOT EXISTS consent_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  consent_id TEXT,
  tool TEXT NOT NULL,
  selector_hash TEXT,
  actor TEXT,
  at TEXT NOT NULL,
  result TEXT NOT NULL CHECK (result IN ('allowed', 'refused'))
);
CREATE INDEX IF NOT EXISTS consent_audit_case ON consent_audit(case_id, id);
CREATE TRIGGER IF NOT EXISTS consent_audit_no_update
BEFORE UPDATE ON consent_audit
BEGIN
  SELECT RAISE(ABORT, 'consent audit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS consent_audit_no_delete
BEFORE DELETE ON consent_audit
BEGIN
  SELECT RAISE(ABORT, 'consent audit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS consent_audit_no_reinsert
BEFORE INSERT ON consent_audit
WHEN EXISTS (SELECT 1 FROM consent_audit WHERE id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'consent audit is append-only');
END;
"""


class ConsentError(Exception):
    """A verification or consent request was rejected."""

    def __init__(self, message: str, *, status: int = 400, consent_id: str | None = None):
        super().__init__(message)
        self.status = status
        self.consent_id = consent_id


class ConsentRequired(ConsentError):
    """A gated lookup has no usable consent. The HTTP layer answers 403."""

    def __init__(self, message: str, refused: list | None = None, *, consent_id: str | None = None):
        super().__init__(message, status=403, consent_id=consent_id)
        self.refused = list(refused or [])


@dataclass(frozen=True)
class Decision:
    ok: bool
    tool: str
    reason: str
    consent_id: str | None = None
    platform: str | None = None
    selector_hash: str | None = None


def normalize_actor(value: str | None) -> str:
    """Opaque operator id from ``X-Casefile-Operator``, or ``local``."""
    if isinstance(value, str) and _ACTOR_RE.fullmatch(value):
        return value
    return "local"


def open_consent(store_root, **kwargs) -> "ConsentService":
    """Open the consent database next to the case files, using env configuration."""
    root = Path(store_root)
    salt = kwargs.pop("salt", os.environ.get("CASEFILE_CONSENT_SALT", ""))
    email = kwargs.pop("email", None) or SmtpEmailSender()
    sms = kwargs.pop("sms", None) or sms_from_env()
    profiles = kwargs.pop("profiles", None) or HttpProfileFetcher()
    oauth = kwargs.pop("oauth", None) or oauth_from_env()
    return ConsentService(
        root / "consent.sqlite",
        salt=salt,
        email=email,
        sms=sms,
        profiles=profiles,
        oauth=oauth,
        **kwargs,
    )


class ConsentService:
    def __init__(
        self,
        path,
        *,
        salt: str | bytes,
        email,
        sms,
        profiles,
        oauth: OAuthRegistry | None = None,
        clock=None,
        code_ttl_s: int = _CODE_TTL_S,
        consent_ttl_s: int = _CONSENT_TTL_S,
        max_attempts: int = _MAX_ATTEMPTS,
        max_sends: int = _MAX_SENDS,
        max_case_sends: int = _MAX_CASE_SENDS,
        max_global_sends: int = _MAX_GLOBAL_SENDS,
        send_window_s: int = _SEND_WINDOW_S,
        sweep_interval_s: float = _SWEEP_INTERVAL_S,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._salt = salt.encode("utf-8") if isinstance(salt, str) else salt
        self.email = email
        self.sms = sms
        self.profiles = profiles
        self.oauth = oauth or OAuthRegistry()
        self._clock = clock or time.time
        self.code_ttl_s = code_ttl_s
        self.consent_ttl_s = consent_ttl_s
        self.max_attempts = max_attempts
        self.max_sends = max_sends
        self.max_case_sends = max_case_sends
        self.max_global_sends = max_global_sends
        self.send_window_s = send_window_s
        self.sweep_interval_s = sweep_interval_s
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        # REPLACE deletes the old row. The append-only DELETE trigger fires for
        # that delete only when recursive triggers are enabled.
        self._conn.execute("PRAGMA recursive_triggers=ON")
        self._conn.executescript(_SCHEMA)
        _migrate(self._conn)
        self._conn.commit()
        self._sweeper = threading.Thread(target=self._sweep_loop, name="casefile-consent-sweep", daemon=True)
        self._sweeper.start()

    def close(self) -> None:
        self._stop.set()
        thread = getattr(self, "_sweeper", None)
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2)
        with self._lock:
            conn = self._conn
            self._conn = None
            if conn is not None:
                conn.close()

    # -- data package -------------------------------------------------------
    def create_package(self, case_id: str, body: dict) -> list[dict]:
        """Open one pending verification per identifier and deliver every code."""
        self._require_salt()
        self._require_case_id(case_id)
        if not isinstance(body, dict):
            raise ConsentError("data package must be an object", status=400)
        _reject_unknown(body, _ENVELOPE_KEYS, envelope=True)
        identifiers = body.get("identifiers")
        if not isinstance(identifiers, list) or not identifiers:
            raise ConsentError("identifiers must be a non-empty list", status=400)
        if len(identifiers) > _MAX_PACKAGE:
            raise ConsentError("a data package is limited to 50 identifiers", status=400)
        prepared = [self._prepare(item) for item in identifiers]
        created = []
        with self._lock:
            try:
                self._enforce_rate(case_id, prepared)
                opened = [self._insert_verification(case_id, item) for item in prepared]
                self._conn.commit()
            except Exception:
                if self._conn is not None:
                    self._conn.rollback()
                raise
        for item, (row, reveal) in zip(prepared, opened):
            try:
                self._deliver(item)
            except DeliveryError as error:
                self._delete_verification(row["id"])
                raise ConsentError(str(error), status=502) from None
            created.append(self._public_verification(row, **reveal))
        return created

    def confirm(
        self,
        case_id: str,
        verification_id: str,
        *,
        code: str | None = None,
        oauth_code: str | None = None,
        state: str | None = None,
    ) -> dict:
        self._require_case_id(case_id)
        row = self._claim_attempt(case_id, verification_id)
        method = row["method"]
        if method == "oauth":
            self._confirm_oauth(row, oauth_code, state)
        elif method == "profile_code":
            self._confirm_profile(row, code)
        else:
            self._confirm_otp(row, code)
        return self._grant(row)

    def list_verifications(self, case_id: str) -> list[dict]:
        self._require_case_id(case_id)
        rows = self._conn.execute(
            "SELECT * FROM verifications WHERE case_id=? ORDER BY created_at, id",
            (case_id,),
        ).fetchall()
        return [self._public_verification(row) for row in rows]

    def list_consents(self, case_id: str) -> list[dict]:
        self._require_case_id(case_id)
        rows = self._conn.execute(
            "SELECT id, case_id, identifier_hash, identifier_type, method, platform, verified_at, tools, expires_at, revoked_at"
            " FROM consents WHERE case_id=? ORDER BY verified_at, id",
            (case_id,),
        ).fetchall()
        return [_public_consent(row) for row in rows]

    def revoke(self, case_id: str, consent_id: str) -> dict:
        self._require_case_id(case_id)
        with self._lock:
            row = self._consent_row(case_id, consent_id)
            if row is None:
                raise ConsentError("consent not found", status=404)
            if not row["revoked_at"]:
                self._conn.execute(
                    "UPDATE consents SET revoked_at=? WHERE id=? AND case_id=?",
                    (self._now_iso(), consent_id, case_id),
                )
                self._conn.commit()
            fresh = self._consent_row(case_id, consent_id)
        return _public_consent(fresh)

    # -- enforcement --------------------------------------------------------
    def evaluate(self, case_id: str, tool: str, selector: str, selector_type: str) -> Decision:
        """Decide a gated lookup. Does not write the audit log."""
        if not self._salt:
            return Decision(False, tool, "CASEFILE_CONSENT_SALT is not set", None)
        if selector_type not in GATED_SELECTOR_TYPES:
            return Decision(True, tool, "selector type is not gated", None)
        try:
            normalized = _normalize_identifier(selector_type, selector)
            digest = self._identifier_hash(selector_type, _hash_form(selector_type, normalized))
        except schema.SchemaError as error:
            reason = str(error) if "ASCII" in str(error) else "identifier could not be normalized"
            return Decision(False, tool, reason, None)
        rows = self._conn.execute(
            "SELECT id, case_id, identifier_hash, identifier_type, method, platform, verified_at, tools, expires_at, revoked_at"
            " FROM consents WHERE case_id=? AND identifier_hash=? ORDER BY verified_at DESC",
            (case_id, digest),
        ).fetchall()
        now = self._now_iso()
        out_of_scope = expired = revoked = None
        for row in rows:
            tools = json.loads(row["tools"])
            is_revoked = bool(row["revoked_at"])
            is_expired = row["expires_at"] <= now
            in_scope = tool in tools
            if not is_revoked and not is_expired and in_scope:
                return _decision(True, tool, "allowed", row, digest)
            if not is_revoked and not is_expired and not in_scope:
                out_of_scope = out_of_scope or row
            elif is_revoked:
                revoked = revoked or row
            elif is_expired:
                expired = expired or row
        if out_of_scope:
            return _decision(False, tool, f"consent does not cover {tool}", out_of_scope, digest)
        if revoked:
            return _decision(False, tool, "consent has been revoked", revoked, digest)
        if expired:
            return _decision(False, tool, "consent has expired", expired, digest)
        if selector_type == "person":
            return _decision(False, tool, "a person name is not a verifiable identifier", None, digest)
        return _decision(False, tool, "no verified consent for this identifier", None, digest)

    def authorize(self, case_id: str, tool: str, selector: str, selector_type: str, *, actor: str | None = None) -> Decision:
        """Allow a gated lookup, or raise ``ConsentRequired`` after auditing it."""
        decision = self.evaluate(case_id, tool, selector, selector_type)
        self.audit(
            case_id,
            decision.consent_id,
            tool,
            "allowed" if decision.ok else "refused",
            selector_hash=decision.selector_hash,
            actor=actor,
        )
        if not decision.ok:
            raise ConsentRequired(decision.reason, consent_id=decision.consent_id)
        return decision

    def audit(
        self,
        case_id: str,
        consent_id: str | None,
        tool: str,
        result: str,
        *,
        selector_hash: str | None = None,
        actor: str | None = None,
    ) -> None:
        if result not in ("allowed", "refused"):
            raise ConsentError("invalid audit result", status=500)
        with self._lock:
            self._conn.execute(
                "INSERT INTO consent_audit(case_id, consent_id, tool, selector_hash, actor, at, result)"
                " VALUES(?, ?, ?, ?, ?, ?, ?)",
                (case_id, consent_id, tool, selector_hash, normalize_actor(actor), self._now_iso(), result),
            )
            self._conn.commit()

    def audit_entries(self, case_id: str | None = None) -> list[dict]:
        columns = "id, case_id, consent_id, tool, selector_hash, actor, at, result"
        if case_id:
            rows = self._conn.execute(
                f"SELECT {columns} FROM consent_audit WHERE case_id=? ORDER BY id",
                (case_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(f"SELECT {columns} FROM consent_audit ORDER BY id").fetchall()
        return [
            {
                "id": row["id"],
                "caseId": row["case_id"],
                "consentId": row["consent_id"],
                "tool": row["tool"],
                "selectorHash": row["selector_hash"],
                "actor": row["actor"] or "local",
                "at": row["at"],
                "result": row["result"],
            }
            for row in rows
        ]

    def sweep(self) -> None:
        """Drop raw identifiers from consumed or expired verification rows."""
        now = self._now_iso()
        with self._lock:
            if self._conn is None:
                return
            self._conn.execute(
                "UPDATE verifications SET destination=''"
                " WHERE destination != '' AND (consumed_at IS NOT NULL OR code_expires_at <= ? OR expires_at <= ?)",
                (now, now),
            )
            self._conn.commit()

    # -- internals ----------------------------------------------------------
    def _prepare(self, item) -> dict:
        if not isinstance(item, dict):
            raise ConsentError("each identifier must be an object", status=400)
        _reject_unknown(item, _ITEM_KEYS, envelope=False)
        identifier_type = item.get("type")
        if identifier_type == "person":
            raise ConsentError("a person name is not a verifiable identifier", status=400)
        if identifier_type not in IDENTIFIER_TYPES:
            raise ConsentError("identifier type must be email, phone or username", status=400)
        method = item.get("method")
        if not isinstance(method, str):
            raise ConsentError("method is required", status=400)
        if method in ATTESTATION_METHODS:
            raise ConsentError(
                "staff attestation is not proof of control; deliver a code to the identifier itself",
                status=400,
            )
        if method not in METHODS_FOR[identifier_type]:
            allowed = ", ".join(sorted(METHODS_FOR[identifier_type]))
            raise ConsentError(f"{identifier_type} identifiers are verified with {allowed}", status=400)
        raw = item.get("value")
        if not isinstance(raw, str) or not raw.strip():
            raise ConsentError("identifier value is required", status=400)
        if len(raw) > 320:
            raise ConsentError("identifier value is too long", status=400)
        try:
            normalized = _normalize_identifier(identifier_type, raw)
            hash_form = _hash_form(identifier_type, normalized)
        except schema.SchemaError as error:
            raise ConsentError(str(error), status=400) from None
        platform = item.get("platform")
        if method in ("profile_code", "oauth"):
            if not isinstance(platform, str) or not _PLATFORM_RE.match(platform):
                raise ConsentError("platform must be a short name such as github", status=400)
            if method == "profile_code" and platform in PROFILE_TEXT_UNAVAILABLE:
                raise ConsentError(
                    "profile text is not available for this platform; use oauth instead",
                    status=400,
                )
            if method == "profile_code" and not profile_username_ok(normalized):
                raise ConsentError("username cannot be used as a profile path", status=400)
            if method == "profile_code" and not self.profiles.supports(platform):
                raise ConsentError(f"unsupported platform: {platform}", status=400)
            if method == "oauth":
                if self.oauth.get(platform) is None:
                    raise ConsentError(f"no oauth provider configured for {platform}", status=400)
                if not self.oauth.redirect_uri:
                    raise ConsentError("CASEFILE_OAUTH_REDIRECT_URI is not set", status=503)
        elif platform not in (None, ""):
            raise ConsentError("platform is only used for username verification", status=400)
        code = None
        if method == "email_code" or method == "sms_code":
            code = f"{secrets.randbelow(1_000_000):06d}"
        elif method == "profile_code":
            code = "gev-" + secrets.token_hex(8)
        return {
            "type": identifier_type,
            "destination": normalized,
            "hash_form": hash_form,
            "method": method,
            "platform": platform or None,
            "tools": _tools_for(item.get("tools"), identifier_type),
            "code": code,
        }

    def _enforce_rate(self, case_id: str, prepared: list[dict]) -> None:
        """Reject the whole batch before any insert when a limit would be exceeded.

        Caller holds ``self._lock``.
        """
        counts: dict[str, int] = {}
        for item in prepared:
            digest = self._identifier_hash(item["type"], item["hash_form"])
            counts[digest] = counts.get(digest, 0) + 1
            if self._recent_sends(digest) + counts[digest] > self.max_sends:
                raise ConsentError(
                    "too many verification messages for this identifier; try again later",
                    status=429,
                )
        incoming = len(prepared)
        if self._recent_case_sends(case_id) + incoming > self.max_case_sends:
            raise ConsentError(
                "too many verification messages for this case; try again later",
                status=429,
            )
        if self._recent_global_sends() + incoming > self.max_global_sends:
            raise ConsentError("too many verification messages; try again later", status=429)

    def _recent_sends(self, digest: str) -> int:
        return self._count("identifier_hash=?", (digest,))

    def _recent_case_sends(self, case_id: str) -> int:
        return self._count("case_id=?", (case_id,))

    def _recent_global_sends(self) -> int:
        return self._count("1=1", ())

    def _count(self, where: str, params: tuple) -> int:
        cutoff = _iso(self._now() - self.send_window_s)
        row = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM verifications WHERE {where} AND created_at>=?",
            (*params, cutoff),
        ).fetchone()
        return int(row["n"])

    def _insert_verification(self, case_id: str, item: dict) -> tuple[sqlite3.Row, dict]:
        """Insert one row. Caller holds ``self._lock`` and commits."""
        verification_id = "ver_" + uuid.uuid4().hex[:12]
        state = secrets.token_urlsafe(18) if item["method"] == "oauth" else None
        redirect = self.oauth.redirect_uri if item["method"] == "oauth" else None
        code_hash = self._code_hash(verification_id, item["code"]) if item["code"] else None
        created = self._now_iso()
        code_expires = _iso(self._now() + self.code_ttl_s)
        expires = _iso(self._now() + self.consent_ttl_s)
        digest = self._identifier_hash(item["type"], item["hash_form"])
        masked = mask_identifier(item["type"], item["destination"])
        self._conn.execute(
            "INSERT INTO verifications(id, case_id, identifier_hash, identifier_type, destination, masked, method,"
            " platform, oauth_state, redirect_uri, code_hash, tools, created_at, code_expires_at, expires_at, attempts)"
            " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (
                verification_id,
                case_id,
                digest,
                item["type"],
                item["destination"],
                masked,
                item["method"],
                item["platform"],
                state,
                redirect,
                code_hash,
                json.dumps(item["tools"]),
                created,
                code_expires,
                expires,
            ),
        )
        reveal: dict = {}
        if item["method"] == "profile_code":
            reveal["profile_code"] = item["code"]
        if item["method"] == "oauth":
            provider = self.oauth.get(item["platform"])
            try:
                reveal["authorization_url"] = provider.authorization_url(state=state, redirect_uri=redirect)
            except Exception:
                raise ConsentError("oauth provider is not available", status=503) from None
            reveal["state"] = state
        row = self._verification(case_id, verification_id)
        return row, reveal

    def _deliver(self, item: dict) -> None:
        code = item["code"]
        destination = item["destination"]
        if item["method"] == "email_code":
            self.email.send(
                destination,
                "Your verification code",
                f"Your verification code is {code}. It expires in 15 minutes.",
            )
        elif item["method"] == "sms_code":
            self.sms.send(destination, f"Your verification code is {code}. It expires in 15 minutes.")
        # profile_code is posted by the client. oauth is a sign-in, not a message.

    def _confirm_otp(self, row, code) -> None:
        if not self._code_matches(row, code):
            raise ConsentError("verification code is wrong", status=400)

    def _confirm_profile(self, row, code) -> None:
        if not self._code_matches(row, code):
            raise ConsentError("verification code is wrong", status=400)
        try:
            text = self.profiles.fetch_text(row["platform"], row["destination"])
        except DeliveryError as error:
            raise ConsentError(str(error), status=502) from None
        if not isinstance(text, str) or not _constant_contains(text, code.strip()):
            raise ConsentError("code was not found on the public profile", status=400)

    def _confirm_oauth(self, row, oauth_code, state) -> None:
        expected = row["oauth_state"] or ""
        if not isinstance(state, str) or not _same(state, expected):
            raise ConsentError("oauth state does not match", status=400)
        provider = self.oauth.get(row["platform"])
        if provider is None:
            raise ConsentError("no oauth provider configured", status=503)
        try:
            subject = provider.identity(code=oauth_code or "", redirect_uri=row["redirect_uri"] or "")
        except DeliveryError:
            raise ConsentError("oauth sign-in was not accepted", status=400) from None
        except Exception:
            raise ConsentError("oauth sign-in was not accepted", status=400) from None
        try:
            normalized = schema.normalize_value("username", str(subject))
            form = _hash_form("username", normalized)
        except schema.SchemaError:
            raise ConsentError("oauth identity does not match the identifier", status=400) from None
        actual = self._identifier_hash("username", form)
        if not hmac.compare_digest(actual, row["identifier_hash"]):
            raise ConsentError("oauth identity does not match the identifier", status=400)

    def _code_matches(self, row, code) -> bool:
        submitted = code.strip() if isinstance(code, str) else ""
        actual = self._code_hash(row["id"], submitted)
        expected = row["code_hash"] or ""
        if len(actual) != len(expected):
            return False
        return hmac.compare_digest(actual, expected)

    def _grant(self, row) -> dict:
        consent_id = "cns_" + uuid.uuid4().hex[:12]
        verified_at = self._now_iso()
        expires_at = _iso(self._now() + self.consent_ttl_s)
        with self._lock:
            current = self._verification(row["case_id"], row["id"])
            if current is None or current["consumed_at"]:
                raise ConsentError("verification code has already been used", status=400)
            if current["code_expires_at"] <= verified_at or current["expires_at"] <= verified_at:
                raise ConsentError("verification code has expired", status=400)
            cursor = self._conn.execute(
                "UPDATE verifications SET consumed_at=?, destination='' WHERE id=? AND consumed_at IS NULL",
                (verified_at, row["id"]),
            )
            if cursor.rowcount != 1:
                self._conn.rollback()
                raise ConsentError("verification code has already been used", status=400)
            self._conn.execute(
                "INSERT INTO consents(id, case_id, identifier_hash, identifier_type, method, platform, verified_at, tools, expires_at, revoked_at)"
                " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    consent_id,
                    row["case_id"],
                    row["identifier_hash"],
                    row["identifier_type"],
                    row["method"],
                    row["platform"],
                    verified_at,
                    row["tools"],
                    expires_at,
                ),
            )
            self._conn.commit()
            fresh = self._consent_row(row["case_id"], consent_id)
        return _public_consent(fresh)

    def _claim_attempt(self, case_id: str, verification_id: str):
        """Count one confirm attempt, or reject when the row is no longer open.

        The check and the increment are one UPDATE, so parallel confirms cannot
        pass the attempt limit. The refreshed row is read before the lock is
        released; the connection is not safe to share across threads otherwise.
        """
        with self._lock:
            now = self._now_iso()
            if self._conn is None:
                raise ConsentError("verification not found", status=404)
            cursor = self._conn.execute(
                "UPDATE verifications SET attempts = attempts + 1"
                " WHERE id=? AND consumed_at IS NULL AND code_expires_at > ? AND expires_at > ? AND attempts < ?",
                (verification_id, now, now, self.max_attempts),
            )
            self._conn.commit()
            if cursor.rowcount == 1:
                return _row_dict(self._verification(case_id, verification_id))
            row = _row_dict(self._conn.execute("SELECT * FROM verifications WHERE id=?", (verification_id,)).fetchone())
        if row is None:
            raise ConsentError("verification not found", status=404)
        if row["consumed_at"]:
            raise ConsentError("verification code has already been used", status=400)
        if (row["code_expires_at"] or "") <= now or (row["expires_at"] or "") <= now:
            raise ConsentError("verification code has expired", status=400)
        raise ConsentError("too many attempts", status=429)

    def _delete_verification(self, verification_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM verifications WHERE id=?", (verification_id,))
            self._conn.commit()

    def _verification(self, case_id: str, verification_id: str):
        return self._conn.execute(
            "SELECT * FROM verifications WHERE case_id=? AND id=?",
            (case_id, verification_id),
        ).fetchone()

    def _consent_row(self, case_id: str, consent_id: str):
        return self._conn.execute(
            "SELECT id, case_id, identifier_hash, identifier_type, method, platform, verified_at, tools, expires_at, revoked_at"
            " FROM consents WHERE case_id=? AND id=?",
            (case_id, consent_id),
        ).fetchone()

    def _public_verification(self, row, *, profile_code=None, authorization_url=None, state=None) -> dict:
        payload = {
            "id": row["id"],
            "status": self._verification_status(row),
            "identifierType": row["identifier_type"],
            "identifierMasked": row["masked"] or mask_identifier(row["identifier_type"], row["destination"]),
            "method": row["method"],
            "platform": row["platform"],
            "tools": json.loads(row["tools"]),
            "codeExpiresAt": row["code_expires_at"],
            "expiresAt": row["expires_at"],
        }
        if profile_code:
            payload["profileCode"] = profile_code
        if authorization_url:
            payload["authorizationUrl"] = authorization_url
        if state:
            payload["state"] = state
        return payload

    def _verification_status(self, row) -> str:
        if row["consumed_at"]:
            return "verified"
        now = self._now_iso()
        if (row["code_expires_at"] or "") <= now or (row["expires_at"] or "") <= now:
            return "expired"
        if row["attempts"] >= self.max_attempts:
            return "locked"
        return "pending"

    def _require_salt(self) -> None:
        if not self._salt:
            raise ConsentError("CASEFILE_CONSENT_SALT is not set", status=503)

    def _require_case_id(self, case_id: str) -> None:
        if not isinstance(case_id, str) or not _CASE_ID_RE.match(case_id):
            raise ConsentError("invalid case id", status=400)

    def _identifier_hash(self, identifier_type: str, hash_form: str) -> str:
        return hmac.new(self._salt, f"{identifier_type}\x1f{hash_form}".encode(), hashlib.sha256).hexdigest()

    def _code_hash(self, verification_id: str, code: str) -> str:
        return hmac.new(self._salt, f"{verification_id}\x1f{code}".encode(), hashlib.sha256).hexdigest()

    def _now(self) -> float:
        return float(self._clock())

    def _now_iso(self) -> str:
        return _iso(self._now())

    def _sweep_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.sweep()
            except sqlite3.Error:
                return
            if self._stop.wait(self.sweep_interval_s):
                return


def _public_consent(row) -> dict:
    return {
        "id": row["id"],
        "caseId": row["case_id"],
        "identifierHash": row["identifier_hash"],
        "identifierType": row["identifier_type"],
        "method": row["method"],
        "platform": row["platform"],
        "verifiedAt": row["verified_at"],
        "tools": json.loads(row["tools"]),
        "expiresAt": row["expires_at"],
        "revokedAt": row["revoked_at"],
    }


def _tools_for(requested, identifier_type: str) -> list[str]:
    from . import adapters

    allowed = set(adapters.REGISTRY)
    if requested is None:
        return [name for name in DEFAULT_TOOLS[identifier_type] if name in allowed]
    if not isinstance(requested, list) or not requested:
        raise ConsentError("tools must name a registered adapter", status=400)
    chosen = []
    for name in requested:
        if name not in allowed:
            raise ConsentError("tools must name a registered adapter", status=400)
        if name not in chosen:
            chosen.append(name)
    return chosen


def _normalize_identifier(identifier_type: str, raw: str) -> str:
    """NFKC emails and person names. Usernames are not compatibility-folded."""
    if identifier_type == "username":
        return schema.normalize_value(identifier_type, raw)
    return schema.normalize_value(identifier_type, unicodedata.normalize("NFKC", raw))


def _hash_form(identifier_type: str, normalized: str) -> str:
    # Usernames are not casefolded through NFKC. Casefold maps ß to ss, and
    # NFKC maps ligatures and fullwidth letters onto ASCII, so a consent for
    # one username would authorize a different one. Non-ASCII usernames are
    # refused. ASCII still casefolds, so JDoe and jdoe stay one identifier.
    if identifier_type == "username":
        if not normalized.isascii():
            raise schema.SchemaError("usernames must be ASCII")
        return normalized.casefold()
    text = unicodedata.normalize("NFKC", normalized)
    if identifier_type in ("email", "person"):
        return text.casefold()
    return text


def _row_dict(row):
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def _decision(ok: bool, tool: str, reason: str, row, digest: str | None) -> Decision:
    return Decision(
        ok,
        tool,
        reason,
        None if row is None else row["id"],
        None if row is None else row["platform"],
        digest,
    )


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the first consent schema."""

    def columns(table: str) -> set[str]:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

    verification_columns = columns("verifications")
    if "code_expires_at" not in verification_columns:
        conn.execute("ALTER TABLE verifications ADD COLUMN code_expires_at TEXT")
        conn.execute("UPDATE verifications SET code_expires_at = expires_at WHERE code_expires_at IS NULL")
    if "masked" not in verification_columns:
        conn.execute("ALTER TABLE verifications ADD COLUMN masked TEXT NOT NULL DEFAULT ''")
    if "platform" not in columns("consents"):
        conn.execute("ALTER TABLE consents ADD COLUMN platform TEXT")
    audit_columns = columns("consent_audit")
    if "selector_hash" not in audit_columns:
        conn.execute("ALTER TABLE consent_audit ADD COLUMN selector_hash TEXT")
    if "actor" not in audit_columns:
        conn.execute("ALTER TABLE consent_audit ADD COLUMN actor TEXT")


def _reject_unknown(mapping: dict, allowed: frozenset, *, envelope: bool) -> None:
    extra = [key for key in mapping if key not in allowed]
    if not extra:
        return
    if any(_is_forbidden(key) for key in extra):
        raise ConsentError(
            "proof must be delivered to the identifier itself; staff attestation and alternate contacts are not accepted",
            status=400,
        )
    what = "data package" if envelope else "identifier"
    raise ConsentError(f"unrecognized {what} field", status=400)


def _is_forbidden(key: str) -> bool:
    folded = key.lower().replace("_", "")
    return folded in _FORBIDDEN or key.lower() in _FORBIDDEN


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _same(left: str, right: str) -> bool:
    """Constant-time equality for strings that may differ in length."""
    return hmac.compare_digest(
        hashlib.sha256(left.encode("utf-8")).digest(),
        hashlib.sha256(right.encode("utf-8")).digest(),
    )


def _constant_contains(haystack: str, needle: str) -> bool:
    """True when ``needle`` occurs in ``haystack``, without returning early on a match."""
    if not needle:
        return False
    hay = haystack.encode("utf-8", "replace")
    ned = needle.encode("utf-8")
    if len(ned) > len(hay):
        return False
    found = False
    span = len(ned)
    limit = min(len(hay), 65536)
    for index in range(0, limit - span + 1):
        found = hmac.compare_digest(hay[index : index + span], ned) or found
    return found
