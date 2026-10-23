"""Loopback HTTP API for the casefile bridge.

Binds 127.0.0.1 only. When ``CASEFILE_BRIDGE_TOKEN`` is set, every request must
carry it in ``X-Casefile-Token``; the God's Eye View server provider adds it.
The browser never talks to this server directly — only the GEV server relays to
it — so this is defence in depth, not the only gate.
"""

from __future__ import annotations

import json
import os
import queue
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__, adapters, schema
from .consent import ConsentError, ConsentRequired, open_consent
from .export import case_to_geojson
from .jobs import JobRunner
from .store import CaseRegistry

MAX_BODY_BYTES = 1 * 1024 * 1024


class EventBroker:
    """Fan-out of job/entity events to per-case Server-Sent Event listeners."""

    def __init__(self):
        self._subscribers: dict[str, set[queue.Queue]] = {}
        self._lock = threading.Lock()

    def publish(self, event: dict) -> None:
        case_id = event.get("caseId")
        with self._lock:
            targets = list(self._subscribers.get(case_id, ()))
        for channel in targets:
            try:
                channel.put_nowait(event)
            except queue.Full:
                pass

    def subscribe(self, case_id: str) -> queue.Queue:
        channel: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.setdefault(case_id, set()).add(channel)
        return channel

    def unsubscribe(self, case_id: str, channel: queue.Queue) -> None:
        with self._lock:
            listeners = self._subscribers.get(case_id)
            if listeners:
                listeners.discard(channel)
                if not listeners:
                    self._subscribers.pop(case_id, None)


class Bridge:
    """Holds the registry, job runner and event broker for the handlers."""

    def __init__(self, store_root: str, *, token: str | None = None, workers: int = 2, consent=None):
        self.registry = CaseRegistry(store_root)
        self.broker = EventBroker()
        self.consent = consent or open_consent(store_root)
        self.runner = JobRunner(self.registry, workers=workers, on_event=self.broker.publish, consent=self.consent)
        self.token = token

    def close(self) -> None:
        self.runner.stop()
        self.consent.close()
        self.registry.close()


_CASE = r"(?P<case>case_[a-z0-9]{12})"
_ENTITY = r"(?P<entity>ent_[a-z0-9]{24})"
_JOB = r"(?P<job>job_[a-z0-9]{12})"
_VER = r"(?P<ver>ver_[a-z0-9]{12})"
_CONSENT = r"(?P<consent>cns_[a-z0-9]{12})"


class Handler(BaseHTTPRequestHandler):
    bridge: Bridge = None  # set by make_server
    protocol_version = "HTTP/1.1"
    server_version = f"casefile-bridge/{__version__}"

    def log_message(self, *args):  # keep the console quiet
        pass

    # -- helpers ------------------------------------------------------------
    def _authorized(self) -> bool:
        token = self.bridge.token
        return not token or self.headers.get("X-Casefile-Token") == token

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8")) or {}
        except (ValueError, UnicodeDecodeError):
            return {}

    # -- dispatch -----------------------------------------------------------
    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def do_HEAD(self):
        self._dispatch("GET")

    def _dispatch(self, method: str):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        if path == "/api/health":
            return self._send(200, {"ok": True, "version": __version__})
        if not self._authorized():
            return self._send(401, {"error": "bad token"})
        try:
            self._route(method, path, query)
        except ConsentRequired as error:
            self._send(403, {"error": str(error), "refused": [
                {"tool": item.tool, "error": item.reason, "consentId": item.consent_id}
                for item in error.refused
            ]})
        except ConsentError as error:
            self._send(error.status, {"error": str(error)})
        except KeyError:
            self._send(404, {"error": "case or entity not found"})
        except ValueError as error:
            self._send(400, {"error": str(error)})
        except BrokenPipeError:
            pass

    def _route(self, method: str, path: str, query: dict):
        bridge = self.bridge
        if path == "/api/tools" and method == "GET":
            return self._send(200, {"tools": adapters.describe(), "routing": adapters.DEFAULT_ROUTING})
        if path == "/api/cases":
            if method == "GET":
                return self._send(200, {"cases": bridge.registry.list_cases()})
            if method == "POST":
                name = str(self._read_json().get("name", "")).strip()
                return self._send(201, bridge.registry.create(name))
        match = re.fullmatch(rf"/api/cases/{_CASE}", path)
        if match:
            case_id = match["case"]
            if method == "GET":
                return self._send(200, bridge.registry.describe(case_id))
            if method == "DELETE":
                return self._send(200, {"deleted": bridge.registry.delete(case_id)})
        match = re.fullmatch(rf"/api/cases/{_CASE}/entities", path)
        if match and method == "GET":
            return self._entities(match["case"], query)
        match = re.fullmatch(rf"/api/cases/{_CASE}/entities/{_ENTITY}", path)
        if match and method == "GET":
            entity = bridge.registry.store(match["case"]).get_entity(match["entity"])
            if not entity:
                raise KeyError(match["entity"])
            return self._send(200, entity)
        match = re.fullmatch(rf"/api/cases/{_CASE}/entities/{_ENTITY}/flags", path)
        if match and method == "POST":
            body = self._read_json()
            ok = bridge.registry.store(match["case"]).set_flag(
                match["entity"], hidden=body.get("hidden"), verified=body.get("verified")
            )
            return self._send(200, {"updated": ok})
        match = re.fullmatch(rf"/api/cases/{_CASE}/jobs", path)
        if match:
            case_id = match["case"]
            if method == "GET":
                return self._send(200, {"jobs": bridge.runner.jobs_for(case_id)})
            if method == "POST":
                body = self._read_json()
                selector = str(body.get("selector", "")).strip()
                if not selector:
                    raise ValueError("selector is required")
                jobs = bridge.runner.submit(
                    case_id, selector, body.get("tools"), selector_type=body.get("selectorType")
                )
                return self._send(202, {"jobs": jobs})
        match = re.fullmatch(rf"/api/cases/{_CASE}/verifications", path)
        if match:
            case_id = match["case"]
            bridge.registry.store(case_id)
            if method == "GET":
                return self._send(200, {"verifications": bridge.consent.list_verifications(case_id)})
            if method == "POST":
                created = bridge.consent.create_package(case_id, self._read_json())
                return self._send(201, {"verifications": created})
        match = re.fullmatch(rf"/api/cases/{_CASE}/verifications/{_VER}/confirm", path)
        if match and method == "POST":
            case_id = match["case"]
            bridge.registry.store(case_id)
            body = self._read_json()
            consent = bridge.consent.confirm(
                case_id,
                match["ver"],
                code=body.get("code"),
                oauth_code=body.get("oauthCode"),
                state=body.get("state"),
            )
            return self._send(200, {"consent": consent})
        match = re.fullmatch(rf"/api/cases/{_CASE}/consents", path)
        if match and method == "GET":
            case_id = match["case"]
            bridge.registry.store(case_id)
            return self._send(200, {"consents": bridge.consent.list_consents(case_id)})
        match = re.fullmatch(rf"/api/cases/{_CASE}/consents/{_CONSENT}/revoke", path)
        if match and method == "POST":
            case_id = match["case"]
            bridge.registry.store(case_id)
            return self._send(200, {"consent": bridge.consent.revoke(case_id, match["consent"])})
        match = re.fullmatch(rf"/api/jobs/{_JOB}", path)
        if match and method == "DELETE":
            return self._send(200, {"cancelled": bridge.runner.cancel(match["job"])})
        match = re.fullmatch(rf"/api/cases/{_CASE}/export\.geojson", path)
        if match and method == "GET":
            store = bridge.registry.store(match["case"])
            return self._send(200, case_to_geojson(store))
        match = re.fullmatch(rf"/api/cases/{_CASE}/events", path)
        if match and method == "GET":
            return self._events(match["case"])
        self._send(404, {"error": "no such route"})

    def _entities(self, case_id: str, query: dict):
        store = self.bridge.registry.store(case_id)
        bbox = _parse_bbox(query.get("bbox", [None])[0])
        types = _csv(query.get("types", [None])[0])
        entities = store.query_entities(
            bbox=bbox,
            types=types or None,
            min_confidence=float(query.get("minConfidence", [0])[0] or 0),
            text=(query.get("text", [None])[0] or None),
            limit=int(query.get("limit", [2000])[0] or 2000),
        )
        self._send(200, {"entities": entities, "counts": store.counts()})

    def _events(self, case_id: str):
        self.bridge.registry.store(case_id)
        channel = self.bridge.broker.subscribe(case_id)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    event = channel.get(timeout=20)
                    self.wfile.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.bridge.broker.unsubscribe(case_id, channel)


def _parse_bbox(value):
    if not value:
        return None
    parts = value.split(",")
    if len(parts) != 4:
        raise ValueError("bbox must be minLon,minLat,maxLon,maxLat")
    try:
        return tuple(float(part) for part in parts)
    except ValueError:
        raise ValueError("bbox values must be numbers") from None


def _csv(value):
    return [item.strip() for item in value.split(",") if item.strip()] if value else []


def make_server(store_root: str, *, host: str = "127.0.0.1", port: int = 7733, token: str | None = None, workers: int = 2, consent=None):
    bridge = Bridge(store_root, token=token, workers=workers, consent=consent)
    handler = type("BoundHandler", (Handler,), {"bridge": bridge})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.bridge = bridge
    return httpd


def serve(store_root: str, *, host: str = "127.0.0.1", port: int = 7733, token: str | None = None, workers: int = 2):
    httpd = make_server(store_root, host=host, port=port, token=token, workers=workers)
    print(f"casefile-bridge {__version__} listening on http://{host}:{port} (store: {store_root})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.bridge.close()
        httpd.server_close()
