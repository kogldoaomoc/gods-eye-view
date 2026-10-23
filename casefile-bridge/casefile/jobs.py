"""Job queue that runs tools against a selector and ingests their findings.

One job runs one tool against one selector for one case. A global worker pool
bounds how many tools run at once, and each tool has a minimum interval between
runs so a scan cannot hammer an upstream service. Results are cached by
``(tool, tool version, normalized selector)`` so repeating a pivot is instant.
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field

from . import adapters, schema
from .adapters.base import AdapterError, Cancelled, RateLimited, RunContext
from .consent import GATED_SELECTOR_TYPES, ConsentRequired, Decision, normalize_actor
from .geo import GeoResolver
from .store import CaseRegistry

QUEUED = "queued"
RUNNING = "running"
DONE = "done"
FAILED = "failed"
CANCELLED = "cancelled"


@dataclass
class Job:
    id: str
    case_id: str
    tool: str
    selector: str
    selector_type: str
    state: str = QUEUED
    message: str = ""
    created: str = field(default_factory=schema.now_iso)
    started: str | None = None
    finished: str | None = None
    found: int = 0
    actor: str = "local"
    cancel: threading.Event = field(default_factory=threading.Event)

    def snapshot(self) -> dict:
        return {
            "id": self.id,
            "caseId": self.case_id,
            "tool": self.tool,
            "selector": self.selector,
            "selectorType": self.selector_type,
            "state": self.state,
            "message": self.message,
            "found": self.found,
            "created": self.created,
            "started": self.started,
            "finished": self.finished,
        }


class JobRunner:
    def __init__(
        self,
        registry: CaseRegistry,
        *,
        resolver: GeoResolver | None = None,
        workers: int = 2,
        on_event=None,
        consent=None,
    ):
        self.registry = registry
        self.consent = consent
        self.resolver = resolver or GeoResolver()
        self._on_event = on_event or (lambda event: None)
        self._jobs: dict[str, Job] = {}
        self._queue: deque[str] = deque()
        self._lock = threading.Lock()
        self._slots = threading.Semaphore(max(1, workers))
        self._cache: dict[tuple, tuple[float, dict]] = {}
        self._last_run: dict[str, float] = {}
        self._stopping = False
        self._pump = threading.Thread(target=self._loop, name="casefile-jobs", daemon=True)
        self._pump.start()

    # -- submission ---------------------------------------------------------
    def submit(
        self,
        case_id: str,
        selector: str,
        tools: list[str] | None = None,
        *,
        selector_type: str | None = None,
        actor: str | None = None,
    ):
        self.registry.store(case_id)  # raises KeyError for an unknown case
        stype = selector_type or schema.detect_selector(selector)
        chosen = tools or adapters.default_tools(stype)
        actor = normalize_actor(actor)
        planned = []
        refused = []
        for name in chosen:
            adapter = adapters.REGISTRY.get(name)
            if not adapter or stype not in adapter.accepts:
                continue
            # Any tool on a person-identifier selector is gated, including ones
            # added later. Domain, host, IP, ASN, cert and the other
            # infrastructure types are not in GATED_SELECTOR_TYPES.
            if stype in GATED_SELECTOR_TYPES:
                if self.consent is None:
                    refused.append(Decision(False, name, "verified consent is not configured", None))
                    continue
                decision = self.consent.evaluate(case_id, name, selector, stype)
                if not decision.ok:
                    refused.append(decision)
                    continue
                planned.append((name, decision))
            else:
                planned.append((name, None))
        if refused:
            if self.consent is not None:
                for item in refused:
                    self.consent.audit(
                        case_id,
                        item.consent_id,
                        item.tool,
                        "refused",
                        selector_hash=item.selector_hash,
                        actor=actor,
                    )
            message = "; ".join(f"{item.tool}: {item.reason}" for item in refused)
            raise ConsentRequired(message, refused)
        created = []
        for name, decision in planned:
            if decision is not None and self.consent is not None:
                self.consent.audit(
                    case_id,
                    decision.consent_id,
                    name,
                    "allowed",
                    selector_hash=decision.selector_hash,
                    actor=actor,
                )
            job = Job(
                id="job_" + uuid.uuid4().hex[:12],
                case_id=case_id,
                tool=name,
                selector=selector,
                selector_type=stype,
                actor=actor,
            )
            with self._lock:
                self._jobs[job.id] = job
                self._queue.append(job.id)
            created.append(job)
            self._emit("job", job)
        return [job.snapshot() for job in created]

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.state in (DONE, FAILED, CANCELLED):
                return False
            job.cancel.set()
            if job.state == QUEUED:
                job.state = CANCELLED
                job.finished = schema.now_iso()
        if job.state == CANCELLED:
            self._emit("job", job)
        return True

    def jobs_for(self, case_id: str) -> list[dict]:
        with self._lock:
            return [job.snapshot() for job in self._jobs.values() if job.case_id == case_id]

    def stop(self) -> None:
        self._stopping = True

    # -- worker loop --------------------------------------------------------
    def _loop(self) -> None:
        while not self._stopping:
            job_id = None
            with self._lock:
                if self._queue:
                    job_id = self._queue.popleft()
            if job_id is None:
                time.sleep(0.05)
                continue
            self._slots.acquire()
            threading.Thread(target=self._run_job, args=(job_id,), daemon=True).start()

    def _run_job(self, job_id: str) -> None:
        try:
            job = self._jobs[job_id]
            if job.cancel.is_set():
                self._finish(job, CANCELLED)
                return
            self._respect_interval(job.tool)
            job.state = RUNNING
            job.started = schema.now_iso()
            self._emit("job", job)
            try:
                counts = self._execute(job)
                job.found = counts.get("entities", 0) + counts.get("updated", 0)
                self._finish(job, DONE)
            except Cancelled:
                self._finish(job, CANCELLED)
            except ConsentRequired as error:
                self._finish(job, FAILED, str(error))
            except RateLimited as error:
                self._finish(job, FAILED, f"rate limited: {error}")
            except AdapterError as error:
                self._finish(job, FAILED, str(error))
            except Exception as error:  # a tool crash must not take the bridge down
                self._finish(job, FAILED, f"unexpected error: {error}")
        finally:
            self._slots.release()

    def _execute(self, job: Job) -> dict:
        platform = None
        if job.selector_type in GATED_SELECTOR_TYPES:
            if self.consent is None:
                raise ConsentRequired("verified consent is not configured")
            # Checked again at start so a consent revoked while queued still fails,
            # and a cached result cannot skip the gate. The selector type is what
            # gates the lookup, so a new adapter cannot bypass it.
            decision = self.consent.authorize(
                job.case_id, job.tool, job.selector, job.selector_type, actor=job.actor
            )
            platform = decision.platform
        adapter = adapters.get(job.tool)
        normalized_selector = _safe_normalize(job.selector_type, job.selector)
        cache_key = (job.tool, adapter.version(), job.selector_type, normalized_selector)
        cached = self._cache.get(cache_key)
        observation_at = schema.now_iso()
        if cached and time.time() - cached[0] < adapter.ttl_s:
            native, raw_ref = cached[1]["native"], cached[1]["raw"]
        else:
            ctx = RunContext(env=None, timeout_s=adapter.timeout_s, cancel_event=job.cancel)
            try:
                native = adapter.run(job.selector, job.selector_type, ctx)
            finally:
                ctx.close()
            raw_ref = self._archive(job, native)
            self._cache[cache_key] = (time.time(), {"native": native, "raw": raw_ref})
        result = adapter.normalize(native, job.selector, job.selector_type)
        if job.tool in ("sherlock", "maigret") and platform:
            _mark_ownership(result.entities, platform)
        entities = [self.resolver.resolve(entity) for entity in result.entities]
        observation = schema.make_observation(
            job.tool, query=job.selector, tool_version=adapter.version(), confidence=adapter.confidence, raw=raw_ref, at=observation_at
        )
        store = self.registry.store(job.case_id)
        counts = store.ingest(entities, result.links, observation)
        self._emit("entities", job, extra={"counts": counts})
        return counts

    def _archive(self, job: Job, native) -> str | None:
        try:
            raw_dir = self.registry.raw_dir(job.case_id)
        except (KeyError, ValueError):
            return None
        name = f"{job.started or job.created}-{job.tool}-{job.id}.json".replace(":", "")
        path = raw_dir / name
        try:
            payload = native if isinstance(native, (dict, list)) else {"text": str(native)}
            path.write_text(json.dumps(payload, ensure_ascii=False), "utf-8")
        except (OSError, TypeError, ValueError):
            return None
        return f"{job.case_id}/raw/{name}"

    def _respect_interval(self, tool: str) -> None:
        adapter = adapters.REGISTRY.get(tool)
        interval = adapter.min_interval_s if adapter else 0
        if interval <= 0:
            return
        last = self._last_run.get(tool, 0)
        wait = interval - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        self._last_run[tool] = time.time()

    def _finish(self, job: Job, state: str, message: str = "") -> None:
        job.state = state
        job.message = message
        job.finished = schema.now_iso()
        self._emit("job", job)

    def _emit(self, kind: str, job: Job, *, extra: dict | None = None) -> None:
        event = {"kind": kind, "caseId": job.case_id, "job": job.snapshot()}
        if extra:
            event.update(extra)
        try:
            self._on_event(event)
        except Exception:
            pass


def _mark_ownership(entities: list[dict], platform: str) -> None:
    """A username proof covers one platform. Other sites stay unverified."""
    verified_key = re.sub(r"[^a-z0-9]", "", platform.casefold())
    for entity in entities:
        attrs = entity.get("attrs") if isinstance(entity.get("attrs"), dict) else {}
        site_key = re.sub(r"[^a-z0-9]", "", str(attrs.get("site") or "").casefold())
        if entity.get("type") == "username" or (verified_key and site_key == verified_key):
            entity["_ownership"] = "verified"
        else:
            entity["_ownership"] = "unverified"


def _safe_normalize(selector_type: str, selector: str) -> str:
    try:
        return schema.normalize_value(selector_type, selector)
    except schema.SchemaError:
        return selector.strip().casefold()
