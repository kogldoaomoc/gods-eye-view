"""The interface every tool adapter implements.

An adapter knows how to run one tool against one selector and how to turn
that tool's native output into entities and links. It never touches the store,
the cache or the rate policy; the job runner owns those.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .. import schema

READY = "ready"
MISSING_BINARY = "missing-binary"
MISSING_KEY = "missing-key"
BROKEN = "broken"


class AdapterError(RuntimeError):
    """The tool ran but its output could not be used."""


class RateLimited(AdapterError):
    """The upstream refused the request for rate reasons; retry later."""


class Cancelled(RuntimeError):
    """The job was cancelled while the tool ran."""


class RunContext:
    """What an adapter may use while it runs.

    Processes start in their own session so cancelling kills the tool and
    every child it spawned, not just the first process.
    """

    def __init__(self, *, env: dict | None = None, timeout_s: int = 600, cancel_event=None, fetch_json=None):
        self.env = dict(os.environ if env is None else env)
        self.timeout_s = timeout_s
        self._cancel = cancel_event
        self._fetch_json = fetch_json
        self._tmp = tempfile.TemporaryDirectory(prefix="casefile-")
        self.workdir = Path(self._tmp.name)
        self._process: subprocess.Popen | None = None

    @property
    def cancelled(self) -> bool:
        return bool(self._cancel and self._cancel.is_set())

    def run_process(self, args: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess:
        if self.cancelled:
            raise Cancelled()
        self._process = subprocess.Popen(
            args,
            cwd=self.workdir,
            env=self.env,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = self._communicate(input_text)
        finally:
            process, self._process = self._process, None
        return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)

    def _communicate(self, input_text):
        deadline_s = self.timeout_s
        step_s = 0.5
        waited = 0.0
        first = True
        while True:
            try:
                return self._process.communicate(input=input_text if first else None, timeout=step_s)
            except subprocess.TimeoutExpired:
                first = False
                waited += step_s
                if self.cancelled:
                    self.kill()
                    raise Cancelled() from None
                if waited >= deadline_s:
                    self.kill()
                    raise AdapterError(f"timed out after {deadline_s}s") from None

    def kill(self) -> None:
        process = self._process
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, 9)
            except (ProcessLookupError, PermissionError):
                process.kill()
            process.communicate()

    def fetch_json(self, url: str, *, headers: dict | None = None):
        if self.cancelled:
            raise Cancelled()
        if not self._fetch_json:
            from .. import http

            return http.fetch_json(url, headers=headers, timeout_s=min(60, self.timeout_s))
        return self._fetch_json(url, headers=headers)

    def close(self) -> None:
        self.kill()
        self._tmp.cleanup()


@dataclass
class Result:
    entities: list[dict] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)

    def add(self, entity_type: str, value, **kwargs) -> dict | None:
        """Add an entity, skipping values that do not normalize."""
        try:
            entity = schema.make_entity(entity_type, value, **kwargs)
        except schema.SchemaError:
            return None
        for index, existing in enumerate(self.entities):
            if existing["id"] == entity["id"]:
                merged = _merge(existing, entity)
                self.entities[index] = merged
                return merged
        self.entities.append(entity)
        return entity

    def link(self, source: dict | None, target: dict | None, relation: str) -> None:
        if not source or not target or source["id"] == target["id"]:
            return
        link = schema.make_link(source["id"], target["id"], relation)
        if all(existing["id"] != link["id"] for existing in self.links):
            self.links.append(link)


def _merge(current: dict, incoming: dict) -> dict:
    merged = dict(current)
    if "geo" not in merged and "geo" in incoming:
        merged["geo"] = incoming["geo"]
    if incoming.get("attrs"):
        merged["attrs"] = {**incoming["attrs"], **(current.get("attrs") or {})}
    if merged.get("label") == merged.get("value") and incoming.get("label") != incoming.get("value"):
        merged["label"] = incoming["label"]
    return merged


class Adapter:
    """Base class. Subclasses set the class attributes and implement ``run``."""

    name: str = ""
    title: str = ""
    accepts: tuple[str, ...] = ()
    # Unmaintained tools: off by default, still listed with their health.
    legacy: bool = False
    # Executables, any one of which satisfies the requirement.
    binaries: tuple[str, ...] = ()
    # Environment variable naming a binary path that overrides ``binaries``.
    binary_env: str | None = None
    # Environment variables that must all be set.
    env_keys: tuple[str, ...] = ()
    homepage: str = ""
    licence: str = ""
    ttl_s: int = 24 * 3600
    timeout_s: int = 600
    # Minimum seconds between two runs of this tool.
    min_interval_s: float = 0.0
    confidence: float = 0.6

    def binary(self, env: dict | None = None) -> str | None:
        env = os.environ if env is None else env
        if self.binary_env and env.get(self.binary_env):
            override = env[self.binary_env]
            return shutil.which(override) or (override if os.path.isfile(override) else None)
        for candidate in self.binaries:
            found = shutil.which(candidate)
            if found:
                return found
        return None

    def health(self, env: dict | None = None) -> dict:
        env = os.environ if env is None else env
        missing = [key for key in self.env_keys if not env.get(key)]
        if missing:
            return {"state": MISSING_KEY, "reason": "set " + ", ".join(missing)}
        if self.binaries and not self.binary(env):
            hint = self.binary_env or self.binaries[0]
            return {"state": MISSING_BINARY, "reason": f"install {self.binaries[0]} or set {hint}"}
        return {"state": READY, "reason": ""}

    def version(self, env: dict | None = None) -> str | None:
        return None

    def describe(self, env: dict | None = None) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "accepts": list(self.accepts),
            "legacy": self.legacy,
            "homepage": self.homepage,
            "licence": self.licence,
            **self.health(env),
        }

    def run(self, selector: str, selector_type: str, ctx) -> object:
        """Run the tool and return its native output (parsed JSON or text)."""
        raise NotImplementedError

    def normalize(self, native, selector: str, selector_type: str) -> Result:
        """Turn native output into entities and links."""
        raise NotImplementedError
