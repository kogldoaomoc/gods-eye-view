"""Small JSON-over-HTTPS client for adapters that call web APIs directly."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import __version__

USER_AGENT = f"casefile-bridge/{__version__}"
MAX_BODY_BYTES = 20 * 1024 * 1024


class HttpError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


def fetch_json(url: str, *, headers: dict | None = None, timeout_s: float = 30):
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": USER_AGENT, **(headers or {})}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            body = response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as error:
        detail = ""
        try:
            detail = json.loads(error.read(65536).decode("utf-8", "replace")).get("error", "")
        except (ValueError, AttributeError):
            pass
        raise HttpError(error.code, detail or error.reason or "request failed") from None
    if len(body) > MAX_BODY_BYTES:
        raise HttpError(502, "response too large")
    return json.loads(body.decode("utf-8"))
