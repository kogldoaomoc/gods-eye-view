"""Sherlock adapter.

Hunts a username across sites. Sherlock prints ``[+] Site: URL`` for each
account it finds; with ``--print-found --no-color`` that is easy to parse. The
accounts have no geography, so they live in the case panel, not on the map,
unless a later pivot geolocates one.
"""

from __future__ import annotations

import re

from .base import Adapter, AdapterError, Result

_FOUND_RE = re.compile(r"^\[\+\]\s*([^:]+):\s*(\S+)\s*$")


class SherlockAdapter(Adapter):
    name = "sherlock"
    title = "Sherlock"
    accepts = ("username",)
    binaries = ("sherlock",)
    binary_env = "CASEFILE_SHERLOCK_BIN"
    homepage = "https://github.com/sherlock-project/sherlock"
    licence = "MIT"
    timeout_s = 600
    confidence = 0.5

    def run(self, selector, selector_type, ctx):
        binary = self.binary(ctx.env)
        if not binary:
            raise AdapterError("Sherlock is not installed")
        completed = ctx.run_process([binary, "--print-found", "--no-color", "--timeout", "15", selector])
        if completed.returncode not in (0, 1) and not completed.stdout.strip():
            raise AdapterError(completed.stderr.strip()[:300] or "Sherlock failed")
        return completed.stdout

    def normalize(self, native, selector, selector_type):
        result = Result()
        username = result.add("username", selector)
        for line in str(native).splitlines():
            match = _FOUND_RE.match(line.strip())
            if not match:
                continue
            site, url = match.group(1).strip(), match.group(2).strip()
            account = result.add("account", url, label=f"{site}: {selector}", attrs={"site": site})
            result.link(username, account, "same_as")
        return result
