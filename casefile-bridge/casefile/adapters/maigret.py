"""Maigret adapter.

Like Sherlock but richer: ``maigret USERNAME -J simple -fo DIR`` writes
``report_USERNAME_simple.json`` mapping each site to a status and the found
profile URL, sometimes with extracted fields such as a stated location. Those
location strings are weak, so they are kept as address entities for the
geocoder to place, never as direct pins.
"""

from __future__ import annotations

import json

from .base import Adapter, AdapterError, Result


class MaigretAdapter(Adapter):
    name = "maigret"
    title = "Maigret"
    accepts = ("username",)
    binaries = ("maigret",)
    binary_env = "CASEFILE_MAIGRET_BIN"
    homepage = "https://github.com/soxoj/maigret"
    licence = "MIT"
    timeout_s = 900
    confidence = 0.5

    def run(self, selector, selector_type, ctx):
        binary = self.binary(ctx.env)
        if not binary:
            raise AdapterError("Maigret is not installed")
        completed = ctx.run_process([binary, selector, "-J", "simple", "-fo", str(ctx.workdir), "--timeout", "15"])
        report = ctx.workdir / f"report_{selector}_simple.json"
        if not report.exists():
            matches = list(ctx.workdir.glob("report_*_simple.json"))
            report = matches[0] if matches else report
        if not report.exists():
            raise AdapterError(completed.stderr.strip()[:300] or "Maigret wrote no report")
        try:
            return json.loads(report.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise AdapterError(f"could not read Maigret report: {error}") from None

    def normalize(self, native, selector, selector_type):
        result = Result()
        username = result.add("username", selector)
        sites = native if isinstance(native, dict) else {}
        for site, info in sites.items():
            if not isinstance(info, dict):
                continue
            status = str(info.get("status", "")).lower()
            url = info.get("url_user") or info.get("url")
            if "claimed" not in status and "found" not in status and not url:
                continue
            account = result.add(
                "account", url or f"{site}:{selector}", label=f"{site}: {selector}", attrs={"site": site}
            )
            result.link(username, account, "same_as")
            fields = info.get("ids") or info.get("fields") or {}
            location = fields.get("location") or fields.get("city")
            if location:
                result.link(account, result.add("address", str(location)), "located_at")
        return result
