"""Command line entry point: ``python -m casefile``."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .export import case_to_geojson
from .store import CaseRegistry

DEFAULT_STORE = os.environ.get("CASEFILE_STORE", os.path.join(os.getcwd(), ".gev-cache", "casefile"))


def _serve(args) -> int:
    from .server import serve

    serve(
        args.store,
        host=args.host,
        port=args.port,
        token=args.token or os.environ.get("CASEFILE_BRIDGE_TOKEN"),
        workers=args.workers,
    )
    return 0


def _export(args) -> int:
    registry = CaseRegistry(args.store)
    try:
        store = registry.store(args.case)
    except KeyError:
        print(f"no such case: {args.case}", file=sys.stderr)
        return 1
    geojson = case_to_geojson(store, include_hidden=args.include_hidden, min_confidence=args.min_confidence)
    text = json.dumps(geojson, indent=2 if args.pretty else None)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"wrote {len(geojson['features'])} features to {args.output}")
    else:
        print(text)
    registry.close()
    return 0


def _cases(args) -> int:
    registry = CaseRegistry(args.store)
    for case in registry.list_cases():
        total = sum(case["counts"].values())
        print(f"{case['id']}  {case['name']}  ({total} entities)")
    registry.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="casefile", description="Casefile research bridge for God's Eye View.")
    parser.add_argument("--version", action="version", version=f"casefile-bridge {__version__}")
    parser.add_argument("--store", default=DEFAULT_STORE, help="case store directory")
    sub = parser.add_subparsers(dest="command", required=True)

    serve_cmd = sub.add_parser("serve", help="run the HTTP API")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=7733)
    serve_cmd.add_argument("--token", default=None)
    serve_cmd.add_argument("--workers", type=int, default=2)
    serve_cmd.set_defaults(func=_serve)

    export_cmd = sub.add_parser("export", help="export a case as GeoJSON")
    export_cmd.add_argument("case")
    export_cmd.add_argument("-o", "--output")
    export_cmd.add_argument("--pretty", action="store_true")
    export_cmd.add_argument("--include-hidden", action="store_true")
    export_cmd.add_argument("--min-confidence", type=float, default=0.0)
    export_cmd.set_defaults(func=_export)

    cases_cmd = sub.add_parser("cases", help="list cases")
    cases_cmd.set_defaults(func=_cases)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
