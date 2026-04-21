#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# In-container benchmark harness for VulnScout API routes.
#
# Iterates app.url_map and issues N timed GET requests against every
# idempotent route via Flask's test_client (no socket overhead). Required
# path converters (variant_id, scan_id, project_id, vulnerability_id,
# assessment_id) are filled from a single SELECT against the live DB.
#
# Output: a Markdown table on stdout sorted by ms/req desc, plus a JSON
# dump under /scan/outputs/profiles/ for downstream tooling.
#
# Designed to be wrapped by `py-spy record -- python3 -m src.bin.pyspy_bench`.
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone

# Allow `python3 -m src.bin.pyspy_bench` from /scan as well as direct invocation.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlalchemy import text  # noqa: E402

from src.bin.webapp import create_app  # noqa: E402
from src.extensions import db  # noqa: E402

DEFAULT_DB_PATH = "/cache/vulnscout/vulnscout.db"
DEFAULT_OUTPUT_DIR = "/scan/outputs/profiles"
DEFAULT_ITERATIONS = 200

# Path converters we know how to satisfy from the DB. Mapped to the table
# we pull a representative id from. Unknown converters cause the route to
# be skipped.
PARAM_TABLES = {
    "variant_id": "variants",
    "scan_id": "scans",
    "project_id": "projects",
    "vulnerability_id": "vulnerabilities",
    "assessment_id": "assessments",
    "id": None,  # generic — try variants then projects
    "doc_name": None,  # documents endpoint, filled with a sentinel
    "path": None,  # static fallthrough — skipped explicitly below
    "upload_id": None,  # async upload polling — skipped, no live id
}

# Routes excluded regardless of method / parameter resolution.
EXCLUDED_RULES = {
    "/api/scan/status",     # middleware bypass; not representative
    "/<path:path>",         # CORS OPTIONS shim
    "/static/<path:filename>",
}


def _build_param_table(app) -> dict[str, str]:
    """Pull one representative id per known parameter from the live DB."""
    out: dict[str, str] = {}
    with app.app_context():
        for param, table in PARAM_TABLES.items():
            if table is None:
                continue
            try:
                row = db.session.execute(text(f"SELECT id FROM {table} LIMIT 1")).first()
                if row is not None:
                    out[param] = str(row[0])
            except Exception as e:
                print(f"[bench] WARN: could not resolve {param} from {table}: {e}", file=sys.stderr)
    # Generic fallbacks
    if "id" not in out and "variant_id" in out:
        out["id"] = out["variant_id"]
    # /api/documents/<doc_name> — pick something the route will at least parse.
    out.setdefault("doc_name", "summary.adoc")
    return out


def _fill_path(rule, params: dict[str, str]) -> str | None:
    """Return concrete URL for a rule, or None if any required arg can't be filled."""
    try:
        kwargs = {arg: params[arg] for arg in rule.arguments}
    except KeyError:
        return None

    # Substitute <converter:name> or <name> placeholders directly in rule.rule.
    # Avoids relying on rule.build() which requires a bound URL map adapter.
    placeholder_re = re.compile(r"<(?:[^:>]+:)?([^>]+)>")

    def _sub(m: re.Match) -> str:
        return kwargs[m.group(1)]

    try:
        return placeholder_re.sub(_sub, rule.rule)
    except KeyError:
        return None


def _discover_routes(app, params: dict[str, str], filter_re: re.Pattern | None):
    """Yield (rule_string, concrete_url) for every benchmarkable GET route."""
    seen: set[str] = set()
    for rule in app.url_map.iter_rules():
        methods = rule.methods or set()
        if "GET" not in methods:
            continue
        if rule.rule in EXCLUDED_RULES:
            continue
        if rule.rule.startswith("/static/"):
            continue
        url = _fill_path(rule, params)
        if url is None:
            continue
        if filter_re and not filter_re.search(rule.rule):
            continue
        if url in seen:
            continue
        seen.add(url)
        yield rule.rule, url


def _bench_one(client, app, url: str, iterations: int) -> dict:
    # Warm-up — also tells us the response code/size and whether it errors.
    with app.app_context():
        warm = client.get(url)
    status = warm.status_code
    size = len(warm.data)

    t0 = time.perf_counter()
    for _ in range(iterations):
        with app.app_context():
            client.get(url)
    elapsed = time.perf_counter() - t0

    return {
        "url": url,
        "status": status,
        "bytes": size,
        "iterations": iterations,
        "total_s": elapsed,
        "req_per_s": iterations / elapsed if elapsed > 0 else 0.0,
        "ms_per_req": (elapsed / iterations) * 1000 if iterations > 0 else 0.0,
    }


def _setup_app(db_path: str):
    # Read-only SQLite URI so we never accidentally mutate the live DB.
    abs_db = os.path.abspath(db_path)
    if not os.path.exists(abs_db):
        raise SystemExit(f"DB not found: {abs_db}")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{abs_db}"

    # Satisfy the scan-finished middleware without touching /scan/status.txt.
    marker = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    marker.write("8 __END_OF_SCAN_SCRIPT__\n")
    marker.close()
    os.environ["FLASK_SCAN_FILE"] = marker.name

    # Suppress background enrichment threads during benchmark.
    os.environ["FLASK_TESTING"] = "True"

    app = create_app()
    app.config["TESTING"] = True
    app._INT_SCAN_FINISHED = True
    return app, marker.name


def _print_table(results: list[dict]) -> str:
    results = sorted(results, key=lambda r: r["ms_per_req"], reverse=True)
    lines = [
        "| ms/req | req/s  | status | bytes | URL |",
        "|-------:|-------:|:------:|------:|:----|",
    ]
    for r in results:
        lines.append(
            f"| {r['ms_per_req']:6.2f} | {r['req_per_s']:6.1f} "
            f"| {r['status']:^6} | {r['bytes']:5d} | `{r['url']}` |"
        )
    out = "\n".join(lines)
    print(out)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Benchmark VulnScout API routes.")
    p.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to vulnscout.db")
    p.add_argument("--iterations", "-n", type=int, default=DEFAULT_ITERATIONS,
                   help=f"Requests per route (default: {DEFAULT_ITERATIONS})")
    p.add_argument("--filter", "-f", default=None,
                   help="Regex applied to the rule string (e.g. '^/api/vulnerab')")
    p.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                   help="Directory for JSON dump (created if missing)")
    p.add_argument("--list-only", action="store_true",
                   help="Only print discovered URLs, do not benchmark")
    args = p.parse_args(argv)

    filter_re = re.compile(args.filter) if args.filter else None
    app, marker_path = _setup_app(args.db)

    try:
        params = _build_param_table(app)
        print(f"[bench] Resolved params: {params}", file=sys.stderr)

        routes = list(_discover_routes(app, params, filter_re))
        if not routes:
            print("[bench] No routes matched.", file=sys.stderr)
            return 1

        print(f"[bench] {len(routes)} route(s) to benchmark "
              f"({args.iterations} iter each).", file=sys.stderr)

        if args.list_only:
            for rule, url in routes:
                print(f"{rule}\t{url}")
            return 0

        client = app.test_client()
        results: list[dict] = []
        for i, (rule, url) in enumerate(routes, 1):
            print(f"[bench] ({i}/{len(routes)}) {url}", file=sys.stderr)
            try:
                res = _bench_one(client, app, url, args.iterations)
            except Exception as e:
                print(f"[bench] ERROR on {url}: {e}", file=sys.stderr)
                continue
            res["rule"] = rule
            results.append(res)

        os.makedirs(args.output_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(args.output_dir, f"bench_{ts}.json")
        md_path = os.path.join(args.output_dir, f"bench_{ts}.md")

        table = _print_table(results)
        with open(json_path, "w") as f:
            json.dump({
                "generated_at": ts,
                "iterations_per_route": args.iterations,
                "db": os.path.abspath(args.db),
                "results": results,
            }, f, indent=2)
        with open(md_path, "w") as f:
            f.write(table + "\n")

        print(f"\n[bench] JSON: {json_path}", file=sys.stderr)
        print(f"[bench] MD:   {md_path}", file=sys.stderr)
        return 0
    finally:
        try:
            os.unlink(marker_path)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
