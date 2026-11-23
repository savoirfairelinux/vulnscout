# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Resolve references in one target variant's saved STRIDE model."""

import hashlib
import json
import re
from typing import Any

from .stride_model import MAX_TEXT

MAX_LINKS_PER_TARGET = 16
MAX_SNAPSHOT_BYTES = 256 * 1024


class RiskLinkError(ValueError):
    """The target or one of its model references cannot be resolved."""


def _check_count(raw: object) -> list:
    if not isinstance(raw, list) or len(raw) > MAX_LINKS_PER_TARGET:
        raise RiskLinkError(f"risk_links must be a list of at most {MAX_LINKS_PER_TARGET} references")
    return raw


def charge_snapshots(remaining: int, links: list[dict[str, str]]) -> int:
    if links:
        remaining -= len(json.dumps(links, separators=(",", ":")).encode())
    if remaining < 0:
        raise RiskLinkError("Assessment exceeds the modeled risk snapshot byte limit")
    return remaining


def portable_snapshots(raw: object) -> list[dict[str, str]]:
    """Validate stored evidence without resolving IDs against the destination model."""
    links = _check_count(raw)
    seen = set()
    for link in links:
        if not isinstance(link, dict):
            raise RiskLinkError("Invalid modeled risk snapshot")
        fields = {"risk_id", "risk_description"}
        if "threat_id" in link:
            fields.update(("threat_id", "threat_description"))
        if set(link) != fields or any(not isinstance(v, str) for v in link.values()):
            raise RiskLinkError("Invalid modeled risk snapshot fields")
        if any(len(link[k]) > MAX_TEXT for k in fields if k.endswith("_description")):
            raise RiskLinkError("Modeled risk snapshot description is too long")
        pair = (link["risk_id"], link.get("threat_id"))
        if (not re.fullmatch(r"R[1-9]\d*", pair[0])
                or (pair[1] is not None and not re.fullmatch(r"T[1-9]\d*", pair[1])) or pair in seen):
            raise RiskLinkError("Invalid or repeated modeled risk snapshot IDs")
        seen.add(pair)
    return links


def _revision(record: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()


def preview_link(ids: dict[str, str], model: dict | None) -> dict[str, str]:
    record = resolve_links([ids], model)[0]
    return {**record, "revision": _revision(record)}


def _records(model: dict | None, section: str) -> dict[str, dict]:
    rows = model.get(section) if isinstance(model, dict) else None
    if not isinstance(rows, list):
        return {}
    return {r["id"]: r for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)}


def _resolve(link: object, risks: dict[str, dict], threats: dict[str, dict]) -> dict[str, str]:
    if not isinstance(link, dict) or link.keys() - {"risk_id", "threat_id"}:
        raise RiskLinkError("Expected risk_id and optional threat_id")
    rid = link.get("risk_id")
    if not isinstance(rid, str) or rid not in risks:
        raise RiskLinkError("Unknown modeled risk for this variant")
    risk = risks[rid]
    record = {"risk_id": rid, "risk_description": risk.get("description") or ""}
    if "threat_id" in link:
        tid = link["threat_id"]
        associated = risk.get("threat_ids")
        if not isinstance(tid, str) or tid not in threats or not isinstance(associated, list) or tid not in associated:
            raise RiskLinkError("Threat is not associated with this modeled risk in this variant")
        record.update(threat_id=tid, threat_description=threats[tid].get("description") or "")
    return record


def resolve_links(
    raw: object, model: dict | None, *, confirmed: set[tuple[str, str | None]] | None = None,
) -> list[dict[str, str]]:
    links = _check_count(raw)
    risks, threats = _records(model, "risks"), _records(model, "threats")
    resolved = {}
    for link in links:
        check_revision = confirmed is not None and isinstance(link, dict) and "confirmed_revision" in link
        ids = {k: v for k, v in link.items() if k != "confirmed_revision"} if check_revision else link
        record = _resolve(ids, risks, threats)
        pair = (record["risk_id"], record.get("threat_id"))
        if check_revision and confirmed is not None:
            if link["confirmed_revision"] != _revision(record):
                raise RiskLinkError("Modeled risk changed; reload before reconfirming")
            confirmed.add(pair)
        resolved[pair] = record
    return list(resolved.values())


def describe_links(stored: list[dict[str, str]], model: dict | None) -> list[dict[str, Any]]:
    """Keep reviewed descriptions visible even when the model removes or reuses an ID."""
    links = []
    risks, threats = _records(model, "risks"), _records(model, "threats")
    for record in stored:
        ids = {key: record[key] for key in ("risk_id", "threat_id") if key in record}
        try:
            stale = _resolve(ids, risks, threats) != record
        except RiskLinkError:
            stale = True
        links.append({**record, "stale": stale})
    return links
