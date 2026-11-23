# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Resolve references in one target variant's saved STRIDE model."""

import hashlib
import json
import re
from typing import Any, TypedDict, cast

from .stride_model import MAX_ROWS, MAX_TEXT

MAX_LINKS_PER_TARGET = 16
MAX_SNAPSHOT_BYTES = 256 * 1024


class RiskLinkError(ValueError):
    """The target or one of its model references cannot be resolved."""


class _RiskSnapshot(TypedDict):
    risk_id: str
    risk_description: str


class RiskSnapshot(_RiskSnapshot, total=False):
    threat_id: str
    threat_description: str
    threat_target_ids: list[str]


def _sorted_target_ids(raw: object) -> list[str]:
    if (not isinstance(raw, list) or len(raw) > 2 * MAX_ROWS
            or any(not isinstance(v, str) or not re.fullmatch(r"[CI][1-9]\d*", v) for v in raw)
            or len(set(raw)) != len(raw)):
        raise RiskLinkError("Invalid modeled threat target IDs")
    return sorted(raw)


def _check_count(raw: object) -> list:
    if not isinstance(raw, list) or len(raw) > MAX_LINKS_PER_TARGET:
        raise RiskLinkError(f"risk_links must be a list of at most {MAX_LINKS_PER_TARGET} references")
    return raw


def charge_snapshots(remaining: int, links: list[RiskSnapshot]) -> int:
    if links:
        remaining -= len(json.dumps(links, separators=(",", ":")).encode())
    if remaining < 0:
        raise RiskLinkError("Assessment exceeds the modeled risk snapshot byte limit")
    return remaining


def portable_snapshots(raw: object) -> list[RiskSnapshot]:
    """Validate stored evidence without resolving IDs against the destination model."""
    links = _check_count(raw)
    seen = set()
    result = []
    for link in links:
        if not isinstance(link, dict):
            raise RiskLinkError("Invalid modeled risk snapshot")
        fields = {"risk_id", "risk_description"}
        if "threat_id" in link:
            fields.update(("threat_id", "threat_description"))
        values = dict(link)
        # A missing field in a legacy snapshot is unknown, not an empty set.
        targets = (_sorted_target_ids(values.pop("threat_target_ids"))
                   if "threat_id" in link and "threat_target_ids" in link else None)
        if set(values) != fields or any(not isinstance(v, str) for v in values.values()):
            raise RiskLinkError("Invalid modeled risk snapshot fields")
        if any(len(link[k]) > MAX_TEXT for k in fields if k.endswith("_description")):
            raise RiskLinkError("Modeled risk snapshot description is too long")
        pair = (link["risk_id"], link.get("threat_id"))
        if (not re.fullmatch(r"R[1-9]\d*", pair[0])
                or (pair[1] is not None and not re.fullmatch(r"T[1-9]\d*", pair[1])) or pair in seen):
            raise RiskLinkError("Invalid or repeated modeled risk snapshot IDs")
        seen.add(pair)
        if targets is not None:
            values["threat_target_ids"] = targets
        result.append(cast(RiskSnapshot, values))
    return result


def _revision(record: RiskSnapshot) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()


def preview_link(ids: dict[str, str], model: dict | None) -> dict[str, Any]:
    record = resolve_links([ids], model)[0]
    return {**record, "revision": _revision(record)}


def _records(model: dict | None, section: str) -> dict[str, dict]:
    rows = model.get(section) if isinstance(model, dict) else None
    if not isinstance(rows, list):
        return {}
    return {r["id"]: r for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)}


def _resolve(link: object, risks: dict[str, dict], threats: dict[str, dict]) -> RiskSnapshot:
    if not isinstance(link, dict) or link.keys() - {"risk_id", "threat_id"}:
        raise RiskLinkError("Expected risk_id and optional threat_id")
    rid = link.get("risk_id")
    if not isinstance(rid, str) or rid not in risks:
        raise RiskLinkError("Unknown modeled risk for this variant")
    risk = risks[rid]
    record: RiskSnapshot = {"risk_id": rid, "risk_description": risk.get("description") or ""}
    if "threat_id" in link:
        tid = link["threat_id"]
        associated = risk.get("threat_ids")
        if not isinstance(tid, str) or tid not in threats or not isinstance(associated, list) or tid not in associated:
            raise RiskLinkError("Threat is not associated with this modeled risk in this variant")
        record["threat_id"] = tid
        record["threat_description"] = threats[tid].get("description") or ""
        record["threat_target_ids"] = _sorted_target_ids(threats[tid].get("target_ids"))
    return record


def resolve_links(
    raw: object, model: dict | None, *, confirmed: set[tuple[str, str | None]] | None = None,
) -> list[RiskSnapshot]:
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


def describe_links(stored: list[RiskSnapshot], model: dict | None) -> list[dict[str, Any]]:
    """Keep reviewed descriptions visible even when the model removes or reuses an ID."""
    links = []
    risks, threats = _records(model, "risks"), _records(model, "threats")
    for record in stored:
        ids = {"risk_id": record["risk_id"]}
        if "threat_id" in record:
            ids["threat_id"] = record["threat_id"]
        try:
            stale = _resolve(ids, risks, threats) != record
        except RiskLinkError:
            stale = True
        links.append({**record, "stale": stale})
    return links
