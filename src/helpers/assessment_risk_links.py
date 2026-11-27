# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Resolve references in one target variant's saved STRIDE model."""

import hashlib
import json
from typing import Any, TypedDict, cast

from .stride_model import COMPONENT_ID, INTERACTION_ID, MAX_ROWS, MAX_TEXT, RISK_ID, THREAT_ID, matches_model_id

MAX_LINKS_PER_TARGET = 16
MAX_SNAPSHOT_BYTES = 256 * 1024


class RiskLinkError(ValueError):
    """The target or one of its model references cannot be resolved."""


class _RiskSnapshot(TypedDict):
    risk_id: str
    risk_description: str


class InteractionEndpoints(TypedDict):
    source_id: str
    destination_id: str


class RiskSnapshot(_RiskSnapshot, total=False):
    threat_id: str
    threat_description: str
    threat_target_ids: list[str]
    interaction_endpoints: dict[str, InteractionEndpoints]


def _sorted_target_ids(raw: object) -> list[str]:
    if (not isinstance(raw, list) or len(raw) > 2 * MAX_ROWS
            or any(not matches_model_id(v, COMPONENT_ID, INTERACTION_ID) for v in raw)
            or len(set(raw)) != len(raw)):
        raise RiskLinkError("Invalid modeled threat target IDs")
    return sorted(raw)


def _check_count(raw: object) -> list:
    if not isinstance(raw, list) or len(raw) > MAX_LINKS_PER_TARGET:
        raise RiskLinkError(f"risk_links must be a list of at most {MAX_LINKS_PER_TARGET} references")
    return raw


def _endpoints(raw: object, ids: list[str]) -> dict[str, InteractionEndpoints]:
    if not isinstance(raw, dict) or len(raw) > MAX_ROWS or raw.keys() != set(ids):
        raise RiskLinkError("Expected endpoints for each linked interaction")
    result: dict[str, InteractionEndpoints] = {}
    for interaction in ids:
        ends = raw[interaction]
        if (not isinstance(ends, dict) or ends.keys() != {"source_id", "destination_id"}
                or any(not matches_model_id(v, COMPONENT_ID) for v in ends.values())
                or ends["source_id"] == ends["destination_id"]):
            raise RiskLinkError("Invalid modeled interaction endpoints")
        result[interaction] = {"source_id": ends["source_id"], "destination_id": ends["destination_id"]}
    return result


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
        interaction_ids = [t for t in targets or [] if t.startswith("I")]
        endpoints = (_endpoints(values.pop("interaction_endpoints"), interaction_ids)
                     if interaction_ids and "interaction_endpoints" in values else None)
        if set(values) != fields or any(not isinstance(v, str) for v in values.values()):
            raise RiskLinkError("Invalid modeled risk snapshot fields")
        if any(len(link[k]) > MAX_TEXT for k in fields if k.endswith("_description")):
            raise RiskLinkError("Modeled risk snapshot description is too long")
        pair = (link["risk_id"], link.get("threat_id"))
        if (not matches_model_id(pair[0], RISK_ID)
                or (pair[1] is not None and not matches_model_id(pair[1], THREAT_ID)) or pair in seen):
            raise RiskLinkError("Invalid or repeated modeled risk snapshot IDs")
        seen.add(pair)
        if targets is not None:
            values["threat_target_ids"] = targets
        if endpoints is not None:
            values["interaction_endpoints"] = endpoints
        result.append(cast(RiskSnapshot, values))
    return result


def _revision(record: RiskSnapshot) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()


def preview_link(ids: dict[str, str], model: dict | None) -> dict[str, Any]:
    record = resolve_links([ids], RiskModelIndex(model))[0]
    return {**record, "revision": _revision(record)}


def _records(model: dict | None, section: str) -> dict[str, dict]:
    rows = model.get(section) if isinstance(model, dict) else None
    if not isinstance(rows, list):
        return {}
    return {r["id"]: r for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)}


class RiskModelIndex:
    """Index each referenced section of one variant's model on first use."""

    def __init__(self, model: dict | None):
        self.model = model
        self.sections: dict[str, dict[str, dict]] = {}

    def records(self, section: str) -> dict[str, dict]:
        if section not in self.sections:
            self.sections[section] = _records(self.model, section)
        return self.sections[section]


def _resolve(link: object, index: RiskModelIndex) -> RiskSnapshot:
    if not isinstance(link, dict) or link.keys() - {"risk_id", "threat_id"}:
        raise RiskLinkError("Expected risk_id and optional threat_id")
    rid = link.get("risk_id")
    risks = index.records("risks")
    if not isinstance(rid, str) or rid not in risks:
        raise RiskLinkError("Unknown modeled risk for this variant")
    risk = risks[rid]
    record: RiskSnapshot = {"risk_id": rid, "risk_description": risk.get("description") or ""}
    if "threat_id" in link:
        threats = index.records("threats")
        tid = link["threat_id"]
        associated = risk.get("threat_ids")
        if not isinstance(tid, str) or tid not in threats or not isinstance(associated, list) or tid not in associated:
            raise RiskLinkError("Threat is not associated with this modeled risk in this variant")
        record["threat_id"] = tid
        record["threat_description"] = threats[tid].get("description") or ""
        record["threat_target_ids"] = _sorted_target_ids(threats[tid].get("target_ids"))
        interaction_ids = [t for t in record["threat_target_ids"] if t.startswith("I")]
        if interaction_ids:
            interactions = index.records("interactions")
            record["interaction_endpoints"] = _endpoints({
                i: {k: interactions.get(i, {}).get(k) for k in ("source_id", "destination_id")}
                for i in interaction_ids
            }, interaction_ids)
    return record


def resolve_links(
    raw: object, index: RiskModelIndex, *, confirmed: set[tuple[str, str | None]] | None = None,
) -> list[RiskSnapshot]:
    links = _check_count(raw)
    resolved = {}
    for link in links:
        check_revision = confirmed is not None and isinstance(link, dict) and "confirmed_revision" in link
        ids = {k: v for k, v in link.items() if k != "confirmed_revision"} if check_revision else link
        record = _resolve(ids, index)
        pair = (record["risk_id"], record.get("threat_id"))
        if check_revision and confirmed is not None:
            if link["confirmed_revision"] != _revision(record):
                raise RiskLinkError("Modeled risk changed; reload before reconfirming")
            confirmed.add(pair)
        resolved[pair] = record
    return list(resolved.values())


def describe_links(stored: list[RiskSnapshot], index: RiskModelIndex) -> list[dict[str, Any]]:
    """Keep reviewed descriptions visible even when the model removes or reuses an ID."""
    links = []
    for record in stored:
        ids = {"risk_id": record["risk_id"]}
        if "threat_id" in record:
            ids["threat_id"] = record["threat_id"]
        try:
            stale = _resolve(ids, index) != record
        except RiskLinkError:
            stale = True
        links.append({**record, "stale": stale})
    return links
