# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Resolve references in one target variant's saved STRIDE model."""

from typing import Any


class RiskLinkError(ValueError):
    """The target or one of its model references cannot be resolved."""


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


def resolve_links(raw: object, model: dict | None) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        raise RiskLinkError("risk_links must be a list")
    risks, threats = _records(model, "risks"), _records(model, "threats")
    resolved = {}
    for link in raw:
        record = _resolve(link, risks, threats)
        resolved[record["risk_id"], record.get("threat_id")] = record
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
