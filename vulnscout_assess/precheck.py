"""Find which in-scope variants still need an AI assessment for a CVE."""

from vulnscout_mcp.tools.assessments import find_ai_assessment

from .scope import Variant


def missing_variants(client, cve_id: str, variants: tuple[Variant, ...]) -> tuple[Variant, ...]:
    """Return the variants that have no AI-generated assessment for *cve_id*."""
    assessments = client.list_assessments_by_vuln(cve_id)
    return tuple(v for v in variants if find_ai_assessment(assessments, v.id) is None)


def variants_with_vuln(client, cve_id: str, variants: tuple[Variant, ...]) -> tuple[Variant, ...]:
    """Return the in-scope variants in which *cve_id* is actually present."""
    present = {v["id"] for v in client.list_variants_by_vuln(cve_id)}
    return tuple(v for v in variants if v.id in present)
