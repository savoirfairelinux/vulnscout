"""Read-only upstream maintenance signal (OpenSSF Scorecard) for an exact package."""

import json

from vulnscout_mcp.client import VulnScoutClient, VulnScoutError

EVIDENCE_NOTE = (
    "OpenSSF Scorecard rates the upstream maintainers' practices; it is context, "
    "not evidence that this package is or is not affected by a vulnerability"
)


def _package_health_impl(client: VulnScoutClient, variant_id: str, package_id: str) -> str:
    try:
        data = client.get_package_health(variant_id, package_id)
        health = data["packages"].get(package_id)
        return json.dumps({
            "variant_id": variant_id, "package_id": package_id,
            "lookups_enabled": data.get("enabled") is not False,
            "resolved": health is not None, "health": health, "evidence": EVIDENCE_NOTE,
        }, ensure_ascii=True)
    except VulnScoutError as exc:
        return f"Error: {exc}"


def register_tools(server, client: VulnScoutClient) -> None:
    @server.tool()
    def get_package_health(variant_id: str, package_id: str) -> str:
        """Read the cached upstream repository and OpenSSF Scorecard result for an exact package ID.

        repository_source tells how the repository was found: sbom, deps_dev, osv (CVE fix
        data, inferred) or none. scorecard.status is scored, not_found (outside the public
        dataset), unsupported (not GitHub/GitLab) or error; checks list every Scorecard check
        (score -1 is inconclusive) and maintained reflects 90-day commit/issue activity.
        deprecated comes from deps.dev for ecosystem packages.
        resolved=false means no maintenance refresh has looked this package up yet, not that it
        is unmaintained. Use as context (e.g. likelihood of upstream fixes or backports); never
        as an assessment verdict or justification. Errors use Error:. Read-only.
        """
        return _package_health_impl(client, variant_id, package_id)
