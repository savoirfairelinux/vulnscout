from client import VulnScoutClient, VulnScoutError


def _get_vulnerability_impl(
    client: VulnScoutClient,
    vuln_id: str,
    variant_id: str,
) -> str:
    """Core logic for get_vulnerability — separated for testability."""
    try:
        result = client.get_vulnerability(vuln_id, variant_id=variant_id)
        return str(result)
    except VulnScoutError as e:
        return f"Error: {e}"


def register_tools(server, client: VulnScoutClient) -> None:
    """Register all vulnerability tools on the given FastMCP server."""

    @server.tool()
    def get_vulnerability(vuln_id: str, variant_id: str) -> str:
        """Retrieve full details for a single vulnerability by its ID from VulnScout.

        Returns severity/CVSS info, EPSS score, effort estimates, fix info,
        advisories, aliases, related vulnerabilities, affected packages, and a
        `texts` list of SBOM-derived observations (title/content pairs) about
        the vulnerability. The response's severity and effort fields are
        overridden with values scoped to the given variant, if any exist.
        Returns "Not found" if no vulnerability exists with the given id.
        Client errors are returned as an `Error: ...` string.

        Args:
            vuln_id: CVE identifier, e.g. CVE-2024-1234
            variant_id: Required UUID of the variant to scope this lookup to.
        """
        return _get_vulnerability_impl(client, vuln_id=vuln_id, variant_id=variant_id)
