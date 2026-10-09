from typing import Optional
from vulnscout_mcp.client import VulnScoutClient, VulnScoutError


def _write_assessment_impl(
    client: VulnScoutClient,
    vuln_id: str,
    status: str,
    packages: Optional[list] = None,
    variant_id: Optional[str] = None,
    variant_ids: Optional[list] = None,
    targets: Optional[list] = None,
    justification: Optional[str] = None,
    status_notes: Optional[str] = None,
    impact_statement: Optional[str] = None,
    workaround: Optional[str] = None,
    responses: Optional[list] = None,
    timestamp: Optional[str] = None,
    ai_generated: bool = True,
) -> str:
    """Core logic for write_assessment — separated for testability."""
    if targets:
        payload: dict = {"targets": targets, "status": status, "ai_generated": ai_generated}
    else:
        if not packages:
            return "Error: packages is required when targets is not provided"
        if not variant_ids and not variant_id:
            return "Error: variant_id or variant_ids is required"
        payload = {"packages": packages, "status": status, "ai_generated": ai_generated}
        if variant_ids:
            payload["variant_ids"] = variant_ids
        else:
            payload["variant_id"] = variant_id
    if justification is not None:
        payload["justification"] = justification
    if status_notes is not None:
        payload["status_notes"] = status_notes
    if impact_statement is not None:
        payload["impact_statement"] = impact_statement
    if workaround is not None:
        payload["workaround"] = workaround
    if responses is not None:
        payload["responses"] = responses
    if timestamp is not None:
        payload["timestamp"] = timestamp

    try:
        result = client.write_assessment(vuln_id, payload)
        if "assessment" not in result:
            return str(result)
        a = result.get("assessment", {})
        targets = a.get("targets") or []
        summary = (
            f"Assessment created: id={a.get('id')}, "
            f"status={a.get('status')}, "
            f"packages={a.get('packages')}, "
            f"variant_ids={a.get('variant_ids')}, "
            f"{len(targets)} target(s)"
        )
        replaced = result.get("replaced") or []
        if replaced:
            summary += "; replaced: " + ", ".join(
                f"{r.get('id')} ({r.get('action')}, {' '.join(r.get('variant_ids') or [])})"
                for r in replaced
            )
        return summary
    except VulnScoutError as e:
        return f"Error: {e}"


def _has_ai_assessment_impl(
    client: VulnScoutClient,
    vuln_id: str,
    variant_id: str,
    package: Optional[str] = None,
) -> str:
    """Core logic for has_ai_assessment — separated for testability."""
    try:
        assessments = client.list_assessments_by_vuln(vuln_id)
    except VulnScoutError as e:
        return f"Error: {e}"

    found = []
    for a in assessments:
        if a.get("origin") != "ai":
            continue
        covered = a.get("variant_ids") or [a.get("variant_id")]
        if variant_id not in covered:
            continue
        scoped_packages = a.get("packages") or []
        targets = a.get("targets") or []
        if targets:
            scoped_packages = [
                t.get("package")
                for t in targets
                if t.get("variant_id") == variant_id and t.get("package")
            ]
        if package and package not in scoped_packages:
            continue
        found.append(
            f"AI assessment found: id={a.get('id')}, "
            f"status={a.get('status')}, "
            f"packages={scoped_packages}, "
            f"variant_ids={a.get('variant_ids')}"
        )
    if found:
        return "\n".join(found)
    scope = f"variant {variant_id}" + (f" and package {package}" if package else "")
    return f"No AI assessment found for {vuln_id} with {scope}"


def _update_ai_assessment_impl(
    client: VulnScoutClient,
    assessment_id: str,
    status: Optional[str] = None,
    status_notes: Optional[str] = None,
    justification: Optional[str] = None,
    impact_statement: Optional[str] = None,
    workaround: Optional[str] = None,
) -> str:
    """Core logic for update_ai_assessment — separated for testability."""
    try:
        existing = client.get_assessment(assessment_id)
    except VulnScoutError as e:
        return f"Error: {e}"

    if existing.get("origin") != "ai":
        return f"Assessment {assessment_id} is not an AI-generated assessment; refusing to modify it."

    payload: dict = {}
    if status is not None:
        payload["status"] = status
    if status_notes is not None:
        payload["status_notes"] = status_notes
    if justification is not None:
        payload["justification"] = justification
    if impact_statement is not None:
        payload["impact_statement"] = impact_statement
    if workaround is not None:
        payload["workaround"] = workaround

    if not payload:
        return "Error: no fields provided to update"

    try:
        result = client.update_assessment(assessment_id, payload)
    except VulnScoutError as e:
        return f"Error: {e}"

    if "assessment" not in result:
        return str(result)
    a = result.get("assessment", {})
    return (
        f"Assessment updated: id={a.get('id')}, "
        f"status={a.get('status')}, "
        f"packages={a.get('packages')}"
    )


def register_tools(server, client: VulnScoutClient) -> None:
    """Register all assessment tools on the given FastMCP server."""

    @server.tool()
    def write_assessment(
        vuln_id: str,
        status: str,
        packages: Optional[list] = None,
        variant_id: Optional[str] = None,
        variant_ids: Optional[list] = None,
        targets: Optional[list] = None,
        justification: Optional[str] = None,
        status_notes: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
        responses: Optional[list] = None,
        timestamp: Optional[str] = None,
        ai_generated: bool = True,
    ) -> str:
        """Write a VEX assessment for a CVE on one or more packages in VulnScout.

        Two ways to scope the assessment:

        - `packages` + (`variant_id` or `variant_ids`): creates a single
          assessment covering every (package, variant) pair actually observed
          among the given packages and variants — i.e. the cross-product,
          filtered to what a scan recorded. Pairs that no scan recorded are
          silently skipped, not rejected. Use this only when every package
          in `packages` genuinely applies to every variant in the group; a
          naive union crossed with variants can otherwise assess a
          package/variant combo that was never actually selected for it.
        - `targets`: a list of exact `{"package": ..., "variant_id": ...}`
          pairs. Takes precedence over `packages`/`variant_id`/`variant_ids`
          when given, and is the required form for a multi-variant group
          where different variants have different affected package versions
          (a sparse selection) — the server validates each pair individually
          and rejects any that was never observed, rather than filling in
          extra pairs from a cross-product.

        The call is rejected (and nothing written) only if a package or
        variant does not exist, the variants belong to different projects, or
        a target pair was never observed. Compare the "N target(s)" count in
        the result with the expected pair count to detect skipped pairs.
        When ai_generated is true (the default), the write replaces any
        pending AI assessment on the same (variant, package) targets. A pending
        assessment that also covers other targets (other variants, or other
        packages of the same variant) keeps those and loses only the overlap.
        Only AI assessments are replaced, never custom ones, and the swap is
        atomic: if the write fails, the old assessment is left intact. No
        pre-check with has_ai_assessment is needed.

        Returns a success summary when the API response includes an `assessment`
        object, followed by "; replaced: <id> (<deleted|trimmed>, <variant ids>)"
        for each pending AI assessment the write replaced. If the response does not include `assessment`, the call is treated
        as failed and the raw response payload is returned instead. Client errors
        are returned as an `Error: ...` string.

        Args:
            vuln_id: CVE identifier, e.g. CVE-2024-1234
            status: Assessment status. OpenVEX values: under_investigation, not_affected, affected, fixed.
                    CycloneDX VEX values: in_triage, false_positive, not_affected, exploitable,
                    resolved, resolved_with_pedigree.
            packages: List of affected package strings in 'name@version' format, e.g. ['openssl@1.0.0'].
                    Required unless `targets` is given.
            variant_id: UUID of the variant to scope this assessment to. Either
                    this or variant_ids is required unless `targets` is given.
            variant_ids: List of variant UUIDs to scope this assessment to, when
                    it covers more than one variant. Takes precedence over
                    variant_id when both are given.
            targets: List of exact `{"package": "<name>@<version>", "variant_id": "<uuid>"}`
                    pairs. Use this instead of `packages`/`variant_id`/`variant_ids`
                    for a multi-variant group whose members do not all share the
                    same affected package set. Takes precedence over
                    `packages`/`variant_id`/`variant_ids` when given.
            justification: Required when status is 'not_affected'. OpenVEX values:
                    component_not_present, vulnerable_code_not_present,
                    vulnerable_code_not_in_execute_path,
                    vulnerable_code_cannot_be_controlled_by_adversary,
                    inline_mitigations_already_exist. CycloneDX VEX values: code_not_present,
                    code_not_reachable, requires_configuration, requires_dependency,
                    requires_environment, protected_by_compiler, protected_at_runtime,
                    protected_at_perimeter, protected_by_mitigating_control.
            status_notes: Free-text notes about the assessment.
            impact_statement: Free-text description of impact.
            workaround: Workaround description.
            responses: CycloneDX response tags. Valid values: can_not_fix, will_not_fix,
                    update, rollback, workaround_available.
            timestamp: ISO 8601 datetime string, e.g. 2024-01-15T10:30:00Z.
            ai_generated: Whether this assessment was generated by an AI agent. Defaults to True.
        """
        return _write_assessment_impl(
            client,
            vuln_id=vuln_id,
            status=status,
            packages=packages,
            variant_id=variant_id,
            variant_ids=variant_ids,
            targets=targets,
            justification=justification,
            status_notes=status_notes,
            impact_statement=impact_statement,
            workaround=workaround,
            responses=responses,
            timestamp=timestamp,
            ai_generated=ai_generated,
        )

    @server.tool()
    def get_assessment(assessment_id: str) -> str:
        """Retrieve a single VEX assessment by its ID from VulnScout.

        Args:
            assessment_id: UUID of the assessment to retrieve.
        """
        try:
            result = client.get_assessment(assessment_id)
            return str(result)
        except VulnScoutError as e:
            return f"Error: {e}"

    @server.tool()
    def list_assessments_by_vuln(vuln_id: str) -> str:
        """List all VEX assessments for a given CVE in VulnScout.

        Returns all assessment records across all packages associated with the
        vulnerability, including their timestamps. Use this before writing a
        new assessment to understand the current assessment state for a CVE.

        Args:
            vuln_id: CVE identifier, e.g. CVE-2024-1234
        """
        try:
            results = client.list_assessments_by_vuln(vuln_id)
            if not results:
                return f"No assessments found for {vuln_id}"
            lines = [f"Assessments for {vuln_id} ({len(results)} total):"]
            for a in results:
                targets = a.get("targets") or []
                lines.append(
                    f"  id={a.get('id')} origin={a.get('origin')} status={a.get('status')} "
                    f"packages={a.get('packages')} justification={a.get('justification')} "
                    f"variant_ids={a.get('variant_ids')} {len(targets)} target(s) "
                    f"timestamp={a.get('timestamp')}"
                )
            return "\n".join(lines)
        except VulnScoutError as e:
            return f"Error: {e}"

    @server.tool()
    def has_ai_assessment(vuln_id: str, variant_id: str, package: Optional[str] = None) -> str:
        """Look up the AI-generated assessments for a vulnerability on a given variant.

        Queries all assessments for the CVE and returns one line per
        AI-generated assessment that covers the specified variant (and
        package, when given), or a clear "not found" message if none exists.
        A variant can hold several pending AI assessments, one per package
        set. This is informational only: write_assessment replaces pending AI
        assessments on the same (variant, package) targets on its own, so
        there is no need to call this before writing.

        Args:
            vuln_id: CVE identifier, e.g. CVE-2024-1234
            variant_id: UUID of the variant to check.
            package: Optional 'name@version' package to narrow the lookup to.
        """
        return _has_ai_assessment_impl(client, vuln_id=vuln_id, variant_id=variant_id, package=package)

    @server.tool()
    def update_ai_assessment(
        assessment_id: str,
        status: Optional[str] = None,
        status_notes: Optional[str] = None,
        justification: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
    ) -> str:
        """Modify an existing AI-generated VEX assessment in VulnScout.

        Only assessments whose `origin` is `"ai"` may be modified by
        this tool. The assessment is fetched first to verify this; if it is
        not AI-generated, the tool refuses to modify it and no update request
        is sent. All fields below are optional — only the ones supplied are
        included in the update, and at least one must be provided. The update
        applies to the assessment's content only: it cannot add, remove, or
        otherwise change which (package, variant) targets the assessment covers.

        Args:
            assessment_id: UUID of the assessment to modify.
            status: New assessment status. OpenVEX values: under_investigation,
                    not_affected, affected, fixed. CycloneDX VEX values: in_triage,
                    false_positive, not_affected, exploitable, resolved,
                    resolved_with_pedigree.
            status_notes: Free-text notes about the assessment.
            justification: Required by the server when status is 'not_affected'.
                    OpenVEX values: component_not_present, vulnerable_code_not_present,
                    vulnerable_code_not_in_execute_path,
                    vulnerable_code_cannot_be_controlled_by_adversary,
                    inline_mitigations_already_exist. CycloneDX VEX values: code_not_present,
                    code_not_reachable, requires_configuration, requires_dependency,
                    requires_environment, protected_by_compiler, protected_at_runtime,
                    protected_at_perimeter, protected_by_mitigating_control.
            impact_statement: Free-text description of impact.
            workaround: Workaround description.
        """
        return _update_ai_assessment_impl(
            client,
            assessment_id=assessment_id,
            status=status,
            status_notes=status_notes,
            justification=justification,
            impact_statement=impact_statement,
            workaround=workaround,
        )
