from typing import Optional

from client import VulnScoutClient, VulnScoutError
from tools.context import _find_project_id_or_raise, _find_variant_id_or_raise


def _strip_reference(reference: str) -> str:
    """Strip a copied `assessment:<uuid>` or legacy `group:<uuid>` prefix.

    The Review page and the vulnerability modal copy one of these two forms
    depending on whether the assessment covers one target or several; both
    name the same kind of id today, so the prefix carries no information
    this tool needs — it is only stripped so a pasted reference can be
    passed straight through.
    """
    ref = (reference or "").strip()
    for prefix in ("assessment:", "group:"):
        if ref.lower().startswith(prefix):
            return ref[len(prefix):].strip()
    return ref


def _get_custom_assessment_impl(client: VulnScoutClient, assessment_id: str) -> str:
    """Core logic for get_custom_assessment — separated for testability."""
    assessment_id = _strip_reference(assessment_id)
    if not assessment_id:
        return "Error: no assessment id provided"

    try:
        assessment = client.get_assessment(assessment_id)
    except VulnScoutError as e:
        return f"Error: {e}"

    origin = assessment.get("origin")
    if origin != "custom":
        return (
            f"Assessment {assessment_id} is not a custom assessment "
            f"(origin={origin!r}); skip it — only custom assessments are reviewed."
        )

    targets = assessment.get("targets") or []
    lines = [
        f"Custom assessment {assessment_id} "
        f"({len(targets)} target(s) across {len(assessment.get('variant_ids') or [])} variant(s)):",
        f"  assessment_fingerprint={assessment.get('assessment_fingerprint')}",
        f"  project_id={assessment.get('project_id')}",
        f"  vuln_id={assessment.get('vuln_id')}",
        f"  packages={assessment.get('packages')}",
        f"  variant_ids={assessment.get('variant_ids')}",
        f"  status={assessment.get('status')}",
        f"  justification={assessment.get('justification')}",
        f"  status_notes={assessment.get('status_notes')}",
        f"  impact_statement={assessment.get('impact_statement')}",
        f"  workaround={assessment.get('workaround')}",
        f"  responses={assessment.get('responses')}",
        f"  timestamp={assessment.get('timestamp')}",
        "  targets:",
    ]
    reviews_by_target = {
        (r.get("variant_id"), r.get("package")): r
        for r in (assessment.get("reviews") or [])
    }
    for t in targets:
        lines.append(
            f"    project_id={t.get('project_id')} variant_id={t.get('variant_id')} "
            f"package={t.get('package')} "
            f"outdated={t.get('outdated')}"
        )
        review = reviews_by_target.get((t.get("variant_id"), t.get("package")))
        if review:
            lines.append(
                f"      review: status={review.get('status')} "
                f"verdict={review.get('verdict')} is_stale={review.get('is_stale')}"
            )
        else:
            lines.append("      review: none")
    if not targets:
        lines.append("    none")

    return "\n".join(lines)


def _list_custom_assessments_impl(
    client: VulnScoutClient,
    project_name: Optional[str] = None,
    variant_name: Optional[str] = None,
    variant_id: Optional[str] = None,
    has_review: Optional[bool] = None,
    order: str = "timestamp_desc",
    limit: int = 50,
    offset: int = 0,
) -> str:
    """Core logic for list_custom_assessments — separated for testability."""
    params: dict = {"order": order, "limit": limit, "offset": offset}

    if variant_id:
        params["variant_id"] = variant_id
    elif project_name:
        try:
            project_id = _find_project_id_or_raise(client, project_name)
            resolved_variant = _find_variant_id_or_raise(
                client, project_name, variant_name or "default"
            )
        except VulnScoutError as e:
            return f"Error: {e}"
        params["project_id"] = project_id
        params["variant_id"] = resolved_variant

    if has_review is not None:
        params["has_review"] = "true" if has_review else "false"

    try:
        rows = client.list_custom_assessments(params)
    except VulnScoutError as e:
        return f"Error: {e}"

    if not rows:
        return "No custom assessments found for the given scope."

    lines = [f"Custom assessments ({len(rows)} returned):"]
    for a in rows:
        targets = a.get("targets") or []
        lines.append(
            f"  assessment_id={a.get('id')} vuln_id={a.get('vuln_id')} "
            f"assessment_fingerprint={a.get('assessment_fingerprint')} "
            f"project_id={a.get('project_id')} "
            f"packages={a.get('packages')} variant_ids={a.get('variant_ids')} "
            f"{len(targets)} target(s) "
            f"status={a.get('status')} justification={a.get('justification')} "
            f"status_notes={a.get('status_notes')} "
            f"impact_statement={a.get('impact_statement')} "
            f"workaround={a.get('workaround')} timestamp={a.get('timestamp')} "
            f"has_review={a.get('has_review')} (any target reviewed)"
        )
        for tr in a.get("target_reviews") or []:
            lines.append(
                f"    variant_id={tr.get('variant_id')} package={tr.get('package')} "
                f"has_review={tr.get('has_review')} is_stale={tr.get('is_stale')}"
            )
    return "\n".join(lines)


def _write_assessment_review_impl(
    client: VulnScoutClient,
    assessment_id: str,
    expected_assessment_fingerprint: str,
    variant_id: str,
    status: str,
    rationale: str,
    package: Optional[str] = None,
    finding_id: Optional[str] = None,
    status_notes: Optional[str] = None,
    justification: Optional[str] = None,
    impact_statement: Optional[str] = None,
    workaround: Optional[str] = None,
    responses: Optional[list] = None,
) -> str:
    """Core logic for write_assessment_review — separated for testability."""
    if not expected_assessment_fingerprint or not expected_assessment_fingerprint.strip():
        return (
            "Error: expected_assessment_fingerprint is required — pass the "
            "assessment_fingerprint returned by get_custom_assessment or "
            "list_custom_assessments."
        )
    if not rationale or not rationale.strip():
        return "Error: rationale is required — state why the review reaches its conclusion."
    if not variant_id:
        return "Error: variant_id is required — a review targets one (variant, package) pair."
    if not finding_id and not package:
        return "Error: finding_id or package is required — a review targets one (variant, package) pair."

    payload: dict = {
        "expected_assessment_fingerprint": expected_assessment_fingerprint.strip(),
        "status": status,
        "rationale": rationale.strip(),
        "variant_id": variant_id,
    }
    if finding_id:
        payload["finding_id"] = finding_id
    if package:
        payload["package"] = package
    if status_notes is not None:
        payload["status_notes"] = status_notes
    if justification is not None:
        payload["justification"] = justification
    if impact_statement is not None:
        payload["impact_statement"] = impact_statement
    if workaround is not None:
        payload["workaround"] = workaround
    if responses is not None:
        payload["responses"] = responses

    try:
        result = client.write_assessment_review(assessment_id, payload)
    except VulnScoutError as e:
        return f"Error: {e}"

    review = result.get("review")
    if not review:
        return str(result)
    return (
        f"Review saved: id={review.get('id')}, "
        f"assessment_id={review.get('assessment_id')}, "
        f"status={review.get('status')}, verdict={review.get('verdict')}"
    )


def register_tools(server, client: VulnScoutClient) -> None:
    """Register all assessment-review tools on the given MCP server."""

    @server.tool()
    def get_custom_assessment(assessment_id: str) -> str:
        """Fetch one user/custom VEX assessment by ID, with any existing reviews.

        Use this when the caller names a specific assessment to review. One
        assessment can cover several (package, variant) pairs at once; the
        response lists every one of them under `targets`, each with its own
        variant_id and package, and an `outdated` flag. Each target is
        reviewed independently, so the output shows a `review` line per
        target (or "none") rather than one review for the whole assessment.
        You need every listed variant_id to call `get_merged_context` per
        variant. Refuses assessments whose origin is not "custom" — only
        user-authored assessments are reviewed.

        Accepts a bare UUID, or a pasted `assessment:<uuid>` /
        `group:<uuid>` reference copied from the Review page or the
        vulnerability modal — the prefix is stripped automatically.

        Args:
            assessment_id: UUID of the assessment to fetch, optionally
                    prefixed with `assessment:` or `group:`.
        """
        return _get_custom_assessment_impl(client, assessment_id)

    @server.tool()
    def list_custom_assessments(
        project_name: Optional[str] = None,
        variant_name: Optional[str] = None,
        variant_id: Optional[str] = None,
        has_review: Optional[bool] = None,
        order: str = "timestamp_desc",
        limit: int = 50,
        offset: int = 0,
    ) -> str:
        """List user/custom VEX assessments, optionally scoped to a project variant.

        Every returned assessment has origin "custom" — assessments from SBOM
        scans and pending AI suggestions are never included. With no arguments,
        returns custom assessments across all variants.

        Args:
            project_name: Project name to scope to. Resolved to a UUID internally.
            variant_name: Variant name within the project. Defaults to "default"
                    when project_name is given.
            variant_id: Variant UUID, if already known. Takes precedence over
                    project_name/variant_name.
            has_review: True returns only assessments with a review on at least
                    one target (see each row's `target_reviews` for which);
                    False returns only assessments with no review on any target.
                    Omit for both.
            order: "timestamp_desc" (newest first, the default) or "timestamp_asc".
            limit: Maximum rows to return. Defaults to 50.
            offset: Rows to skip, for paging through a large scope.
        """
        return _list_custom_assessments_impl(
            client,
            project_name=project_name,
            variant_name=variant_name,
            variant_id=variant_id,
            has_review=has_review,
            order=order,
            limit=limit,
            offset=offset,
        )

    @server.tool()
    def write_assessment_review(
        assessment_id: str,
        expected_assessment_fingerprint: str,
        variant_id: str,
        status: str,
        rationale: str,
        package: Optional[str] = None,
        finding_id: Optional[str] = None,
        status_notes: Optional[str] = None,
        justification: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
        responses: Optional[list] = None,
    ) -> str:
        """Save an AI review of one target of a user/custom VEX assessment.

        A review carries the same VEX fields as an assessment — they are the
        values the reviewer independently derived, which a user may later accept
        to replace the original. It never modifies the assessment itself.

        A review is scoped to exactly one (variant_id, package) target of the
        assessment — not the assessment as a whole. A multi-target assessment
        needs one write_assessment_review call per target, since group members
        share the assessment text but target different variants/packages and
        may legitimately disagree. Use get_custom_assessment first to see the
        exact variant_id/package pairs listed under `targets`. Writing again
        for the same target overwrites its previous review; other targets'
        reviews are untouched. The server rejects any assessment whose origin
        is not "custom".

        Pass the assessment_fingerprint returned by get_custom_assessment or
        list_custom_assessments as expected_assessment_fingerprint. This
        read-time token prevents a review derived from stale authored content
        from being stored as current. If the assessment changed, fetch it
        again and repeat the review rather than retrying with a new token.

        Every VEX field you leave unset is stored empty and counts as a
        disagreement when the server computes the agrees/differs verdict —
        pass every field you derived, including ones that match the
        assessment, not just the ones that differ from it.

        Args:
            assessment_id: UUID of the assessment being reviewed.
            expected_assessment_fingerprint: Exact assessment_fingerprint from
                    the assessment read used for this review. Required.
            variant_id: UUID of the target variant. Required — must be one of
                    the assessment's own targets (see get_custom_assessment).
            status: Independently derived status. OpenVEX values:
                    under_investigation, not_affected, affected, fixed.
            rationale: Required. Why the review reaches this conclusion — name
                    the evidence, and for a disagreement name each differing field.
            package: The target package string-id (e.g. "openssl@3.0.2"). Required
                    unless finding_id is given.
            finding_id: UUID of the target finding. Alternative to package when
                    already known.
            status_notes: Notes that would replace the assessment's status_notes.
                    Append "confidence level: <high|medium|low>" here.
            justification: Required when status is 'not_affected'. OpenVEX values:
                    component_not_present, vulnerable_code_not_present,
                    vulnerable_code_not_in_execute_path,
                    vulnerable_code_cannot_be_controlled_by_adversary,
                    inline_mitigations_already_exist.
            impact_statement: Impact description for a 'not_affected' review.
            workaround: Workaround description, when one exists.
            responses: CycloneDX response tags. Valid values: can_not_fix,
                    will_not_fix, update, rollback, workaround_available.
        """
        return _write_assessment_review_impl(
            client,
            assessment_id=assessment_id,
            expected_assessment_fingerprint=expected_assessment_fingerprint,
            variant_id=variant_id,
            status=status,
            rationale=rationale,
            package=package,
            finding_id=finding_id,
            status_notes=status_notes,
            justification=justification,
            impact_statement=impact_statement,
            workaround=workaround,
            responses=responses,
        )
