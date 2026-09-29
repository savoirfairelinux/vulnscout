from typing import Optional
from client import VulnScoutClient, VulnScoutError


def _fmt_merged_context(ctx: dict) -> str:
    files = ctx.get("files") or []
    file_names = ", ".join(f.get("original_name", "") for f in files) if files else "(none)"
    return (
        f"project_id={ctx.get('project_id')}\n"
        f"description={ctx.get('description')}\n"
        f"variant_id={ctx.get('variant_id')}\n"
        f"variant_description={ctx.get('variant_description')}\n"
        f"codebase_path={ctx.get('codebase_path')}\n"
        f"environment={ctx.get('environment')}\n"
        f"threat_model={ctx.get('threat_model')}\n"
        f"risks={ctx.get('risks')}\n"
        f"other_info={ctx.get('other_info')}\n"
        f"files={file_names}"
    )


def _fmt_project_context(ctx: dict) -> str:
    return (
        f"project_id={ctx.get('project_id')}\n"
        f"description={ctx.get('description')}"
    )


def _fmt_variant_context(ctx: dict) -> str:
    files = ctx.get("files") or []
    file_names = ", ".join(f.get("original_name", "") for f in files) if files else "(none)"
    return (
        f"variant_id={ctx.get('variant_id')}\n"
        f"variant_description={ctx.get('variant_description')}\n"
        f"environment={ctx.get('environment')}\n"
        f"threat_model={ctx.get('threat_model')}\n"
        f"risks={ctx.get('risks')}\n"
        f"other_info={ctx.get('other_info')}\n"
        f"files={file_names}"
    )


def _find_project_id_or_raise(client: VulnScoutClient, project_name: str) -> str:
    projects = client.list_projects()
    matches = [p for p in projects if p.get("name") == project_name]
    if not matches:
        raise VulnScoutError(f"No project found with name '{project_name}'.")
    if len(matches) > 1:
        raise VulnScoutError(f"Multiple projects found with name '{project_name}'.")
    return matches[0]["id"]


def _find_project_id_impl(client: VulnScoutClient, project_name: str) -> str:
    try:
        return _find_project_id_or_raise(client, project_name)
    except VulnScoutError as e:
        return f"Error: {e}"


def _find_variant_id_or_raise(client: VulnScoutClient, project_name: str, variant_name: str) -> str:
    project_id = _find_project_id_or_raise(client, project_name)
    variants = client.list_variants_by_project(project_id)
    matches = [v for v in variants if v.get("name") == variant_name]
    if not matches:
        raise VulnScoutError(f"No variant found with name '{variant_name}' in project '{project_name}'.")
    if len(matches) > 1:
        raise VulnScoutError(f"Multiple variants found with name '{variant_name}' in project '{project_name}'.")
    return matches[0]["id"]


def _find_variant_id_impl(client: VulnScoutClient, project_name: str, variant_name: str) -> str:
    try:
        return _find_variant_id_or_raise(client, project_name, variant_name)
    except VulnScoutError as e:
        return f"Error: {e}"


def _list_variants_impl(client: VulnScoutClient) -> str:
    try:
        variants = client.list_variants()
    except VulnScoutError as e:
        return f"Error: {e}"
    if not variants:
        return "(none)"
    return "\n".join(
        f"id={v.get('id')} name={v.get('name')} project_id={v.get('project_id')}"
        for v in variants
    )


def _get_merged_context_impl(client: VulnScoutClient, project_id: str, variant_id: str) -> str:
    try:
        ctx = client.get_merged_context(project_id, variant_id)
        return _fmt_merged_context(ctx)
    except VulnScoutError as e:
        return f"Error: {e}"


def _get_project_context_impl(client: VulnScoutClient, project_id: str) -> str:
    try:
        ctx = client.get_project_context(project_id)
        return _fmt_project_context(ctx)
    except VulnScoutError as e:
        return f"Error: {e}"


def _update_project_context_impl(
    client: VulnScoutClient, project_id: str, description: Optional[str] = None
) -> str:
    try:
        ctx = client.update_project_context(project_id, description)
        return _fmt_project_context(ctx)
    except VulnScoutError as e:
        return f"Error: {e}"


def _update_variant_context_impl(
    client: VulnScoutClient,
    variant_id: str,
    variant_description: Optional[str] = None,
    environment: Optional[str] = None,
    threat_model: Optional[str] = None,
    risks: Optional[str] = None,
    other_info: Optional[str] = None,
) -> str:
    fields = {
        "variant_description": variant_description,
        "environment": environment,
        "threat_model": threat_model,
        "risks": risks,
        "other_info": other_info,
    }
    try:
        ctx = client.update_variant_context(variant_id, fields)
        return _fmt_variant_context(ctx)
    except VulnScoutError as e:
        return f"Error: {e}"


def register_tools(server, client: VulnScoutClient) -> None:
    """Register all project/variant context tools on the given FastMCP server."""

    @server.tool()
    def find_project_id(project_name: str) -> str:
        """Look up a project's UUID by its exact name.

        Lists all projects and returns the id of the one whose name matches
        project_name exactly (case-sensitive). Use this when you only know a
        project's name, e.g. before calling get_merged_context,
        get_project_context, update_project_context, or find_variant_id.

        Args:
            project_name: Exact name of the project.
        """
        return _find_project_id_impl(client, project_name)

    @server.tool()
    def find_variant_id(project_name: str, variant_name: str) -> str:
        """Look up a variant's UUID by its project name and variant name.

        Resolves the project by exact name, then lists that project's
        variants and returns the id of the one whose name matches
        variant_name exactly (case-sensitive). Use this when you only know
        the project/variant names, e.g. before calling get_merged_context or
        update_variant_context.

        Args:
            project_name: Exact name of the project containing the variant.
            variant_name: Exact name of the variant within that project.
        """
        return _find_variant_id_impl(client, project_name, variant_name)

    @server.tool()
    def list_variants() -> str:
        """List every variant across all projects.

        Returns one line per variant in the form
        "id=<uuid> name=<name> project_id=<uuid>", or "(none)" if there are
        no variants. Use this to discover available variants; if you already
        know the project and variant names, use find_variant_id instead.
        """
        return _list_variants_impl(client)

    @server.tool()
    def get_merged_context(project_id: str, variant_id: str) -> str:
        """Get the merged context for a project + variant pair.

        Returns the project's description together with the variant's
        variant_description, codebase_path, environment, threat_model, risks,
        other_info, and any attached file names. codebase_path may contain
        multiple paths separated by semicolons (e.g. "/src/app;/src/lib").
        Both IDs are required; the variant must belong to the given project.
        If only the project/variant names are known, resolve them first with
        find_project_id and find_variant_id.

        Args:
            project_id: UUID of the project.
            variant_id: UUID of the variant. Must belong to project_id.
        """
        return _get_merged_context_impl(client, project_id, variant_id)

    @server.tool()
    def get_project_context(project_id: str) -> str:
        """Get the context (description) for a project by its UUID.

        If only the project's name is known, resolve project_id first with
        find_project_id.

        Args:
            project_id: UUID of the project.
        """
        return _get_project_context_impl(client, project_id)

    @server.tool()
    def update_project_context(project_id: str, description: Optional[str] = None) -> str:
        """Set the context description for a project by its UUID.

        This replaces the project's description entirely. Passing null (or
        omitting it) clears the description to null. If only the project's
        name is known, resolve project_id first with find_project_id.

        Args:
            project_id: UUID of the project to update.
            description: Free-text description of the project. Pass null to clear it.
        """
        return _update_project_context_impl(client, project_id, description)

    @server.tool()
    def update_variant_context(
        variant_id: str,
        variant_description: Optional[str] = None,
        environment: Optional[str] = None,
        threat_model: Optional[str] = None,
        risks: Optional[str] = None,
        other_info: Optional[str] = None,
    ) -> str:
        """Set the context fields of a variant by its UUID.

        IMPORTANT: This is a FULL REPLACEMENT, not a partial update. Every
        call replaces all fields at once — any field left as null (including
        by omission) is cleared to null on the server, even if it previously
        had a value. To preserve an existing field's value, you must fetch
        the current context first (e.g. via get_merged_context) and pass its
        value back explicitly. If only the project/variant names are known,
        resolve variant_id first with find_variant_id.

        Args:
            variant_id: UUID of the variant to update.
            variant_description: Free-text description of this variant.
            environment: Free-text description of the deployment environment.
            threat_model: Free-text threat model notes for this variant.
            risks: Free-text notes about known risks for this variant.
            other_info: Any other free-text notes about this variant.
        """
        return _update_variant_context_impl(
            client,
            variant_id,
            variant_description=variant_description,
            environment=environment,
            threat_model=threat_model,
            risks=risks,
            other_info=other_info,
        )
