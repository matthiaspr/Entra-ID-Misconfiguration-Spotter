"""Check for admin consent workflow configuration."""

import re

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult


def _strip_version_prefix(query: str) -> str:
    """Strip API version prefixes like /v1.0/ or /beta/ from query paths."""
    return re.sub(r"^/(v1\.0|beta)/", "/", query)


async def _resolve_reviewer(client: GraphServiceClient, query: str) -> dict:
    """Parse a reviewer query and resolve the display name.

    Query paths can look like:
    - /v1.0/users/{uuid}
    - /beta/groups/{uuid}
    - /directoryRoles/{uuid}
    - /beta/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{uuid}'
    """
    # Strip version prefix for matching
    normalized = _strip_version_prefix(query)

    # Match user path: /users/{id}
    user_match = re.match(r"^/users/([a-zA-Z0-9-]+)$", normalized)
    if user_match:
        entity_id = user_match.group(1)
        try:
            user = await client.users.by_user_id(entity_id).get()
            return {"type": "user", "id": entity_id, "display_name": user.display_name}
        except Exception:
            return {"type": "user", "id": entity_id, "display_name": None}

    # Match group path: /groups/{id}
    group_match = re.match(r"^/groups/([a-zA-Z0-9-]+)$", normalized)
    if group_match:
        entity_id = group_match.group(1)
        try:
            group = await client.groups.by_group_id(entity_id).get()
            return {"type": "group", "id": entity_id, "display_name": group.display_name}
        except Exception:
            return {"type": "group", "id": entity_id, "display_name": None}

    # Match directory role path: /directoryRoles/{id}
    role_match = re.match(r"^/directoryRoles/([a-zA-Z0-9-]+)$", normalized)
    if role_match:
        entity_id = role_match.group(1)
        try:
            role = await client.directory_roles.by_directory_role_id(entity_id).get()
            return {"type": "role", "id": entity_id, "display_name": role.display_name}
        except Exception:
            return {"type": "role", "id": entity_id, "display_name": None}

    # Match role assignment query: /roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{id}'
    role_assignment_match = re.search(
        r"roleDefinitionId\s+eq\s+'([a-fA-F0-9-]+)'", normalized
    )
    if role_assignment_match:
        role_def_id = role_assignment_match.group(1)
        try:
            # Look up the role definition to get its display name
            role_def = await client.role_management.directory.role_definitions.by_unified_role_definition_id(
                role_def_id
            ).get()
            return {
                "type": "role",
                "id": role_def_id,
                "display_name": f"Users with {role_def.display_name} role",
            }
        except Exception:
            return {"type": "role", "id": role_def_id, "display_name": None}

    # Unknown query format
    return {"type": "unknown", "query": query, "display_name": None}


def _format_reviewer(reviewer: dict) -> str:
    """Format a resolved reviewer for display."""
    if reviewer.get("display_name"):
        return reviewer["display_name"]
    if reviewer.get("type") == "unknown":
        return reviewer.get("query", "unknown")
    return f"{reviewer['type']}: {reviewer['id']}"


async def check_admin_consent_workflow(client: GraphServiceClient) -> CheckResult:
    """Check if admin consent workflow is enabled with reviewers.

    Calls GET /policies/adminConsentRequestPolicy and checks
    isEnabled and reviewers array. Resolves reviewer identities
    to display their names.

    Pass: isEnabled=true AND reviewers is non-empty
    Fail: isEnabled=false
    Warning: isEnabled=true but reviewers is empty
    """
    response = await client.policies.admin_consent_request_policy.get()

    is_enabled = response.is_enabled
    reviewers_raw = response.reviewers or []

    if not is_enabled:
        return CheckResult(
            check_id="admin-consent-workflow",
            status="fail",
            message="Admin consent workflow is disabled.",
            recommendation="Enable admin consent workflow in Entra ID.",
            details={"is_enabled": is_enabled},
        )

    if not reviewers_raw:
        return CheckResult(
            check_id="admin-consent-workflow",
            status="warning",
            message="Admin consent workflow is enabled but has no reviewers.",
            recommendation="Add reviewers to the admin consent workflow.",
            details={"is_enabled": is_enabled, "reviewer_count": 0},
        )

    # Resolve reviewer details
    resolved_reviewers = []
    for reviewer in reviewers_raw:
        query = getattr(reviewer, "query", None)
        if query:
            resolved = await _resolve_reviewer(client, query)
            resolved_reviewers.append(resolved)

    # Format reviewer names for message
    reviewer_names = [_format_reviewer(r) for r in resolved_reviewers]
    names_display = ", ".join(reviewer_names)

    return CheckResult(
        check_id="admin-consent-workflow",
        status="pass",
        message=f"Admin consent workflow is enabled with {len(resolved_reviewers)} reviewer(s): {names_display}.",
        details={
            "is_enabled": is_enabled,
            "reviewer_count": len(resolved_reviewers),
            "reviewers": resolved_reviewers,
        },
    )
